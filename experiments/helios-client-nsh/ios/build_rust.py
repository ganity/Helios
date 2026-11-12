#!/usr/bin/env python3
"""Xcode build phase: compile Rust for the active SDK/architectures, preserving linker flags."""
import argparse
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess


def native_flags(output):
    # Cargo may force ANSI colours in CI; escape sequences are not linker flags.
    plain = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", output)
    flags = re.findall(r"native-static-libs:\s*([^\n]+)", plain)
    return " ".join(shlex.quote(flag) for flag in shlex.split(flags[-1])) + "\n" if flags else None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("component", choices=["app", "tunnel"])
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    platform = os.environ.get("PLATFORM_NAME", "iphoneos")
    if platform not in ("iphoneos", "iphonesimulator"):
        parser.error("Only iPhoneOS and iPhoneSimulator SDKs are supported")
    manifest = root / "runner/Cargo.toml" if args.component == "app" else root.parent / "core/Cargo.toml"
    library = "helios_ios_ui" if args.component == "app" else "helios_mobile_core"
    env = os.environ.copy()
    env["RUSTUP_TOOLCHAIN"] = "stable"
    env["CARGO_TERM_COLOR"] = "never"
    env["CARGO_TARGET_DIR"] = str(root / "build/cargo")
    # Xcode's per-architecture output settings must not leak into Cargo build scripts.
    env.pop("SDKROOT", None)
    env["SDKROOT"] = subprocess.check_output(["xcrun", "--sdk", platform, "--show-sdk-path"], text=True).strip()
    for arch in os.environ.get("ARCHS", "arm64").split():
        target = {
            ("iphoneos", "arm64"): "aarch64-apple-ios",
            ("iphonesimulator", "arm64"): "aarch64-apple-ios-sim",
            ("iphonesimulator", "x86_64"): "x86_64-apple-ios",
        }.get((platform, arch))
        if not target:
            parser.error(f"Unsupported iOS architecture: {platform}/{arch}")
        command = ["cargo", "rustc", "--manifest-path", str(manifest), "--target", target,
                   "--release", "--lib", "--locked"]
        if args.component == "tunnel":
            command += ["--features", "ios-ffi"]
        command += ["--", "--print=native-static-libs"]
        result = subprocess.run(command, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        print(result.stdout, flush=True)
        result.check_returncode()
        output = root / "build/rust" / platform / arch
        output.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(Path(env["CARGO_TARGET_DIR"]) / target / "release" / f"lib{library}.a", output / f"lib{library}.a")
        flags = native_flags(result.stdout)
        response = output / ("app-linker-flags.rsp" if args.component == "app" else "tunnel-linker-flags.rsp")
        if flags:
            response.write_text(flags)
        elif not response.exists():
            raise RuntimeError("Rust did not report native linker flags; clean the Rust build and retry")


if __name__ == "__main__":
    main()
