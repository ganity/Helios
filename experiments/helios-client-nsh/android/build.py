#!/usr/bin/env python3
"""Build the pinned NSH Android host and create a development APK."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--release", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    sdk = Path(os.environ["ANDROID_HOME"])
    env = os.environ.copy()
    env["RUSTUP_TOOLCHAIN"] = "stable"
    installed = sorted((sdk / "ndk").glob("*/toolchains/llvm/prebuilt/*/bin/aarch64-linux-android26-clang"))
    compiler = Path(env["ANDROID_NDK_HOME"]) / "toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android26-clang" if "ANDROID_NDK_HOME" in env else (installed[-1] if installed else None)
    if compiler is None or not compiler.is_file():
        parser.error("Install Android NDK (API 26 or newer) before building")
    env["CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER"] = str(compiler)
    env["CC_aarch64_linux_android"] = str(compiler)
    env["AR_aarch64_linux_android"] = str(compiler.parent / "llvm-ar")
    manifest = root / "runner/Cargo.toml"
    base = ["cargo", "--manifest-path", str(manifest)]
    command = [base[0], "build", *base[1:], "--locked", "--target", "aarch64-linux-android"]
    if args.release:
        command.append("--release")
    subprocess.run(command, env=env, check=True)
    metadata = json.loads(subprocess.check_output([
        "cargo", "metadata", *base[1:], "--format-version", "1", "--locked", "--offline",
        "--filter-platform", "aarch64-linux-android",
    ], env=env))
    nsh = next(Path(package["manifest_path"]).parents[2] for package in metadata["packages"]
               if package["name"] == "nsh-platform-android")
    target = Path(metadata["target_directory"])
    profile = "release" if args.release else "debug"
    output = target / "artifacts" / f"helios-arm64-{profile}.apk"
    subprocess.run([sys.executable, str(root / "package.py"), "--nsh-source", str(nsh),
                    "--library", str(target / "aarch64-linux-android" / profile / "libnsh.so"),
                    "--output", str(output)], env=env, check=True)
    print(output)


if __name__ == "__main__":
    main()
