#!/usr/bin/env python3
"""Package an ARM64 development APK from a built Rust host and pinned NSH sources."""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile
import shutil
import xml.etree.ElementTree as ET
import zipfile


def run(*args):
    subprocess.run([str(arg) for arg in args], check=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--nsh-source", type=Path, required=True)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    sdk = Path(os.environ["ANDROID_HOME"])
    tools = sdk / "build-tools/36.0.0"
    android = sdk / "platforms/android-36/android.jar"
    root = Path(__file__).resolve().parent
    with args.library.open("rb") as library:
        header = library.read(20)
    if header[:6] != b"\x7fELF\x02\x01" or header[18:20] != b"\xb7\x00":
        parser.error("--library must be a little-endian ARM64 ELF shared library")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="helios-apk-") as temporary:
        work = Path(temporary)
        classes = work / "classes"
        classes.mkdir()
        dex = work / "dex"
        dex.mkdir()
        sources = list((args.nsh_source / "crates/nsh-platform-android/java").rglob("*.java"))
        sources += list((root / "src").rglob("*.java"))
        source_list = work / "sources.txt"
        source_list.write_text("\n".join('"' + str(p.resolve()) + '"' for p in sources))
        run("javac", "--release", "17", "-cp", android, "-d", classes, "@" + str(source_list))
        jar = work / "classes.jar"
        run("jar", "cf", jar, "-C", classes, ".")
        run(tools / "d8", "--lib", android, "--min-api", "26", "--output", dex, jar)
        namespace = "http://schemas.android.com/apk/res/android"
        ET.register_namespace("android", namespace)
        manifest = ET.parse(root / "AndroidManifest.xml")
        manifest.getroot().set("package", "com.helios.mobile")
        manifest.getroot().set("{" + namespace + "}versionCode", "1")
        manifest.getroot().set("{" + namespace + "}versionName", "0.1.0-dev")
        ET.SubElement(manifest.getroot(), "uses-sdk", {
            "{" + namespace + "}minSdkVersion": "26",
            "{" + namespace + "}targetSdkVersion": "35",
        })
        app = manifest.getroot().find("application")
        app.set("{" + namespace + "}label", "Helios")
        app.set("{" + namespace + "}extractNativeLibs", "true")
        app.set("{" + namespace + "}theme", "@android:style/Theme.Material.NoActionBar")
        manifest_path = work / "AndroidManifest.xml"
        manifest.write(manifest_path, encoding="utf-8", xml_declaration=True)
        apk = work / "unsigned.apk"
        run(tools / "aapt2", "link", "-I", android, "--manifest", manifest_path, "-o", apk)
        library = work / "libnsh.so"
        shutil.copyfile(args.library, library)
        strips = sorted((sdk / "ndk").glob("*/toolchains/llvm/prebuilt/*/bin/llvm-strip"))
        if strips:
            run(strips[-1], "--strip-debug", library)
        with zipfile.ZipFile(apk, "a", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.write(library, "lib/arm64-v8a/libnsh.so")
            for path in dex.glob("*.dex"):
                archive.write(path, path.name)
        aligned = work / "aligned.apk"
        run(tools / "zipalign", "-f", "4", apk, aligned)
        key = args.output.parent / "debug.keystore"
        if not key.exists():
            run("keytool", "-genkeypair", "-keystore", key, "-storepass", "android", "-keypass", "android",
                "-alias", "androiddebugkey", "-keyalg", "RSA", "-validity", "365", "-dname", "CN=Helios Development")
        run(tools / "apksigner", "sign", "--ks", key, "--ks-pass", "pass:android", "--out", args.output, aligned)
        run(tools / "apksigner", "verify", args.output)


if __name__ == "__main__":
    main()
