# Android service integration status

`HeliosVpnService.java` calls the JNI entry exported by the Rust library. It
establishes IPv4/IPv6 default routes and a DNS resolver through the tunnel,
runs forwarding on a worker thread, and stops when VPN consent is revoked.
It currently uses full proxy mode. MainActivity handles consent and the shared
NSH UI sends connection requests through JNI. Service state, authorization
cancellation and startup errors are returned to the UI. The service verifies
TLS authentication and a UDP association before reporting a connected state.

A custom host now lives in `runner`; `package.py` compiles the Java sources,
creates dex, packages the library, aligns the APK and verifies a development
signature. From the experiment directory, with ANDROID_HOME set:

```sh
python3 android/package.py --nsh-source /path/to/pinned/nsh \
  --library android/runner/target/aarch64-linux-android/debug/libnsh.so \
  --output /path/to/build/helios-arm64-debug.apk
```

Keep the generated debug.keystore beside the output for repeat installations.
For a complete Linux build, use `ANDROID_HOME=/path/to/sdk python3 android/build.py`
from the experiment directory (JDK 17+, SDK 36, NDK and the Rust Android target).
The integration uses these contracts:

1. Include these Java sources, merge `AndroidManifest.xml`, and apply
   `proguard-rules.pro` so JNI method names survive minification.
2. Package an NSH `libnsh.so` linked with this app's Rust crate. Check that
   `Java_com_helios_mobile_HeliosVpnService_nativeRun` is exported in the final
   library; checking the Rust library alone does not verify this.
3. Obtain consent using `VpnService.prepare(activity)` and wait for the result.
4. Start the foreground service explicitly with the selected `NodeProfile`
   JSON in extra `HeliosVpnService.NODE`. This metadata contains paths to
   private credential files, not a `helios://` link or raw token.
5. Poll service state and display errors in NSH. Disconnect either by stopping
   the service or using its notification action `HeliosVpnService.STOP`.

The descriptor remains owned by Java throughout the blocking native call;
Rust duplicates it and owns only the duplicate. Neither layer should detach
or close the other layer's descriptor.

Validation: Java compilation, ARM64 library linking and JNI exports, APK
packaging and signature verification. Installation, VPN consent, routing,
background operation and revocation still require device tests. Domain rules,
DNS mapping and Android rule-mode controls remain unfinished. The iOS host and
its separate acceptance gates are documented in `../ios/README.md`.

## GitHub Actions packages

The shared `.github/workflows/mobile-ios.yml` workflow builds an ARM64 release
APK on Ubuntu with JDK 17, Android SDK/build-tools 36 and NDK 28.2.13676358.
It runs the engine/UI tests, links the native library, compiles the Java host,
packages and verifies the APK, and uploads `helios-android-apk` with SHA256SUMS.
Run it manually from Actions or push changes to the mobile sources/dependencies.
The key is a development key generated for that build, not a production signing
identity. Installing a later CI build may require uninstalling the old one,
which removes its local nodes/settings. Keep your import links before uninstalling.
The same workflow provides an unsigned IPA under `helios-ios-ipa`.
