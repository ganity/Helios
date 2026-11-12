#!/usr/bin/env python3
"""Generate the two-target Xcode project using only Python's standard library."""
import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import re


ROOT = Path(__file__).resolve().parent


def identifier(value):
    return hashlib.sha256(value.encode()).hexdigest()[:24].upper()


def encode(value):
    if isinstance(value, dict):
        return "{\n" + "".join(f"{json.dumps(str(key))} = {encode(item)};\n" for key, item in value.items()) + "}"
    if isinstance(value, list):
        return "(" + ", ".join(encode(item) for item in value) + ")"
    return json.dumps(str(value))


def plist(path, content):
    path.write_bytes(plistlib.dumps(content, sort_keys=False))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle-id", default="com.helios.mobile")
    parser.add_argument("--app-group", default="group.com.helios.mobile")
    parser.add_argument("--team", default="")
    args = parser.parse_args()
    for value in (args.bundle_id, args.app_group):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]+", value):
            parser.error("Bundle and App Group identifiers must contain only letters, numbers, dots and hyphens")
    if args.team and not re.fullmatch(r"[A-Z0-9]{10}", args.team):
        parser.error("Team ID must contain 10 uppercase letters/digits")
    config = ROOT / "Config.xcconfig"
    if not config.exists():
        config.write_text(f"HELIOS_BUNDLE_ID = {args.bundle_id}\nHELIOS_APP_GROUP = {args.app_group}\nDEVELOPMENT_TEAM = {args.team}\n")
    common = {
        "CFBundleDevelopmentRegion": "zh_CN", "CFBundleExecutable": "$(EXECUTABLE_NAME)",
        "CFBundleIdentifier": "$(PRODUCT_BUNDLE_IDENTIFIER)", "CFBundleInfoDictionaryVersion": "6.0",
        "CFBundleName": "$(PRODUCT_NAME)", "CFBundleShortVersionString": "0.1.0", "CFBundleVersion": "1",
        "HeliosAppGroup": "$(HELIOS_APP_GROUP)",
    }
    plist(ROOT / "App/Info.plist", {**common, "CFBundlePackageType": "APPL", "CFBundleDisplayName": "Helios",
        "LSRequiresIPhoneOS": True, "UILaunchScreen": {},
        "UISupportedInterfaceOrientations": ["UIInterfaceOrientationPortrait", "UIInterfaceOrientationLandscapeLeft", "UIInterfaceOrientationLandscapeRight"],
        "UISupportedInterfaceOrientations~ipad": ["UIInterfaceOrientationPortrait", "UIInterfaceOrientationPortraitUpsideDown", "UIInterfaceOrientationLandscapeLeft", "UIInterfaceOrientationLandscapeRight"],
        "CFBundleURLTypes": [{"CFBundleURLName": "$(PRODUCT_BUNDLE_IDENTIFIER)", "CFBundleURLSchemes": ["helios"]}],
    })
    plist(ROOT / "PacketTunnel/Info.plist", {**common, "CFBundlePackageType": "XPC!",
        "NSExtension": {"NSExtensionPointIdentifier": "com.apple.networkextension.packet-tunnel",
                        "NSExtensionPrincipalClass": "$(PRODUCT_MODULE_NAME).PacketTunnelProvider"}})
    entitlements = {"com.apple.developer.networking.networkextension": ["packet-tunnel-provider"],
                    "com.apple.security.application-groups": ["$(HELIOS_APP_GROUP)"]}
    for target in ("App", "PacketTunnel"):
        plist(ROOT / target / "Helios.entitlements", entitlements)

    objects = {}
    def add(object_key, isa, **values):
        key = identifier(object_key)
        objects[key] = {"isa": isa, **values}
        return key
    config_ref = add("config", "PBXFileReference", lastKnownFileType="text.xcconfig", path="Config.xcconfig", sourceTree="<group>")
    app_product = add("app-product", "PBXFileReference", explicitFileType="wrapper.application", path="Helios.app", sourceTree="BUILT_PRODUCTS_DIR")
    extension_product = add("extension-product", "PBXFileReference", explicitFileType="wrapper.app-extension", path="PacketTunnel.appex", sourceTree="BUILT_PRODUCTS_DIR")
    products = add("products", "PBXGroup", children=[app_product, extension_product], name="Products", sourceTree="<group>")
    sources = {}
    for path in ("App/AppDelegate.swift", "App/VPNController.swift", "PacketTunnel/PacketTunnelProvider.swift", "Shared/SharedContainer.swift"):
        sources[path] = add(path, "PBXFileReference", lastKnownFileType="sourcecode.swift", path=path, sourceTree="<group>")
    group = add("root-group", "PBXGroup", children=[config_ref, *sources.values(), products], sourceTree="<group>")
    root_settings = {
        "IPHONEOS_DEPLOYMENT_TARGET": "16.0", "SDKROOT": "iphoneos", "SWIFT_VERSION": "5.0",
        "CLANG_ENABLE_MODULES": "YES", "CLANG_ENABLE_OBJC_ARC": "YES", "ENABLE_USER_SCRIPT_SANDBOXING": "NO",
        "CODE_SIGN_STYLE": "Automatic", "TARGETED_DEVICE_FAMILY": "1,2",
        "SUPPORTED_PLATFORMS": "iphoneos iphonesimulator", "ONLY_ACTIVE_ARCH": "YES",
    }
    def configurations(name, settings):
        values = []
        for mode in ("Debug", "Release"):
            values.append(add(f"{name}-{mode}", "XCBuildConfiguration", name=mode,
                baseConfigurationReference=config_ref,
                buildSettings={**settings, "SWIFT_OPTIMIZATION_LEVEL": "-Onone" if mode == "Debug" else "-O"}))
        return add(name + "-configurations", "XCConfigurationList", buildConfigurations=values,
                   defaultConfigurationIsVisible="0", defaultConfigurationName="Debug")
    project_configs = configurations("project", root_settings)
    targets = []
    for name, component, paths, product, product_type in (
        ("Helios", "app", ["App/AppDelegate.swift", "App/VPNController.swift", "Shared/SharedContainer.swift"], app_product, "com.apple.product-type.application"),
        ("PacketTunnel", "tunnel", ["PacketTunnel/PacketTunnelProvider.swift", "Shared/SharedContainer.swift"], extension_product, "com.apple.product-type.app-extension"),
    ):
        build_sources = [add(name + path, "PBXBuildFile", fileRef=sources[path]) for path in paths]
        native = add(name + "-rust", "PBXShellScriptBuildPhase", buildActionMask="2147483647", files=[],
            inputPaths=[], outputPaths=[], runOnlyForDeploymentPostprocessing="0", alwaysOutOfDate="1",
            shellPath="/bin/sh", shellScript=f'export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"\npython3 "$PROJECT_DIR/build_rust.py" {component}\n', name="Build Rust")
        compile_phase = add(name + "-sources", "PBXSourcesBuildPhase", buildActionMask="2147483647", files=build_sources, runOnlyForDeploymentPostprocessing="0")
        frameworks = add(name + "-frameworks", "PBXFrameworksBuildPhase", buildActionMask="2147483647", files=[], runOnlyForDeploymentPostprocessing="0")
        library = "helios_ios_ui" if component == "app" else "helios_mobile_core"
        directory = "App" if component == "app" else "PacketTunnel"
        settings = {
            "PRODUCT_NAME": "$(TARGET_NAME)", "PRODUCT_BUNDLE_IDENTIFIER": "$(HELIOS_BUNDLE_ID)" + ("" if component == "app" else ".PacketTunnel"),
            "INFOPLIST_FILE": directory + "/Info.plist", "CODE_SIGN_ENTITLEMENTS": directory + "/Helios.entitlements",
            "SWIFT_OBJC_BRIDGING_HEADER": "Shared/HeliosUI.h" if component == "app" else "Shared/HeliosCore.h",
            "LIBRARY_SEARCH_PATHS": ["$(inherited)", "$(PROJECT_DIR)/build/rust/$(PLATFORM_NAME)/$(CURRENT_ARCH)"],
            "OTHER_LDFLAGS": ["$(inherited)", "-l" + library,
                "@$(PROJECT_DIR)/build/rust/$(PLATFORM_NAME)/$(CURRENT_ARCH)/" + component + "-linker-flags.rsp",
                "-framework", "NetworkExtension", "-framework", "Network", "-framework", "UIKit"],
            "LD_RUNPATH_SEARCH_PATHS": ["$(inherited)", "@executable_path/Frameworks", "@executable_path/../../Frameworks"],
            "GENERATE_INFOPLIST_FILE": "NO", "SWIFT_EMIT_LOC_STRINGS": "NO",
        }
        if component == "tunnel":
            settings.update({"APPLICATION_EXTENSION_API_ONLY": "YES", "SKIP_INSTALL": "YES"})
        targets.append(add(name + "-target", "PBXNativeTarget", name=name, productName=name,
            productReference=product, productType=product_type, buildPhases=[native, compile_phase, frameworks],
            buildRules=[], dependencies=[], buildConfigurationList=configurations(name, settings)))
    embed_file = add("embed-extension-file", "PBXBuildFile", fileRef=extension_product, settings={"ATTRIBUTES": ["RemoveHeadersOnCopy"]})
    embed = add("embed-extension", "PBXCopyFilesBuildPhase", buildActionMask="2147483647", dstPath="", dstSubfolderSpec="13",
        files=[embed_file], name="Embed App Extensions", runOnlyForDeploymentPostprocessing="0")
    project_id = identifier("project")
    proxy = add("extension-proxy", "PBXContainerItemProxy", containerPortal=project_id, proxyType="1", remoteGlobalIDString=targets[1], remoteInfo="PacketTunnel")
    dependency = add("extension-dependency", "PBXTargetDependency", target=targets[1], targetProxy=proxy)
    objects[targets[0]]["buildPhases"].append(embed)
    objects[targets[0]]["dependencies"].append(dependency)
    add("project", "PBXProject", attributes={"LastUpgradeCheck": "1600", "BuildIndependentTargetsInParallel": "YES"},
        buildConfigurationList=project_configs, compatibilityVersion="Xcode 14.0", developmentRegion="zh_CN",
        knownRegions=["zh_CN", "en", "Base"], mainGroup=group, productRefGroup=products, projectDirPath="", projectRoot="", targets=targets)
    project = ROOT / "Helios.xcodeproj"
    project.mkdir(exist_ok=True)
    (project / "project.pbxproj").write_text("// !$*UTF8*$!\n" + encode({"archiveVersion": 1, "classes": {}, "objectVersion": 56, "objects": objects, "rootObject": project_id}) + "\n")
    scheme = project / "xcshareddata/xcschemes"
    scheme.mkdir(parents=True, exist_ok=True)
    (scheme / "Helios.xcscheme").write_text(f'''<?xml version="1.0" encoding="UTF-8"?>
<Scheme LastUpgradeVersion="1600" version="1.3">
 <BuildAction parallelizeBuildables="YES" buildImplicitDependencies="YES"><BuildActionEntries>
  <BuildActionEntry buildForTesting="YES" buildForRunning="YES" buildForProfiling="YES" buildForArchiving="YES" buildForAnalyzing="YES">
   <BuildableReference BuildableIdentifier="primary" BlueprintIdentifier="{targets[0]}" BuildableName="Helios.app" BlueprintName="Helios" ReferencedContainer="container:Helios.xcodeproj"/>
  </BuildActionEntry>
 </BuildActionEntries></BuildAction>
 <LaunchAction buildConfiguration="Debug" selectedDebuggerIdentifier="Xcode.DebuggerFoundation.Debugger.LLDB" selectedLauncherIdentifier="Xcode.IDEFoundation.Launcher.LLDB" launchStyle="0" useCustomWorkingDirectory="NO" ignoresPersistentStateOnLaunch="NO" debugDocumentVersioning="YES" debugServiceExtension="internal" allowLocationSimulation="YES">
  <BuildableProductRunnable runnableDebuggingMode="0"><BuildableReference BuildableIdentifier="primary" BlueprintIdentifier="{targets[0]}" BuildableName="Helios.app" BlueprintName="Helios" ReferencedContainer="container:Helios.xcodeproj"/></BuildableProductRunnable>
 </LaunchAction>
 <ArchiveAction buildConfiguration="Release" revealArchiveInOrganizer="YES"/>
</Scheme>
''')
    print(project)


if __name__ == "__main__":
    main()
