#!/usr/bin/env python3
"""Local checks for project generation; Apple SDK builds are a separate CI gate."""
import contextlib
import importlib.util
import io
from pathlib import Path
import plistlib
import sys
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

spec = importlib.util.spec_from_file_location("generate", Path(__file__).with_name("generate.py"))
generate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(generate)


class ProjectTest(unittest.TestCase):
    def test_app_embeds_extension_with_matching_entitlements_and_scheme(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "App").mkdir()
            (root / "PacketTunnel").mkdir()
            with patch.object(generate, "ROOT", root), patch.object(sys, "argv", ["generate.py"]), contextlib.redirect_stdout(io.StringIO()):
                generate.main()
                original = (root / "Helios.xcodeproj/project.pbxproj").read_bytes()
                generate.main()
                self.assertEqual((root / "Helios.xcodeproj/project.pbxproj").read_bytes(), original)
            project = original.decode()
            self.assertEqual(project.count('"isa" = "PBXNativeTarget"'), 2)
            self.assertIn('"dstSubfolderSpec" = "13"', project)
            self.assertIn('"name" = "Embed App Extensions"', project)
            self.assertIn('"APPLICATION_EXTENSION_API_ONLY" = "YES"', project)
            for target in ("App", "PacketTunnel"):
                entitlements = plistlib.loads((root / target / "Helios.entitlements").read_bytes())
                self.assertEqual(entitlements["com.apple.developer.networking.networkextension"], ["packet-tunnel-provider"])
                self.assertEqual(entitlements["com.apple.security.application-groups"], ["$(HELIOS_APP_GROUP)"])
            info = plistlib.loads((root / "PacketTunnel/Info.plist").read_bytes())
            self.assertEqual(info["NSExtension"]["NSExtensionPointIdentifier"], "com.apple.networkextension.packet-tunnel")
            self.assertEqual(info["NSExtension"]["NSExtensionPrincipalClass"], "$(PRODUCT_MODULE_NAME).PacketTunnelProvider")
            scheme = ET.parse(root / "Helios.xcodeproj/xcshareddata/xcschemes/Helios.xcscheme")
            self.assertEqual(scheme.find(".//BuildableReference").get("BlueprintIdentifier"), generate.identifier("Helios-target"))
            config = root / "Config.xcconfig"
            config.write_text("// preserved user configuration\n")
            with patch.object(generate, "ROOT", root), patch.object(sys, "argv", ["generate.py"]), contextlib.redirect_stdout(io.StringIO()):
                generate.main()
            self.assertEqual(config.read_text(), "// preserved user configuration\n")


if __name__ == "__main__":
    unittest.main()
