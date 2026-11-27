#!/usr/bin/env python3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "integration"))

import test_external_vless as external


class ExternalVlessTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "node.link"
        self.uri = ("vless://00000000-0000-4000-8000-000000000001@192.0.2.1:443?"
                    "security=reality&type=raw&sni=example.test&fp=firefox&pbk=test-key&sid=abcd")

    def test_missing_flow_is_not_replaced_with_vision(self):
        self.path.write_text(self.uri, encoding="utf-8")
        outbound = external.parse_vless(self.path)
        server = outbound["settings"]["vnext"][0]
        self.assertEqual(server["address"], "192.0.2.1")
        self.assertEqual(server["port"], 443)
        self.assertNotIn("flow", server["users"][0])
        self.assertEqual(outbound["streamSettings"], {
            "network": "raw", "security": "reality", "realitySettings": {
                "serverName": "example.test", "fingerprint": "firefox",
                "publicKey": "test-key", "shortId": "abcd"}})

    def test_explicit_vision_is_preserved(self):
        self.path.write_text(self.uri + "&flow=xtls-rprx-vision", encoding="utf-8")
        user = external.parse_vless(self.path)["settings"]["vnext"][0]["users"][0]
        self.assertEqual(user["flow"], "xtls-rprx-vision")

    def test_non_reality_link_is_rejected(self):
        self.path.write_text(self.uri.replace("security=reality", "security=none"), encoding="utf-8")
        with self.assertRaises(ValueError):
            external.parse_vless(self.path)


if __name__ == "__main__":
    unittest.main()
