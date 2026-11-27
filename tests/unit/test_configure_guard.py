#!/usr/bin/env python3
import contextlib
import datetime as dt
import io
import json
import os
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import configure_guard as c
import guard


def tzif(offset=10800, name="TST"):
    abbreviation = name.encode() + b"\0"
    return (b"TZif\0" + bytes(15) + struct.pack("!6I", 0, 0, 0, 0, 1, len(abbreviation)) +
            struct.pack("!iBB", offset, 0, 0) + abbreviation)


class ConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.directory = self.folder / "proc/100"
        self.root = self.directory / "root"
        self.root.mkdir(parents=True)
        self.process = c.Process(100, self.directory, "mnt-node")
        (self.directory / "environ").write_bytes(b"TZ=Etc/GMT-3\0UNUSED_TOKEN=do-not-log\0")
        self.zone = self.root / "usr/share/zoneinfo/Etc/GMT-3"
        self.zone.parent.mkdir(parents=True)
        self.zone.write_bytes(tzif())
        self.config_path = self.folder / "guard.json"
        self.config_path.write_text(json.dumps({
            "access": {"type": "file", "path": "/old/access.log"},
            "eve": {"type": "file", "path": "/var/log/xray-ndpi/eve.json"},
            "xray_timezone": "UTC", "min_distinct_flows": 7,
            "firewall": {"host_network": True, "allowlist_cidrs": ["198.51.100.0/24"]}}))
        version = mock.patch.object(c, "xray_version", return_value=c.MIN_TUN_XRAY_VERSION)
        version.start()
        self.addCleanup(version.stop)

    def helper(self, path="/custom/xray/current"):
        helper = self.root / "usr/local/bin/xlogs"
        helper.parent.mkdir(parents=True)
        helper.write_text(f"#!/bin/sh\nexec tail -n +1 -F '{path}'\n")
        log = self.root / path.lstrip("/")
        log.parent.mkdir(parents=True)
        log.touch()

    def test_remnawave_uses_actual_xlogs_path_and_container_name(self):
        self.helper()
        inventory = [{"name": "/custom-node", "pid": 42, "network": "host", "image": "custom/image"}]
        original = os.readlink

        def readlink(path):
            return "mnt-node" if str(path) == "/proc/42/ns/mnt" else original(path)

        with mock.patch.object(c.os, "readlink", side_effect=readlink):
            source, process = c.discover_source([self.process], inventory)
        self.assertEqual(source, {"type": "docker", "container": "custom-node", "path": "/custom/xray/current"})
        self.assertIs(process, self.process)

    def test_open_access_file_is_detected_for_host_xray(self):
        directory = self.folder / "host-process"
        directory.mkdir()
        (directory / "root").symlink_to("/", target_is_directory=True)
        process = c.Process(101, directory, "host-mount")
        log = self.folder / "custom-access.log"
        log.touch()
        descriptors = directory / "fd"
        descriptors.mkdir()
        (descriptors / "7").symlink_to(log)
        # Ignore non-log files and stdout pipes.
        (descriptors / "8").symlink_to("pipe:[12345]")
        source, _ = c.discover_source([process], [])
        self.assertEqual(source, {"type": "file", "path": str(log)})

    def test_timezone_uses_xray_environment_and_copies_its_rules(self):
        label, data = c.timezone(self.process)
        self.assertEqual(label, "Etc/GMT-3")
        self.assertEqual(data, tzif())
        self.assertEqual(c.ZoneInfo.from_file(io.BytesIO(data)).utcoffset(None), dt.timedelta(hours=3))

    def test_idle_marzban_log_is_found_without_an_open_descriptor(self):
        log = self.root / "var/lib/marzban/access.log"
        log.parent.mkdir(parents=True)
        log.touch()
        self.assertEqual(c.access_paths(self.process), {"/var/lib/marzban/access.log"})

    def test_unset_tz_resolves_absolute_localtime_symlink_in_process_root(self):
        (self.directory / "environ").write_bytes(b"UNUSED=example\0")
        (self.root / "etc").mkdir()
        (self.root / "etc/localtime").symlink_to("/usr/share/zoneinfo/Etc/GMT-3")
        self.assertEqual(c.timezone(self.process), ("Etc/GMT-3", tzif()))

    def test_empty_or_unloadable_timezone_has_go_utc_fallback(self):
        for value in ("", "UTC", "Unknown/Timezone"):
            with self.subTest(value=value):
                (self.directory / "environ").write_bytes(f"TZ={value}\0".encode())
                self.assertEqual(c.timezone(self.process), ("UTC", None))

    def test_configuration_is_automatic_idempotent_and_preserves_thresholds(self):
        source = {"type": "docker", "container": "real-node", "path": "/custom/current"}
        with mock.patch.object(c, "processes", return_value=[self.process]), \
             mock.patch.object(c, "containers", return_value=[]), \
             mock.patch.object(c, "discover_source", return_value=(source, self.process)), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            c.configure(self.config_path)
            before = {str(path): path.read_bytes() for path in self.folder.rglob("*") if path.is_file()}
            c.configure(self.config_path)
            after = {str(path): path.read_bytes() for path in self.folder.rglob("*") if path.is_file()}
        self.assertEqual(before, after)
        cfg = json.loads(self.config_path.read_text())
        self.assertEqual(cfg["access"], source)
        self.assertEqual(cfg["xray_timezone_name"], "Etc/GMT-3")
        self.assertEqual(cfg["min_distinct_flows"], 7)
        self.assertEqual(cfg["firewall"]["allowlist_cidrs"], ["198.51.100.0/24"])
        guard.validate(cfg)
        stamp = guard.parse_access(
            "2025/01/15 18:00:00.000001 from tcp:203.0.113.20:50000 accepted udp:198.51.100.1:6881 "
            "[IN >> DIRECT] email: test", guard.load_timezone(cfg["xray_timezone"]))["ts"]
        self.assertAlmostEqual(stamp, dt.datetime(2025, 1, 15, 15, tzinfo=dt.timezone.utc).timestamp(), places=4)
        self.assertIn("Changed:", output.getvalue())
        self.assertIn("unchanged", output.getvalue())
        self.assertNotIn("do-not-log", output.getvalue())

    def test_discovery_failure_leaves_existing_configuration_untouched(self):
        original = self.config_path.read_bytes()
        with mock.patch.object(c, "processes", return_value=[]), mock.patch.object(c, "containers", return_value=[]):
            with self.assertRaises(c.DiscoveryError):
                c.configure(self.config_path)
        self.assertEqual(self.config_path.read_bytes(), original)
        self.assertFalse((self.folder / "xray-timezone.tzif").exists())

    def test_interface_selection_is_saved_preserved_and_can_return_to_mark(self):
        source = {"type": "file", "path": "/var/log/xray/access.log"}
        with mock.patch.object(c, "processes", return_value=[self.process]), \
             mock.patch.object(c, "containers", return_value=[]), \
             mock.patch.object(c, "discover_source", return_value=(source, self.process)):
            c.configure(self.config_path, inspection_interface="xray-guard")
            c.configure(self.config_path)
            config = json.loads(self.config_path.read_text())
            self.assertEqual(config["inspection"], {"interface": "xray-guard"})
            self.assertEqual(config["min_distinct_flows"], 7)
            c.configure(self.config_path, inspection_mark=True)
            self.assertNotIn("inspection", json.loads(self.config_path.read_text()))

    def test_invalid_interface_does_not_change_config_or_timezone(self):
        original = self.config_path.read_bytes()
        with mock.patch.object(c, "discover_source", return_value=(
                {"type": "file", "path": "/access.log"}, self.process)):
            with self.assertRaisesRegex(ValueError, "inspection.interface"):
                c.configure(self.config_path, inspection_interface='tun"; accept')
        self.assertEqual(self.config_path.read_bytes(), original)
        self.assertFalse((self.folder / "xray-timezone.tzif").exists())

    def test_old_tun_core_does_not_change_config_or_timezone(self):
        original = self.config_path.read_bytes()
        with mock.patch.object(c, "discover_source", return_value=(
                {"type": "file", "path": "/access.log"}, self.process)), \
             mock.patch.object(c, "xray_version", return_value=(26, 3, 27)):
            with self.assertRaisesRegex(c.CoreVersionError, "26.3.27.*too old for TUN"):
                c.configure(self.config_path, inspection_interface="xray-guard")
        self.assertEqual(self.config_path.read_bytes(), original)
        self.assertFalse((self.folder / "xray-timezone.tzif").exists())

    def test_install_version_failure_cannot_be_deferred(self):
        original = self.config_path.read_bytes()
        with mock.patch.object(c, "processes", return_value=[self.process]), \
             mock.patch.object(c, "containers", return_value=[]), \
             mock.patch.object(c, "xray_version", return_value=(26, 3, 27)), \
             mock.patch.object(c.os, "geteuid", return_value=0), \
             mock.patch("sys.argv", ["configure_guard.py", "--config", str(self.config_path),
                                     "--check-core", "--defer"]), \
             contextlib.redirect_stderr(io.StringIO()) as error:
            with self.assertRaises(SystemExit) as raised:
                c.main()
        self.assertEqual(raised.exception.code, 1)
        self.assertIn("26.3.27", error.getvalue())
        self.assertEqual(self.config_path.read_bytes(), original)

    def test_install_can_defer_detection_until_xray_starts(self):
        original = self.config_path.read_bytes()
        with mock.patch.object(c, "processes", return_value=[]), \
             mock.patch.object(c, "containers", return_value=[]), \
             mock.patch.object(c.os, "geteuid", return_value=0), \
             mock.patch.object(c, "__name__", "configure_guard"), \
             mock.patch("sys.argv", ["configure_guard.py", "--config", str(self.config_path), "--defer"]), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            c.main()
        self.assertIn("Detection deferred until enable", output.getvalue())
        self.assertEqual(self.config_path.read_bytes(), original)

    def test_several_nodes_require_explicit_selection(self):
        first = self.process
        second = c.Process(101, self.directory, "mnt-second")
        inventory = [{"name": "/first", "pid": 1, "network": "host"},
                     {"name": "/second", "pid": 2, "network": "host"}]

        def readlink(path):
            return "mnt-node" if str(path) == "/proc/1/ns/mnt" else "mnt-second"

        with mock.patch.object(c.os, "readlink", side_effect=readlink), \
             mock.patch.object(c, "xlogs_path", return_value="/logs/current"):
            with self.assertRaisesRegex(c.DiscoveryError, "Several Xray"):
                c.discover_source([first, second], inventory)
            source, _ = c.discover_source([first, second], inventory, container="second")
            self.assertEqual(source["container"], "second")


class CoreVersionTests(unittest.TestCase):
    def setUp(self):
        self.process = c.Process(100, Path("/proc/100"), "mnt-node")

    def test_reads_actual_running_executable_instead_of_path_binary(self):
        response = subprocess.CompletedProcess([], 0, "Xray 26.11.9 (Xray, Penetrates Everything.)\n", "")
        with mock.patch.object(c.subprocess, "run", return_value=response) as command:
            self.assertEqual(c.xray_version(self.process), (26, 11, 9))
        command.assert_called_once_with(["/proc/100/exe", "version"],
                                        capture_output=True, text=True, timeout=15)

    def test_unreadable_or_invalid_core_version_fails(self):
        for text, status in (("Xray 26.11.9\n", 1), ("", 0), ("Xray unknown\n", 0),
                             ("not Xray 26.11.9\n", 0), ("Xray 26.11\n", 0)):
            with self.subTest(text=text, status=status), \
                 mock.patch.object(c.subprocess, "run", return_value=subprocess.CompletedProcess(
                     [], status, text, "")):
                with self.assertRaises(c.CoreVersionError):
                    c.xray_version(self.process)
        for error in (OSError("not executable"), subprocess.TimeoutExpired("xray version", 15)):
            with self.subTest(error=error), mock.patch.object(c.subprocess, "run", side_effect=error):
                with self.assertRaises(c.CoreVersionError):
                    c.xray_version(self.process)

    def test_minimum_and_newer_tun_versions_are_accepted(self):
        for version in ((26, 11, 9), (26, 11, 10), (27, 1, 1)):
            with self.subTest(version=version), \
                 mock.patch.object(c, "xray_version", return_value=version), \
                 contextlib.redirect_stdout(io.StringIO()) as output:
                c.verify_core(self.process, require_tun=True)
                self.assertIn("TUN version check passed", output.getvalue())

    def test_older_tun_versions_are_rejected(self):
        for version in ((26, 3, 27), (26, 11, 8), (25, 12, 31)):
            with self.subTest(version=version), mock.patch.object(c, "xray_version", return_value=version):
                with self.assertRaisesRegex(c.CoreVersionError, ">= 26.11.9"):
                    c.verify_core(self.process, require_tun=True)

    def test_direct_mark_mode_does_not_require_tun_version(self):
        with mock.patch.object(c, "xray_version", return_value=(26, 3, 27)), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            c.verify_core(self.process, require_tun=False)
        self.assertIn("DIRECT/SO_MARK only", output.getvalue())

    def test_core_discovery_does_not_require_access_logs(self):
        with mock.patch.object(c, "access_paths", side_effect=AssertionError("must not read logs")), \
             mock.patch.object(c, "xlogs_path", side_effect=AssertionError("must not read logs")):
            self.assertIs(c.discover_core([self.process], []), self.process)

    def test_selects_actual_container_core(self):
        second = c.Process(101, Path("/proc/101"), "mnt-second")
        inventory = [{"name": "/first", "pid": 1, "network": "host"},
                     {"name": "/second", "pid": 2, "network": "host"}]
        with mock.patch.object(c.os, "readlink", side_effect=lambda path:
                               "mnt-node" if str(path) == "/proc/1/ns/mnt" else "mnt-second"):
            self.assertIs(c.discover_core([self.process, second], inventory, "second"), second)
            with self.assertRaisesRegex(c.CoreVersionError, "Several running Xray"):
                c.discover_core([self.process, second], inventory)
            with self.assertRaises(c.DiscoveryError):
                c.discover_core([self.process, second], inventory, "missing")

    def test_rejects_container_without_host_network(self):
        inventory = [{"name": "/node", "pid": 1, "network": "bridge"}]
        with mock.patch.object(c.os, "readlink", return_value="mnt-node"):
            with self.assertRaisesRegex(c.CoreVersionError, "network_mode: host"):
                c.discover_core([self.process], inventory, "node")


if __name__ == "__main__":
    unittest.main()
