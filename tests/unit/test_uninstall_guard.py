#!/usr/bin/env python3
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import inspector


class UninstallTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.paths = inspector.Paths(self.root)
        self.units = ("xray-connection-guard.service", "xray-ndpi.service", inspector.QUEUE_UNIT)
        self.removed = [self.paths.units / unit for unit in self.units]
        self.removed.extend(self.paths.helper.parent / name for name in (
            "guard.py", "log_maintenance.py", "inspector.py", "tun_network.py",
            "install_suricata.py", "configure_guard.py", "install-suricata.lock"))
        self.removed.extend((self.paths.units / "xray-connection-guard.service.d/mode.conf",
                             self.paths.bypass, self.paths.config / "inspection.lock",
                             self.paths.network.with_suffix(".lock")))
        self.retained = [self.paths.config / "config.json", self.paths.yaml, self.paths.rules,
                         self.paths.state, self.paths.log / "eve.json",
                         self.paths.helper.parent / "guard.py.bak.123",
                         self.paths.helper.parent / "engines/local/bin/suricata",
                         self.paths.helper.parent / "custom-file",
                         self.paths.units / "xray-ndpi.service.bak.123",
                         self.paths.units / "other.service",
                         self.root / "etc/xray/config.json"]
        for path in self.removed + self.retained:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("preserved content\n")
        (self.paths.units / "xray-ndpi.service").write_text(f"ExecStartPre={self.paths.helper} check\n")
        self.saved_content = {path: path.read_text() for path in self.removed + self.retained}
        self.paths.network.parent.mkdir(parents=True, exist_ok=True)
        self.paths.network.write_text("runtime state\n")
        network_patch = mock.patch.object(inspector.tun_network, "Network")
        self.network = network_patch.start().return_value
        self.addCleanup(network_patch.stop)
        self.network.clear.side_effect = lambda: self.paths.network.unlink(missing_ok=True)
        queue_patch = mock.patch.object(inspector, "update_queue")
        self.queue = queue_patch.start()
        self.addCleanup(queue_patch.stop)
        run_patch = mock.patch.object(inspector, "run", side_effect=self.command)
        self.run = run_patch.start()
        self.addCleanup(run_patch.stop)

    def command(self, arguments, **kwargs):
        output = ""
        if arguments[:2] == ["systemctl", "show"]:
            output = "loaded\n"
        elif arguments == ["nft", "-j", "list", "tables"]:
            output = json.dumps({"nftables": [
                {"table": {"family": "inet", "name": "xray_client_ban"}},
                {"table": {"family": "inet", "name": "unrelated"}}]})
        return subprocess.CompletedProcess(arguments, 0, output, "")

    def assert_files_untouched(self):
        for path, content in self.saved_content.items():
            self.assertEqual(path.read_text(), content, str(path))

    def test_removes_only_program_units_and_runtime_after_network_cleanup(self):
        with mock.patch.dict(os.environ, {"SERVICE_RESULT": "exit-code"}):
            inspector.uninstall(self.paths)
        for path in self.removed:
            self.assertFalse(path.exists(), str(path))
        for path in self.retained:
            self.assertEqual(path.read_text(), "preserved content\n", str(path))
        self.assertFalse(self.paths.network.exists())
        self.assertFalse(self.paths.network.parent.exists())
        self.network.clear.assert_called_once_with()
        self.queue.assert_called_once_with(remove=True, paths=self.paths)
        for unit in self.units:
            self.run.assert_any_call(["systemctl", "disable", "--now", unit])
        self.run.assert_any_call(["nft", "delete", "table", "inet", "xray_client_ban"])
        self.assertEqual(self.run.call_args, mock.call(["systemctl", "daemon-reload"]))

    def test_repeated_uninstall_skips_missing_units_and_bans(self):
        def missing(arguments, **kwargs):
            if arguments[:2] == ["systemctl", "show"]:
                return subprocess.CompletedProcess(arguments, 4, "not-found\n", "")
            if arguments == ["nft", "-j", "list", "tables"]:
                return subprocess.CompletedProcess(arguments, 0, '{"nftables": []}', "")
            return self.command(arguments, **kwargs)

        self.run.side_effect = missing
        inspector.uninstall(self.paths)
        inspector.uninstall(self.paths)
        self.assertFalse(any(call.args[0][:2] == ["systemctl", "disable"] for call in self.run.call_args_list))
        self.assertFalse(any(call.args[0][:2] == ["nft", "delete"] for call in self.run.call_args_list))
        self.assertEqual(self.network.clear.call_count, 2)

    def test_service_query_error_leaves_files_and_network_untouched(self):
        self.run.side_effect = lambda arguments, **kwargs: subprocess.CompletedProcess(
            arguments, 1, "", "cannot connect to systemd")
        with self.assertRaisesRegex(RuntimeError, "Cannot query.*cannot connect"):
            inspector.uninstall(self.paths)
        self.assert_files_untouched()
        self.network.clear.assert_not_called()

    def test_empty_service_state_is_not_assumed_absent(self):
        self.run.side_effect = lambda arguments, **kwargs: subprocess.CompletedProcess(arguments, 0, "", "")
        with self.assertRaisesRegex(RuntimeError, "empty LoadState"):
            inspector.uninstall(self.paths)
        self.assert_files_untouched()
        self.network.clear.assert_not_called()

    def test_foreign_inspector_unit_is_not_stopped_or_removed(self):
        unit = self.paths.units / "xray-ndpi.service"
        unit.write_text("ExecStart=/usr/bin/unrelated-inspector\n")
        with self.assertRaisesRegex(RuntimeError, "unowned service"):
            inspector.uninstall(self.paths)
        self.assertEqual(unit.read_text(), "ExecStart=/usr/bin/unrelated-inspector\n")
        self.run.assert_not_called()
        self.network.clear.assert_not_called()

    def test_external_inspector_without_our_unit_is_left_running(self):
        (self.paths.units / "xray-ndpi.service").unlink()
        inspector.uninstall(self.paths)
        self.assertFalse(any("xray-ndpi.service" in call.args[0] for call in self.run.call_args_list))

    def test_shutdown_error_leaves_files_and_network_untouched(self):
        def fail(arguments, **kwargs):
            if arguments == ["systemctl", "disable", "--now", inspector.QUEUE_UNIT]:
                raise RuntimeError("queue shutdown failed")
            return self.command(arguments, **kwargs)

        self.run.side_effect = fail
        with self.assertRaisesRegex(RuntimeError, "queue shutdown failed"):
            inspector.uninstall(self.paths)
        self.assert_files_untouched()
        self.network.clear.assert_not_called()

    def test_route_cleanup_error_prevents_file_removal(self):
        self.network.clear.side_effect = RuntimeError("unowned route state")
        with self.assertRaisesRegex(RuntimeError, "unowned route state"):
            inspector.uninstall(self.paths)
        self.assert_files_untouched()
        self.queue.assert_not_called()

    def test_queue_cleanup_error_prevents_file_removal(self):
        self.queue.side_effect = RuntimeError("unowned nftables table")
        with self.assertRaisesRegex(RuntimeError, "unowned nftables table"):
            inspector.uninstall(self.paths)
        self.assert_files_untouched()

    def test_nftables_error_prevents_file_removal(self):
        for failed in (["nft", "-j", "list", "tables"],
                       ["nft", "delete", "table", "inet", "xray_client_ban"]):
            with self.subTest(arguments=failed):
                def fail(arguments, **kwargs):
                    if arguments == failed:
                        raise RuntimeError("nftables failed")
                    return self.command(arguments, **kwargs)

                self.run.side_effect = fail
                with self.assertRaisesRegex(RuntimeError, "nftables failed"):
                    inspector.uninstall(self.paths)
                self.assert_files_untouched()

    def test_daemon_reload_error_is_reported(self):
        def fail(arguments, **kwargs):
            if arguments == ["systemctl", "daemon-reload"]:
                raise RuntimeError("reload failed")
            return self.command(arguments, **kwargs)

        self.run.side_effect = fail
        with self.assertRaisesRegex(RuntimeError, "reload failed"):
            inspector.uninstall(self.paths)


if __name__ == "__main__":
    unittest.main()
