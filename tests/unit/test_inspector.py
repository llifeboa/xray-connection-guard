#!/usr/bin/env python3
import copy
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

import inspector as i


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.paths = i.Paths(self.root)
        self.binary = self.root / "suricata"
        self.binary.write_text("installed binary")
        self.binary.chmod(0o755)
        self.base = self.root / "original.yaml"
        self.original = {
            "stream": {"memcap": "64mb"},
            "app-layer": {"protocols": {"tls": {"enabled": True}}},
            "rule-files": ["unrelated.rules"],
            "run-as": {"user": "suricata"},
        }
        self.base.write_text(yaml.safe_dump(self.original))
        self.config = self.root / "guard.json"
        self.eve = self.root / "logs/eve.json"
        self.config.write_text(json.dumps({
            "eve": {"type": "file", "path": str(self.eve)}, "signatures": [i.SID]}))
        self.paths.units.mkdir(parents=True)
        self.old_unit = self.paths.units / "xray-ndpi.service"
        self.old_unit.write_text("original unit\n")
        self.discovery = mock.patch.object(i, "discover", return_value=(
            str(self.binary), self.base, copy.deepcopy(self.original)))
        self.discovery.start()
        self.addCleanup(self.discovery.stop)

    def test_preflight_uses_staging_and_original_config_is_preserved(self):
        staged = []

        def validate(args, **kwargs):
            document = yaml.safe_load(Path(args[args.index("-c") + 1]).read_text())
            self.assertNotEqual(document["outputs"][0]["eve-log"]["filename"], str(self.eve))
            self.assertTrue(Path(document["rule-files"][0]).is_file())
            staged.append(document)
            return subprocess.CompletedProcess(args, 0, "", "")

        with mock.patch.object(i, "run", side_effect=validate):
            i.prepare(self.paths, self.config)
        self.assertEqual(len(staged), 1)
        installed = yaml.safe_load(self.paths.yaml.read_text())
        self.assertTrue(self.paths.yaml.read_text().startswith("%YAML 1.1\n---\n"))
        self.assertEqual(installed["app-layer"], self.original["app-layer"])
        self.assertEqual(installed["stream"]["memcap"], "64mb")
        self.assertTrue(installed["stream"]["inline"])
        self.assertNotIn("run-as", installed)
        self.assertEqual(installed["outputs"][0]["eve-log"]["filename"], str(self.eve))
        self.assertEqual(installed["rule-files"], [str(self.paths.rules)])
        self.assertEqual(yaml.safe_load(self.base.read_text()), self.original)
        backups = list(self.paths.units.glob("xray-ndpi.service.bak.*"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_text(), "original unit\n")

    def test_failed_suricata_validation_does_not_replace_any_installed_files(self):
        self.paths.config.mkdir(parents=True)
        self.paths.yaml.write_text("previous yaml\n")
        self.paths.rules.write_text("previous rules\n")
        with mock.patch.object(i, "run", side_effect=RuntimeError("unknown ndpi-protocol")):
            with self.assertRaisesRegex(RuntimeError, "ndpi-protocol"):
                i.prepare(self.paths, self.config)
        self.assertEqual(self.old_unit.read_text(), "original unit\n")
        self.assertEqual(self.paths.yaml.read_text(), "previous yaml\n")
        self.assertEqual(self.paths.rules.read_text(), "previous rules\n")
        self.assertFalse(self.paths.state.exists())
        self.assertFalse((self.paths.units / i.QUEUE_UNIT).exists())

    def test_repeated_install_does_not_duplicate_rules_or_backups(self):
        with mock.patch.object(i, "run"):
            i.prepare(self.paths, self.config)
            before = {str(p): p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
            i.prepare(self.paths, self.config)
        after = {str(p): p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
        self.assertEqual(before, after)
        self.assertEqual(self.paths.rules.read_text().count(f"sid:{i.SID};"), 1)

    def test_interface_selection_survives_install_and_replaces_mark_selection(self):
        config = json.loads(self.config.read_text())
        config["inspection"] = {"interface": "xray-guard"}
        self.config.write_text(json.dumps(config))
        with mock.patch.object(i, "run"):
            i.prepare(self.paths, self.config)
        state = json.loads(self.paths.state.read_text())
        self.assertEqual(state["interface"], "xray-guard")
        self.assertNotIn("mark", state)
        self.assertEqual(i.selected_interface(self.paths), "xray-guard")
        with mock.patch.object(i, "check_interface") as check, mock.patch.object(i, "run"):
            i.check(self.paths)
        check.assert_called_once_with("xray-guard")

    def test_incompatible_log_or_sid_is_rejected_before_preflight(self):
        for cfg in ({"eve": {"type": "docker", "path": "/eve"}},
                    {"eve": {"path": "relative/eve.json"}},
                    {"eve": {"path": str(self.eve)}, "signatures": [1]}):
            with self.subTest(cfg=cfg):
                self.config.write_text(json.dumps(cfg))
                with mock.patch.object(i, "run") as commands:
                    with self.assertRaises(RuntimeError):
                        i.prepare(self.paths, self.config)
                commands.assert_not_called()
        self.assertEqual(self.old_unit.read_text(), "original unit\n")

    def test_generated_service_waits_for_queue_before_guard_can_start(self):
        unit = i.inspector_unit(self.binary, self.paths)
        self.assertIn(f"Requires={i.QUEUE_UNIT}", unit)
        self.assertIn("ExecStartPre=", unit)
        self.assertIn(" check\n", unit)
        self.assertIn("ExecStartPost=", unit)
        self.assertIn(" ready\n", unit)
        self.assertIn(f" -q {i.QUEUE}\n", unit)
        self.assertNotIn(" -D", unit)
        guard_unit = (Path(__file__).resolve().parents[2] / "systemd" /
                      "xray-connection-guard.service").read_text()
        self.assertIn("Requires=xray-ndpi.service", guard_unit)

    def test_tun_service_waits_for_ipv4_routing_and_cleans_up_after_watcher_stops(self):
        unit = i.queue_unit(self.paths, "xray-guard")
        self.assertIn("Type=simple\n", unit)
        self.assertIn(" queue-watch\n", unit)
        self.assertIn(" network-ready\n", unit)
        self.assertIn("ExecStopPost=", unit)
        self.assertIn(" queue-off\n", unit)
        self.assertIn("Restart=on-failure\n", unit)
        self.assertNotIn("ExecStop=", unit)


class DiscoveryTests(unittest.TestCase):
    def test_old_version_and_missing_nfqueue_are_rejected(self):
        for text, expected in (("Suricata version 8.0.8\nNFQueue support: yes", True),
                               ("Suricata version 8.0.8\nNFQ support: yes", True),
                               ("Suricata version 8.0.8\nNFQueue support: no", False),
                               ("Suricata version 8.0.8\nNFQ support: no", False),
                               ("Suricata version 7.0.15\nNFQ support: yes", False)):
            with self.subTest(text=text), mock.patch.object(i, "run", return_value=mock.Mock(
                    returncode=0, stdout=text)):
                self.assertEqual(i.supported("/suricata"), expected)

    def test_discovers_existing_service_binary_yaml_and_plugin(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            binary = root / "suricata"
            binary.write_text("installed")
            binary.chmod(0o755)
            plugin = root / "ndpi.so"
            plugin.touch()
            base = root / "suricata.yaml"
            base.write_text(yaml.safe_dump({"plugins": [str(plugin)]}))
            start = f"{{ path={binary} ; argv[]={binary} -c {base} -q 0 ; }}"
            info = "This is Suricata version 8.0.2 RELEASE\nNFQ support: yes\n"
            with mock.patch.object(i, "existing_start", return_value=start), \
                 mock.patch.dict(i.os.environ, {}, clear=True), \
                 mock.patch.object(i, "run", return_value=mock.Mock(returncode=0, stdout=info)):
                found, source, config = i.discover(i.Paths(root))
            self.assertEqual(found, str(binary.resolve()))
            self.assertEqual(source, base)
            self.assertEqual(config["plugins"], [str(plugin)])


class QueueTests(unittest.TestCase):
    @staticmethod
    def owned():
        return mock.Mock(returncode=0, stdout=f'table inet {i.TABLE} {{\n comment "{i.OWNER}"\n}}\n')

    def test_update_replaces_only_owned_table_in_one_checked_transaction(self):
        with mock.patch.object(i, "run", side_effect=[self.owned(), mock.Mock(), mock.Mock()]) as run:
            i.update_queue()
        checked, applied = run.call_args_list[1:]
        self.assertEqual(checked.args[0], ["nft", "-c", "-f", "-"])
        self.assertEqual(checked.kwargs["data"], applied.kwargs["data"])
        batch = applied.kwargs["data"]
        self.assertEqual(batch.count("delete table"), 1)
        self.assertIn(f"delete table inet {i.TABLE}\n", batch)
        self.assertNotIn("flush ruleset", batch)
        self.assertNotIn("xray_client_ban", batch)
        self.assertNotIn("xray_ndpi", batch)
        self.assertNotIn("bypass", batch)

    def test_unowned_table_is_never_changed_even_for_removal(self):
        foreign = mock.Mock(returncode=0, stdout=json.dumps({"nftables": [
            {"table": {"family": "inet", "name": i.TABLE}}]}))
        for remove in (False, True):
            with self.subTest(remove=remove), mock.patch.object(i, "run", return_value=foreign) as run:
                with self.assertRaisesRegex(RuntimeError, "unowned"):
                    i.update_queue(remove=remove)
                self.assertEqual(run.call_count, 1)

    def test_failed_nft_check_keeps_previous_table(self):
        with mock.patch.object(i, "run", side_effect=[self.owned(), RuntimeError("bad rules")]) as run:
            with self.assertRaisesRegex(RuntimeError, "bad rules"):
                i.update_queue()
        self.assertEqual(run.call_count, 2)

    def test_wait_ready_requires_the_configured_queue(self):
        with mock.patch.object(Path, "read_text", side_effect=["42 123 0\n", "0 456 0\n"]), \
             mock.patch.object(i.time, "sleep") as sleep:
            i.wait_ready()
        sleep.assert_called_once()

    def test_interface_rules_capture_both_directions_without_mark_or_bypass(self):
        rules = i.queue_rules("xray-guard")
        self.assertIn('oifname "xray-guard"', rules)
        self.assertIn('iifname "xray-guard"', rules)
        self.assertEqual(rules.count(f"queue num {i.QUEUE}"), 2)
        self.assertNotIn("mark", rules)
        self.assertNotIn("bypass", rules)
        self.assertIn("hook output", rules)
        self.assertIn("hook input", rules)

    def test_invalid_interface_is_rejected_before_rendering_rules(self):
        for interface in ("", "lo", "too-long-interface", 'tun"; accept', "../tun", 123):
            with self.subTest(interface=interface), self.assertRaises(ValueError):
                i.queue_rules(interface)

    def test_interface_readiness_requires_an_up_addressed_device(self):
        valid = [{"flags": ["UP"], "addr_info": [{"family": "inet", "scope": "global"}]}]
        for addresses in ([], [{"flags": []}], [{"flags": ["UP"], "addr_info": []}], valid):
            with self.subTest(addresses=addresses), mock.patch.object(i, "run", return_value=mock.Mock(
                    stdout=json.dumps(addresses))):
                if addresses == valid:
                    i.check_interface("xray-guard")
                else:
                    with self.assertRaisesRegex(RuntimeError, "must be UP"):
                        i.check_interface("xray-guard")

    def test_update_uses_persisted_interface_and_removal_does_not_require_device(self):
        with tempfile.TemporaryDirectory() as folder:
            paths = i.Paths(Path(folder))
            paths.config.mkdir(parents=True)
            paths.state.write_text(json.dumps({"interface": "xray-guard"}))
            with mock.patch.object(i, "check_interface") as check, mock.patch.object(i, "run", side_effect=[
                    self.owned(), mock.Mock(), mock.Mock()]) as commands:
                i.update_queue(paths=paths)
            check.assert_called_once_with("xray-guard")
            self.assertIn('oifname "xray-guard"', commands.call_args.kwargs["data"])
            with mock.patch.object(i, "check_interface") as check, mock.patch.object(
                    i, "run", side_effect=[self.owned(), mock.Mock()]):
                i.update_queue(remove=True, paths=paths)
            check.assert_not_called()


if __name__ == "__main__":
    unittest.main()
