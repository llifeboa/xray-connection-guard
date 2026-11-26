#!/usr/bin/env python3
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import guard as g


def config():
    return {"access": {"type": "docker", "container": "remnanode", "path": "/var/log/xray/current"},
            "eve": {"path": "/var/log/xray-ndpi/eve.json"},
            "xray_timezone": "Etc/GMT-3", "window_seconds": 123,
            "min_distinct_peers": 6, "min_distinct_flows": 7,
            "firewall": {"host_network": True, "allowlist_cidrs": ["198.51.100.0/24"]}}


class NetworkTests(unittest.TestCase):
    def test_ready_notification_is_optional_outside_systemd(self):
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(g.socket, "socket") as connection:
            g.notify_ready()
        connection.assert_not_called()

    def test_ready_notification_supports_filesystem_and_abstract_sockets(self):
        for address, expected in (("/run/notify", "/run/notify"), ("@guard-notify", "\0guard-notify")):
            with self.subTest(address=address), mock.patch.dict(os.environ, NOTIFY_SOCKET=address), \
                 mock.patch.object(g.socket, "socket") as connection:
                g.notify_ready()
            notification = connection.return_value.__enter__.return_value
            notification.connect.assert_called_once_with(expected)
            notification.sendall.assert_called_once_with(b"READY=1")

    def test_inspection_defaults_to_mark_and_reports_selected_interface(self):
        cfg = config()
        g.validate(cfg)
        self.assertEqual(g.effective_settings(cfg, set(), "monitor")["inspection"], {"type": "mark"})
        cfg["inspection"] = {"interface": "xray-guard"}
        g.validate(cfg)
        self.assertEqual(g.effective_settings(cfg, set(), "monitor")["inspection"], cfg["inspection"])

    def test_invalid_inspection_selection_is_rejected(self):
        for selection in (None, [], "tun", {"interface": None}, {"interface": "lo"}, {"interface": "a/b"}):
            cfg = config()
            cfg["inspection"] = selection
            with self.subTest(selection=selection), self.assertRaises(ValueError):
                g.validate(cfg)

    def test_local_addresses_include_ipv4_ipv6_and_nat_addresses(self):
        document = [{"addr_info": [
            {"family": "inet", "local": "192.0.2.10"},
            {"family": "inet", "local": "10.0.0.2"},
            {"family": "inet6", "local": "2001:db8::1"},
            {"family": "inet6", "local": "2001:db8::2", "flags": ["tentative"]},
            {"family": "inet6", "local": "2001:db8::3", "dadfailed": True},
            {"family": "inet", "local": "127.0.0.1"},
            {"family": "inet6", "local": "fe80::1"}, {}]}]
        with mock.patch.object(g, "run", return_value=mock.Mock(stdout=json.dumps(document))):
            addresses = g.discover_server_ips()
        self.assertEqual(addresses, {"192.0.2.10", "10.0.0.2", "2001:db8::1"})

    def test_empty_or_invalid_discovery_is_not_accepted(self):
        for document in ([], {}, [None], [{"addr_info": [None]}]):
            with self.subTest(document=document), mock.patch.object(
                    g, "run", return_value=mock.Mock(stdout=json.dumps(document))):
                with self.assertRaises((ValueError, RuntimeError)):
                    g.discover_server_ips()

    def test_refresh_at_600_seconds_updates_shared_references_and_logs_change(self):
        addresses = set()
        monitor = g.AddressMonitor(addresses)
        cfg = config()
        g.validate(cfg)
        firewall = g.Firewall(cfg["firewall"], addresses)
        correlator = g.Correlator(cfg, addresses, "monitor", firewall)
        with mock.patch.object(g, "discover_server_ips", side_effect=[
                {"192.0.2.10"}, {"192.0.2.11", "2001:db8::1"}]) as probe:
            with mock.patch.object(g.time, "monotonic", return_value=100):
                monitor.refresh(initial=True)
            with mock.patch.object(g.time, "monotonic", return_value=699.99):
                self.assertFalse(monitor.refresh())
            self.assertEqual(probe.call_count, 1)
            with mock.patch.object(g.time, "monotonic", return_value=700), self.assertLogs(g.LOG, "INFO") as log:
                self.assertTrue(monitor.refresh())
        self.assertIs(firewall.server_ips, addresses)
        self.assertIs(correlator.server_ips, addresses)
        self.assertEqual(addresses, {"192.0.2.11", "2001:db8::1"})
        self.assertFalse(firewall.allowed_to_ban("192.0.2.11"))
        self.assertNotIn("192.0.2.10", firewall.server_ips)
        self.assertIn("old=['192.0.2.10']", log.output[0])
        self.assertIn("removed=['192.0.2.10']", log.output[0])
        self.assertEqual(monitor.next_check, 1300)

    def test_failed_periodic_check_keeps_last_addresses_and_logs_error(self):
        addresses = {"192.0.2.10"}
        monitor = g.AddressMonitor(addresses)
        with mock.patch.object(g, "discover_server_ips", side_effect=RuntimeError("ip command failed")), \
             mock.patch.object(g.time, "monotonic", return_value=700), \
             self.assertLogs(g.LOG, "ERROR") as log:
            self.assertFalse(monitor.refresh())
        self.assertEqual(addresses, {"192.0.2.10"})
        self.assertIn("ip command failed", log.output[0])
        self.assertEqual(monitor.next_check, 1300)

    @unittest.skipUnless(hasattr(g.socket, "AF_NETLINK"), "Linux netlink is required")
    def test_tun_address_notification_updates_shared_addresses_without_waiting_600_seconds(self):
        addresses = {"192.0.2.10"}
        monitor = g.AddressMonitor(addresses)
        changes = mock.Mock()
        changes.recv.side_effect = [BlockingIOError(), b"address added", BlockingIOError(), BlockingIOError()]
        with mock.patch.object(g.socket, "socket", return_value=changes), \
             mock.patch.object(g, "discover_server_ips", side_effect=[
                 {"192.0.2.10"}, {"192.0.2.10", "198.18.0.1"}]) as probe:
            monitor.watch()
            with mock.patch.object(g.time, "monotonic", return_value=100):
                monitor.refresh(initial=True)
            with mock.patch.object(g.time, "monotonic", return_value=101):
                self.assertTrue(monitor.refresh())
            with mock.patch.object(g.time, "monotonic", return_value=102):
                self.assertFalse(monitor.refresh())
            monitor.close()
        changes.bind.assert_called_once_with((0, 0x111))
        self.assertEqual(probe.call_count, 2)
        self.assertIn("198.18.0.1", addresses)
        changes.close.assert_called_once()

    @unittest.skipUnless(hasattr(g.socket, "AF_NETLINK"), "Linux netlink is required")
    def test_failed_notification_refresh_retries_after_one_second(self):
        monitor = g.AddressMonitor({"192.0.2.10"})
        monitor.changes = mock.Mock()
        monitor.changes.recv.side_effect = [b"address added", BlockingIOError(), BlockingIOError()]
        with mock.patch.object(g, "discover_server_ips", side_effect=[
                RuntimeError("temporary failure"), {"192.0.2.10", "198.18.0.1"}]), \
             mock.patch.object(g.time, "monotonic", side_effect=[100, 101]):
            self.assertFalse(monitor.refresh())
            self.assertEqual(monitor.next_check, 101)
            self.assertTrue(monitor.refresh())
        self.assertIn("198.18.0.1", monitor.server_ips)

    @unittest.skipUnless(hasattr(g.socket, "AF_NETLINK"), "Linux netlink is required")
    def test_failed_netlink_bind_closes_socket(self):
        monitor = g.AddressMonitor(set())
        changes = mock.Mock()
        changes.bind.side_effect = OSError("cannot subscribe")
        with mock.patch.object(g.socket, "socket", return_value=changes):
            with self.assertRaisesRegex(OSError, "cannot subscribe"):
                monitor.watch()
        changes.close.assert_called_once()

    def test_initial_discovery_failure_stops_startup(self):
        monitor = g.AddressMonitor(set())
        with mock.patch.object(g, "discover_server_ips", side_effect=RuntimeError("no addresses")):
            with self.assertRaisesRegex(RuntimeError, "no addresses"):
                monitor.refresh(initial=True)

    def test_unchanged_addresses_are_logged_without_a_change_event(self):
        addresses = {"192.0.2.10"}
        monitor = g.AddressMonitor(addresses)
        with mock.patch.object(g, "discover_server_ips", return_value=set(addresses)), \
             self.assertLogs(g.LOG, "INFO") as log:
            self.assertFalse(monitor.refresh())
        self.assertIn("unchanged", log.output[0])
        self.assertNotIn("addresses changed", log.output[0])

    def test_old_ip_and_port_options_no_longer_limit_enforcement(self):
        cfg = config()
        cfg["server_ips"] = ["192.0.2.99"]
        cfg["firewall"].update(tcp_ports=[443], udp_ports=[])
        g.validate(cfg)
        self.assertNotIn("server_ips", cfg)
        self.assertNotIn("tcp_ports", cfg["firewall"])
        self.assertNotIn("udp_ports", cfg["firewall"])

    def test_real_startup_logs_effective_parameters_and_defaults(self):
        cfg = config()
        cfg["unused_token"] = "do-not-log-this"
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "config.json"
            path.write_text(json.dumps(cfg))
            follower = mock.Mock()
            follower.step.side_effect = KeyboardInterrupt
            with mock.patch.object(sys, "argv", ["guard.py", "--config", str(path)]), \
                 mock.patch.object(g, "discover_server_ips", return_value={"192.0.2.10"}), \
                 mock.patch.object(g, "follower", return_value=follower), \
                 mock.patch.object(g, "LogSizeMonitor") as logs, \
                 self.assertLogs(g.LOG, "INFO") as log:
                g.main()
        self.assertEqual(logs.call_args.args, (cfg["access"],))
        self.assertEqual(logs.return_value.refresh.call_args_list,
                         [mock.call(initial=True), mock.call()])
        logs.return_value.close.assert_called_once()
        startup = next(line.split("Startup settings: ", 1)[1] for line in log.output if "Startup settings: " in line)
        settings = json.loads(startup)
        self.assertEqual(settings["server_ips"], ["192.0.2.10"])
        self.assertEqual(settings["network_refresh_seconds"], 600)
        self.assertEqual(settings["log_size_check"]["interval_seconds"], 600)
        self.assertEqual(settings["log_size_check"]["minimum_bytes"], 100 * 1024 ** 2)
        self.assertEqual(settings["access"], cfg["access"])
        self.assertEqual(settings["eve"]["type"], "file")
        self.assertEqual(settings["xray_timezone"], "Etc/GMT-3")
        self.assertEqual(settings["window_seconds"], 123)
        self.assertEqual(settings["min_distinct_peers"], 6)
        self.assertEqual(settings["min_distinct_flows"], 7)
        self.assertEqual(settings["max_match_delay_seconds"], 60)
        self.assertEqual(settings["firewall"]["scope"], "all-ports-and-protocols")
        self.assertEqual(settings["firewall"]["allowlist_cidrs"], ["198.51.100.0/24"])
        self.assertEqual(settings["firewall"]["ban_seconds"], 600)
        self.assertNotIn("do-not-log-this", startup)


if __name__ == "__main__":
    unittest.main()
