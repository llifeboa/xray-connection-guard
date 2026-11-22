#!/usr/bin/env python3
import configparser
import contextlib
import io
import json
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

import guard as g
import log_maintenance as maintenance


LOG_PATH = "/var/log/supervisor/xray.out.log"
SOURCE = {"type": "docker", "container": "custom-node", "path": LOG_PATH}
BASE = ("[supervisord]\nlogfile_maxbytes=5MB\n"
        "[program:node]\nstdout_logfile=/var/log/supervisor/node.log\n"
        "stdout_logfile_maxbytes=5MB\n"
        "[program:xray]\ncommand=xray -config %(here)s/config.json\n"
        "stdout_logfile=" + LOG_PATH + "\n"
        "stdout_logfile_maxbytes = 5MB ; retain this comment\n"
        "stderr_logfile_maxbytes=5MB\nstdout_logfile_backups=0\n"
        "[program:other]\nstdout_logfile_maxbytes=5MB\n")


class SupervisorLogTests(unittest.TestCase):
    def test_small_limit_changes_only_the_selected_log_option(self):
        expected = BASE.replace("stdout_logfile_maxbytes = 5MB ;", "stdout_logfile_maxbytes = 100MB ;")
        for value in ("5MB", "5mb", "5 MB", "5120KB", "5242880"):
            with self.subTest(value=value):
                text = BASE.replace(" = 5MB ;", " = " + value + " ;")
                updated, result = maintenance.upgrade_supervisor_log(text, LOG_PATH)
                self.assertEqual(updated, expected)
                self.assertEqual(result["status"], "changed")
                self.assertEqual(result["previous_limit_bytes"], 5 * 1024 ** 2)
                self.assertEqual(result["limit_bytes"], 100 * 1024 ** 2)

    def test_sufficient_or_unlimited_size_preserves_the_entire_file(self):
        for value in ("100MB", "100mb", "200MB", "1GB", "102400KB", "104857600", "0", "0MB"):
            with self.subTest(value=value):
                text = BASE.replace(" = 5MB ;", " = " + value + " ;")
                updated, result = maintenance.upgrade_supervisor_log(text, LOG_PATH)
                self.assertEqual(updated, text)
                self.assertEqual(result["status"], "unchanged")

    def test_absent_option_uses_supervisors_50mb_default(self):
        text = BASE.replace("stdout_logfile_maxbytes = 5MB ; retain this comment\n", "")
        updated, result = maintenance.upgrade_supervisor_log(text, LOG_PATH)
        self.assertEqual(result["previous_limit_bytes"], 50 * 1024 ** 2)
        self.assertIn("[program:xray]\nstdout_logfile_maxbytes=100MB\n", updated)
        self.assertEqual(maintenance.upgrade_supervisor_log(updated, LOG_PATH)[1]["status"], "unchanged")

    def test_missing_limit_keeps_indented_ini_options_valid(self):
        text = "[program:xray]\n  stdout_logfile=" + LOG_PATH + "\n  stderr_logfile_maxbytes=5MB\n"
        updated, result = maintenance.upgrade_supervisor_log(text, LOG_PATH)
        parser = configparser.ConfigParser()
        parser.read_string(updated)
        self.assertEqual(result["status"], "changed")
        self.assertEqual(parser["program:xray"]["stdout_logfile_maxbytes"], "100MB")
        self.assertEqual(parser["program:xray"]["stdout_logfile"], LOG_PATH)

    def test_another_log_path_is_not_modified(self):
        updated, result = maintenance.upgrade_supervisor_log(BASE, "/custom/current")
        self.assertEqual(updated, BASE)
        self.assertEqual(result["status"], "unsupported")

    def test_invalid_or_ambiguous_configuration_is_rejected(self):
        for text in (BASE.replace(" = 5MB ;", " = invalid ;"),
                     BASE.replace(" = 5MB ;", " = -1 ;"),
                     BASE + "[program:xray]\nstdout_logfile_maxbytes=5MB\n",
                     BASE + "[program:shared]\nstdout_logfile=" + LOG_PATH + "\n"):
            with self.subTest(text=text), self.assertRaises((ValueError, configparser.Error)):
                maintenance.upgrade_supervisor_log(text, LOG_PATH)

    def test_crlf_and_unterminated_last_line_are_preserved(self):
        text = BASE.replace("\n", "\r\n").rstrip("\r\n")
        updated, _ = maintenance.upgrade_supervisor_log(text, LOG_PATH)
        self.assertEqual(updated, text.replace(" = 5MB ;", " = 100MB ;"))

    def test_atomic_update_preserves_permissions_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "supervisord.conf"
            path.write_text(BASE)
            path.chmod(0o640)
            self.assertEqual(maintenance.ensure_supervisor_log(path, LOG_PATH)["status"], "changed")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o640)
            before = path.stat()
            self.assertEqual(maintenance.ensure_supervisor_log(path, LOG_PATH)["status"], "unchanged")
            self.assertEqual(path.stat().st_ino, before.st_ino)
            self.assertEqual(path.stat().st_mtime_ns, before.st_mtime_ns)
            self.assertEqual(sorted(p.name for p in Path(folder).iterdir()), [path.name])

    def test_failed_write_leaves_working_configuration_intact(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "supervisord.conf"
            path.write_text(BASE)
            with mock.patch.object(Path, "replace", side_effect=PermissionError("read-only mount")):
                with self.assertRaises(PermissionError):
                    maintenance.ensure_supervisor_log(path, LOG_PATH)
            self.assertEqual(path.read_text(), BASE)
            self.assertEqual(sorted(p.name for p in Path(folder).iterdir()), [path.name])

    def test_concurrent_edit_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "supervisord.conf"
            path.write_text(BASE)
            original_open = Path.open
            reads = 0
            newer = BASE.replace(" = 5MB ;", " = 200MB ;")

            def open_file(file, *args, **kwargs):
                nonlocal reads
                if file == path and "w" not in (args[0] if args else "r"):
                    reads += 1
                    if reads == 2:
                        with original_open(path, "w") as output:
                            output.write(newer)
                return original_open(file, *args, **kwargs)

            with mock.patch.object(Path, "open", open_file), self.assertRaisesRegex(ValueError, "changed during"):
                maintenance.ensure_supervisor_log(path, LOG_PATH)
            self.assertEqual(path.read_text(), newer)

    def test_remote_helper_runs_from_stdin_without_leaking_bad_config(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "supervisord.conf"
            script = Path(maintenance.__file__).read_text()
            command = [sys.executable, "-", str(path), LOG_PATH]
            result = subprocess.run(command, input=script, text=True, capture_output=True)
            self.assertEqual(json.loads(result.stdout)["reason"], "supervisor_config_missing")
            path.write_text(BASE)
            result = subprocess.run(command, input=script, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["status"], "changed")
            self.assertIn("stdout_logfile_maxbytes = 100MB ;", path.read_text())
            path.write_text("[program:xray]\nmalformed-private-placeholder\n")
            result = subprocess.run(command, input=script, text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(json.loads(result.stdout)["status"], "error")
            self.assertNotIn("malformed-private-placeholder", result.stdout + result.stderr)


class LogMonitorTests(unittest.TestCase):
    def setUp(self):
        self.monitor = g.LogSizeMonitor(dict(SOURCE))
        self.text = BASE
        self.commands = []

    def docker(self, command, *, stdin=None, check=True):
        self.commands.append(command)
        if command[1] == "exec":
            self.assertEqual(command[2:8], ["-i", "--user", "0", "custom-node", "python3", "-"])
            self.assertIn("def ensure_supervisor_log", stdin)
            self.text, result = maintenance.upgrade_supervisor_log(self.text, LOG_PATH)
            return subprocess.CompletedProcess(command, 0, json.dumps(result), "")
        self.assertEqual(command, ["docker", "restart", "--timeout", "10", "custom-node"])
        return subprocess.CompletedProcess(command, 0, "custom-node\n", "")

    def check_at(self, moment):
        with mock.patch.object(g.time, "monotonic", return_value=moment):
            started = self.monitor.refresh()
        if self.monitor.worker is not None:
            self.monitor.worker.join(timeout=5)
            self.assertFalse(self.monitor.worker.is_alive())
        return started

    def test_startup_and_600s_checks_restart_only_when_limit_needs_increasing(self):
        with mock.patch.object(g, "run", side_effect=self.docker), self.assertLogs(g.LOG, "INFO") as logs:
            self.assertTrue(self.check_at(100))
            self.assertFalse(self.check_at(699.99))
            self.assertTrue(self.check_at(700))
            self.assertTrue(self.check_at(1300))
            self.assertEqual(sum(command[1] == "restart" for command in self.commands), 1)
            self.text = BASE  # A later container recreation restores a small image default.
            self.assertTrue(self.check_at(1900))
        self.assertEqual(sum(command[1] == "restart" for command in self.commands), 2)
        self.assertIn("container_restarted=false", "\n".join(logs.output))

    def test_no_restart_for_existing_large_or_unlimited_limit(self):
        for value in ("100MB", "1GB", "0"):
            with self.subTest(value=value):
                self.text = BASE.replace(" = 5MB ;", " = " + value + " ;")
                self.commands.clear()
                with mock.patch.object(g, "run", side_effect=self.docker):
                    self.monitor.check()
                self.assertEqual(len(self.commands), 1)
                self.assertEqual(self.commands[0][1], "exec")

    def test_failed_restart_is_retried_without_rewriting_the_file(self):
        def docker(command, **kwargs):
            result = self.docker(command, **kwargs)
            if command[1] == "restart" and sum(c[1] == "restart" for c in self.commands) == 1:
                raise RuntimeError("Docker temporarily unavailable")
            return result

        with mock.patch.object(g, "run", side_effect=docker), self.assertLogs(g.LOG, "INFO") as logs:
            self.assertTrue(self.check_at(100))
            self.assertTrue(self.monitor.pending_restart)
            self.assertFalse(self.check_at(699))
            self.assertTrue(self.check_at(700))
            self.assertFalse(self.monitor.pending_restart)
            self.assertTrue(self.check_at(1300))
        self.assertEqual(sum(command[1] == "restart" for command in self.commands), 2)
        self.assertIn("retry_in=600s", "\n".join(logs.output))

    def test_failed_update_never_restarts_container(self):
        response = subprocess.CompletedProcess([], 1, json.dumps({"status": "error", "error": "Read-only file"}), "")
        with mock.patch.object(g, "run", return_value=response) as runner, self.assertLogs(g.LOG, "ERROR"):
            self.monitor.check()
        runner.assert_called_once()
        self.assertFalse(self.monitor.pending_restart)

    def test_unsupported_log_source_is_skipped(self):
        response = subprocess.CompletedProcess([], 0, json.dumps({"status": "unsupported", "reason": "supervisor_config_missing"}), "")
        with mock.patch.object(g, "run", return_value=response) as runner, self.assertLogs(g.LOG, "INFO"):
            self.monitor.check()
        runner.assert_called_once()
        with mock.patch.object(g, "run") as runner:
            self.assertFalse(g.LogSizeMonitor({"type": "file", "path": "/custom/access.log"}).refresh())
        runner.assert_not_called()

    def test_slow_check_does_not_block_or_start_another_worker(self):
        entered, release = threading.Event(), threading.Event()

        def slow_check():
            entered.set()
            release.wait(timeout=5)

        try:
            with mock.patch.object(self.monitor, "check", side_effect=slow_check):
                self.assertTrue(self.monitor.refresh(initial=True))
                self.assertTrue(entered.wait(timeout=2))
                self.assertFalse(self.monitor.refresh(initial=True))
                self.assertTrue(self.monitor.worker.is_alive())
        finally:
            release.set()
            self.monitor.close()

    def test_config_validation_does_not_run_log_maintenance(self):
        config = {"access": SOURCE, "eve": {"path": "/custom/eve.json"},
                  "firewall": {"host_network": True}}
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "config.json"
            path.write_text(json.dumps(config))
            with mock.patch.object(sys, "argv", ["guard.py", "--config", str(path), "--check"]), \
                 mock.patch.object(g, "LogSizeMonitor") as monitor, \
                 mock.patch.object(g, "run") as runner, \
                 contextlib.redirect_stdout(io.StringIO()):
                g.main()
        monitor.assert_not_called()
        runner.assert_not_called()


if __name__ == "__main__":
    unittest.main()
