#!/usr/bin/env python3
import hashlib
import io
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import inspector
import install_suricata as s


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.paths = inspector.Paths(self.root)
        self.engine = ("/opt/private/bin/suricata", Path("/opt/private/suricata.yaml"), {})

    def test_compatible_engine_is_reused_without_build_or_packages(self):
        with mock.patch.object(inspector, "discover", return_value=self.engine), \
             mock.patch.object(inspector, "preflight") as probe, \
             mock.patch.object(s.Builder, "build") as build, \
             mock.patch.object(inspector, "prepare") as prepare:
            s.install(self.paths, "guard.json")
        build.assert_not_called()
        probe.assert_called_once_with(self.engine[0], self.engine[2])
        prepare.assert_called_once_with(self.paths, "guard.json", engine=self.engine)

    def test_missing_engine_or_missing_ndpi_triggers_build_before_prepare(self):
        for failure in ("missing engine", "unknown ndpi-protocol"):
            with self.subTest(failure=failure), \
                 mock.patch.object(inspector, "discover", return_value=self.engine) as discover, \
                 mock.patch.object(inspector, "preflight") as probe, \
                 mock.patch.object(s.Builder, "build", return_value=self.engine) as build, \
                 mock.patch.object(inspector, "prepare") as prepare:
                (discover if failure == "missing engine" else probe).side_effect = RuntimeError(failure)
                s.install(self.paths, "guard.json")
                build.assert_called_once()
                prepare.assert_called_once_with(self.paths, "guard.json", engine=self.engine)

    def test_failed_build_does_not_replace_configuration_or_services(self):
        with mock.patch.object(inspector, "discover", side_effect=RuntimeError("missing")), \
             mock.patch.object(s.Builder, "build", side_effect=RuntimeError("failed build")), \
             mock.patch.object(inspector, "prepare") as prepare:
            with self.assertRaisesRegex(RuntimeError, "failed build"):
                s.install(self.paths, "guard.json")
        prepare.assert_not_called()

    def test_checksum_is_checked_before_archive_can_be_used(self):
        data = b"official archive"
        destination = self.root / "source.tar.gz"
        with mock.patch.object(s.urllib.request, "urlopen", return_value=io.BytesIO(data)):
            s.download("https://example.invalid/source", destination, hashlib.sha256(data).hexdigest())
        self.assertEqual(destination.read_bytes(), data)
        with mock.patch.object(s.urllib.request, "urlopen", return_value=io.BytesIO(b"modified")):
            with self.assertRaisesRegex(RuntimeError, "SHA256 mismatch"):
                s.download("https://example.invalid/source", destination, hashlib.sha256(data).hexdigest())

    def test_archive_rejects_paths_or_links_outside_destination(self):
        for name, link in (("../../outside", None), ("source/link", "../../outside")):
            with self.subTest(name=name):
                archive = self.root / "unsafe.tar.gz"
                with tarfile.open(archive, "w:gz") as target:
                    entry = tarfile.TarInfo(name)
                    if link:
                        entry.type, entry.linkname = tarfile.SYMTYPE, link
                    target.addfile(entry)
                with self.assertRaisesRegex(RuntimeError, "Unsafe archive"):
                    s.unpack(archive, self.root / ("unpack-link" if link else "unpack-path"))
        self.assertFalse((self.root / "outside").exists())

    def test_existing_recent_rust_needs_no_rustup(self):
        env = {"PATH": "/usr/bin"}
        with mock.patch.object(s.shutil, "which", return_value="/usr/bin/rustc"), \
             mock.patch.object(s.subprocess, "run", return_value=subprocess.CompletedProcess(
                 [], 0, "rustc 1.85.0 (abc)", "")), \
             mock.patch.object(s, "download") as download:
            result = s.Builder(self.paths).rust_environment(self.root, env)
        self.assertEqual(result, env)
        download.assert_not_called()

    def test_outdated_rust_uses_temporary_toolchain_without_changing_shell(self):
        builder = s.Builder(self.paths)

        def fetch(url, destination, checksum):
            destination.touch()

        with mock.patch.object(s.shutil, "which", return_value="/usr/bin/rustc"), \
             mock.patch.object(s.platform, "machine", return_value="x86_64"), \
             mock.patch.object(s.subprocess, "run", return_value=subprocess.CompletedProcess(
                 [], 0, "rustc 1.63.0", "")), \
             mock.patch.object(s, "download", side_effect=fetch) as download, \
             mock.patch.object(builder, "command") as command:
            env = builder.rust_environment(self.root, {"PATH": "/usr/bin"})
        self.assertEqual(env["CARGO_HOME"], str(self.root / "cargo"))
        self.assertEqual(env["RUSTUP_HOME"], str(self.root / "rustup"))
        self.assertEqual(env["PATH"], str(self.root / "cargo/bin") + ":/usr/bin")
        self.assertIn("--no-modify-path", command.call_args.args[0])
        self.assertEqual(download.call_args.args[2], s.RUSTUP_HASHES["x86_64"])


if __name__ == "__main__":
    unittest.main()
