#!/usr/bin/env python3
"""Install a compatible Suricata/nDPI engine when none is available (Debian/Ubuntu)."""
import argparse
import hashlib
import os
import platform
import re
import shlex
import shutil
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

import yaml

import inspector

# Release archives, not development branches. nDPI 5 removed APIs used by this plugin.
# https://docs.suricata.io/en/suricata-8.0.8/plugins/ndpi.html
SURICATA_VERSION = "8.0.8"
NDPI_VERSION = "4.14"
SOURCES = {
    "suricata": (
        f"https://www.openinfosecfoundation.org/download/suricata-{SURICATA_VERSION}.tar.gz",
        "bb56bbaeb4da81b4c90e61148f93b789ea924412207388bc9cba0a7ac6a24a8f"),
    "ndpi": (
        f"https://codeload.github.com/ntop/nDPI/tar.gz/refs/tags/{NDPI_VERSION}",
        "954135ee14ad6bd74a78a10db560b534b8f2083ad0615f5c1a2c376fff0301e0"),
}
RUST_VERSION = "1.85.1"
RUSTUP_VERSION = "1.28.2"
RUSTUP_HASHES = {
    "x86_64": "20a06e644b0d9bd2fbdbfd52d42540bdde820ea7df86e92e533c073da0cdd43c",
    "aarch64": "e3853c5a252fca15252d07cb23a1bdd9377a8c6f3efa01531109281ae47f841c",
}
BUILD_PACKAGES = [
    "build-essential", "autoconf", "automake", "libtool", "pkg-config",
    "libpcap-dev", "libpcre2-dev", "libyaml-dev", "zlib1g-dev", "libjansson-dev",
    "libnetfilter-queue-dev", "libnfnetlink-dev", "libcap-ng-dev", "liblz4-dev",
    "rustc", "cargo", "ca-certificates", "curl", "xz-utils",
]


def download(url, destination, checksum):
    for attempt in range(3):
        try:
            digest = hashlib.sha256()
            with urllib.request.urlopen(url, timeout=60) as source, destination.open("wb") as target:
                while data := source.read(1024 * 1024):
                    digest.update(data)
                    target.write(data)
            if digest.hexdigest() != checksum:
                raise RuntimeError(f"SHA256 mismatch: {url}")
            return
        except (OSError, urllib.error.URLError):
            if attempt == 2:
                raise
            time.sleep(2)


def unpack(archive, destination):
    destination.mkdir()
    root = destination.resolve()
    with tarfile.open(archive, "r:gz") as source:
        for member in source.getmembers():
            target = (root / member.name).resolve()
            if not target.is_relative_to(root) or not (
                    member.isfile() or member.isdir() or member.issym() or member.islnk()):
                raise RuntimeError(f"Unsafe archive entry: {member.name}")
            if member.issym() or member.islnk():
                link = (target.parent if member.issym() else root) / member.linkname
                if not link.resolve().is_relative_to(root):
                    raise RuntimeError(f"Unsafe archive link: {member.name}")
        # Sources are pinned by SHA256 and unpacked into a new private directory.
        source.extractall(destination)
    entries = list(destination.iterdir())
    if len(entries) != 1 or not entries[0].is_dir():
        raise RuntimeError(f"Unexpected source archive layout: {archive}")
    return entries[0]


class Builder:
    def __init__(self, paths):
        self.home = paths.helper.parent
        self.log = paths.log.parent / "xray-connection-guard/install-suricata.log"

    def command(self, args, *, cwd=None, env=None):
        self.log.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with self.log.open("a", encoding="utf-8") as log:
            self.log.chmod(0o600)
            log.write(f"\n$ {shlex.join(map(str, args))}\n")
            log.flush()
            result = subprocess.run(args, cwd=cwd, env=env, stdout=log,
                                    stderr=subprocess.STDOUT, timeout=3600, check=False)
        if result.returncode:
            tail = "\n".join(self.log.read_text(encoding="utf-8", errors="replace").splitlines()[-25:])
            raise RuntimeError(f"Build failed; log: {self.log}\n{tail}")

    def rust_environment(self, folder, env):
        rustc = shutil.which("rustc")
        if rustc:
            result = subprocess.run([rustc, "--version"], capture_output=True, text=True, check=False)
            version = re.search(r"rustc (\d+)\.(\d+)\.(\d+)", result.stdout)
            if result.returncode == 0 and version and tuple(map(int, version.groups())) >= (1, 75, 0):
                return env
        architecture = platform.machine()
        if architecture not in RUSTUP_HASHES:
            raise RuntimeError(f"Install Rust 1.75+ for architecture {architecture} and rerun install")
        target = f"{architecture}-unknown-linux-gnu"
        installer = folder / "rustup-init"
        print(f"[inspection] Installing a temporary Rust {RUST_VERSION} build toolchain", flush=True)
        download(f"https://static.rust-lang.org/rustup/archive/{RUSTUP_VERSION}/{target}/rustup-init",
                 installer, RUSTUP_HASHES[architecture])
        installer.chmod(0o700)
        env = dict(env, RUSTUP_HOME=str(folder / "rustup"), CARGO_HOME=str(folder / "cargo"))
        self.command([str(installer), "-y", "--profile", "minimal", "--no-modify-path",
                      "--default-toolchain", RUST_VERSION], env=env)
        return dict(env, PATH=str(folder / "cargo/bin") + ":" + env["PATH"])

    def build(self):
        if not shutil.which("apt-get"):
            raise RuntimeError("Automatic Suricata/nDPI installation requires Debian/Ubuntu (apt-get)")
        print(f"[inspection] Installing Suricata {SURICATA_VERSION} + nDPI {NDPI_VERSION}; "
              f"first build can take several minutes. Log: {self.log}", flush=True)
        env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
        self.command(["apt-get", "update"], env=env)
        self.command(["apt-get", "install", "-y", "--no-install-recommends", *BUILD_PACKAGES], env=env)
        engines = self.home / "engines"
        engines.mkdir(parents=True, exist_ok=True, mode=0o755)
        # A new prefix leaves any running engine intact until the new build passes preflight.
        prefix = Path(tempfile.mkdtemp(
            prefix=f"suricata-{SURICATA_VERSION}-ndpi-{NDPI_VERSION}-", dir=engines))
        prefix.chmod(0o755)
        try:
            with tempfile.TemporaryDirectory(prefix="xray-suricata-", dir="/var/tmp") as temporary:
                folder = Path(temporary)
                sources = {}
                for name, (url, checksum) in SOURCES.items():
                    print(f"[inspection] Downloading and verifying {name}", flush=True)
                    archive = folder / f"{name}.tar.gz"
                    download(url, archive, checksum)
                    sources[name] = unpack(archive, folder / name)
                jobs = min(2, os.cpu_count() or 1)
                env = dict(env, CARGO_BUILD_JOBS=str(jobs))
                env = self.rust_environment(folder, env)
                print("[inspection] Building nDPI", flush=True)
                self.command(["./autogen.sh", "--with-only-libndpi"], cwd=sources["ndpi"], env=env)
                self.command(["make", f"-j{jobs}"], cwd=sources["ndpi"], env=env)
                print("[inspection] Building Suricata with NFQUEUE and the nDPI plugin", flush=True)
                self.command(["./configure", f"--prefix={prefix}", f"--sysconfdir={prefix}/etc",
                              f"--localstatedir={prefix}/var", "--enable-nfqueue", "--enable-ndpi",
                              f"--with-ndpi={sources['ndpi']}", "--disable-suricata-update",
                              "--disable-python"], cwd=sources["suricata"], env=env)
                self.command(["make", f"-j{jobs}"], cwd=sources["suricata"], env=env)
                self.command(["make", "install"], cwd=sources["suricata"], env=env)
                self.command(["make", "install-conf"], cwd=sources["suricata"], env=env)
            binary = str(prefix / "bin/suricata")
            base = prefix / "etc/suricata/suricata.yaml"
            config = yaml.safe_load(base.read_text(encoding="utf-8"))
            plugin = prefix / "lib/suricata/ndpi.so"
            if not inspector.supported(binary):
                raise RuntimeError("Built Suricata does not report version 8+ with NFQUEUE support")
            if not plugin.is_file():
                raise RuntimeError(f"Built nDPI plugin not found: {plugin}")
            config["plugins"] = [str(plugin)]
            inspector.preflight(binary, config)
            # Persist the plugin path in the engine's base config for the next install/enable.
            base.write_text(inspector.dump_config(config), encoding="utf-8")
            return binary, base, config
        except BaseException:
            # This unique prefix was created above; it cannot be an older running engine.
            if prefix.parent.resolve() == engines.resolve() and not prefix.is_symlink():
                shutil.rmtree(prefix)
            raise


def install(paths, config):
    try:
        engine = inspector.discover(paths)
        inspector.preflight(engine[0], engine[2])
        print(f"[inspection] Reusing verified Suricata/nDPI: {engine[0]}", flush=True)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, yaml.YAMLError) as exc:
        print(f"[inspection] No compatible installed engine: {exc}", flush=True)
        engine = Builder(paths).build()
    inspector.prepare(paths, config, engine=engine)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="/etc/xray-connection-guard/config.json")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("Run as root")
    # Linux only: serialize builds/installations using this helper.
    import fcntl
    paths = inspector.Paths()
    with (paths.helper.parent / "install-suricata.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            install(paths, args.config)
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, yaml.YAMLError) as exc:
            raise SystemExit(f"[inspection] {exc}") from exc


if __name__ == "__main__":
    main()
