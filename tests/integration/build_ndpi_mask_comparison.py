#!/usr/bin/env python3
"""Build two real nDPI plugins and compare them in a private mount namespace.

Run with root and ``unshare --mount``. Package installs use private overlays;
no host services or firewall rules are changed. Results and build logs remain
under --output. Production installation code is used without modifying it.
"""
import argparse
import json
import os
import shutil
import subprocess
from pathlib import Path

import yaml

import inspector
import install_suricata


def private_mounts(work, reuse=False):
    if os.readlink('/proc/self/ns/mnt') == os.readlink('/proc/1/ns/mnt'):
        raise SystemExit('Run as root with unshare --mount')
    subprocess.run(['mount', '--make-rprivate', '/'], check=True)
    destinations = {str(Path(p).resolve()) for p in (
        '/usr', '/bin', '/sbin', '/lib', '/lib64', '/etc',
        '/var/lib', '/var/cache', '/var/tmp')}
    for number, destination in enumerate(sorted(destinations)):
        upper, scratch = work / f'upper{number}', work / f'work{number}'
        upper.mkdir(exist_ok=reuse)
        scratch.mkdir(exist_ok=reuse)
        subprocess.run(['mount', '-t', 'overlay', 'overlay', '-o',
                        f'lowerdir={destination},upperdir={upper},workdir={scratch}',
                        destination], check=True)
    for destination in ('/opt', '/var/log', '/root', '/run'):
        subprocess.run(['mount', '-t', 'tmpfs', 'tmpfs', destination], check=True)
    policy = Path('/usr/sbin/policy-rc.d')
    policy.write_text('#!/bin/sh\nexit 101\n')
    policy.chmod(0o755)


class ComparisonBuilder(install_suricata.Builder):
    def __init__(self, work):
        paths = inspector.Paths(work / 'installation')
        super().__init__(paths)
        self.work = work
        self.log = work / 'build.log'
        self.sources = {}
        self.variants = {}

    def command(self, args, *, cwd=None, env=None):
        # Retain only the source directories needed while Builder is active.
        if args[0] == './autogen.sh':
            self.sources['ndpi'] = Path(cwd)
        if args[0] == './configure':
            self.sources['suricata'] = Path(cwd)
            self.prefix = Path(next(arg.split('=', 1)[1] for arg in args
                                    if arg.startswith('--prefix=')))
        super().command(args, cwd=cwd, env=env)
        if args != ['make', 'install-conf']:
            return
        plugin = self.prefix / 'lib/suricata/ndpi.so'
        stock = plugin.with_name('ndpi-all.so')
        shutil.copy2(plugin, stock)
        source = self.sources['suricata'] / 'plugins/ndpi/ndpi.c'
        original = source.read_text()
        needle = 'NDPI_BITMASK_SET_ALL(protos);'
        if original.count(needle) != 1:
            raise RuntimeError('Unexpected nDPI plugin source: refusing an ambiguous patch')
        patched = original.replace(needle, 'NDPI_BITMASK_RESET(protos);\n'
                                   '    NDPI_ADD_PROTOCOL_TO_BITMASK(protos, '
                                   'NDPI_PROTOCOL_BITTORRENT);')
        source.write_text(patched)
        (self.work / 'ndpi-original.c').write_text(original)
        (self.work / 'ndpi-bittorrent.c').write_text(patched)
        print('[comparison] Building BitTorrent-only variant', flush=True)
        try:
            super().command(['make', '-j2'], cwd=source.parent, env=env)
            super().command(['make', 'install'], cwd=source.parent, env=env)
            torrent = plugin.with_name('ndpi-bittorrent.so')
            shutil.copy2(plugin, torrent)
        finally:
            source.write_text(original)
            shutil.copy2(stock, plugin)
        self.variants = {'all': str(stock), 'bittorrent': str(torrent)}
        # Upstream captures stay in the disposable lab, never in the repository.
        captures = self.sources['ndpi'] / 'tests/pcap'
        candidates = sorted(p.name for p in captures.glob('*')
                            if p.is_file() and p.suffix.lower() in ('.pcap', '.pcapng', '.cap'))
        (self.work / 'upstream-capture-names.json').write_text(json.dumps(candidates, indent=2))
        chosen = [name for name in candidates if 'bittorrent' in name.lower()]
        for pattern in ('tls', 'http', 'dns', 'quic', 'ntp', 'utp', 'torrent'):
            matches = [name for name in candidates if name.lower().startswith(pattern)]
            chosen.extend(matches[:3])
        target = self.work / 'upstream-pcaps'
        target.mkdir()
        for name in dict.fromkeys(chosen):
            if (captures / name).stat().st_size <= 25 * 1024 * 1024:
                shutil.copy2(captures / name, target / name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path,
                        help='New absolute lab directory under /tmp on Linux')
    parser.add_argument('--reuse-startup-check', action='store_true',
                        help='Reuse a completed lab to measure startup overhead only')
    args = parser.parse_args()
    work = args.output.resolve()
    if not work.is_relative_to(Path('/tmp')) or work == Path('/tmp'):
        parser.error('--output must be a new directory below /tmp')
    if args.reuse_startup_check:
        manifest = json.loads((work / 'manifest.json').read_text())
    else:
        work.mkdir(mode=0o700)
    print(f'[comparison] Lab directory: {work}', flush=True)
    private_mounts(work, reuse=args.reuse_startup_check)
    if args.reuse_startup_check:
        from ndpi_mask_benchmark import startup_overhead
        result = startup_overhead(work, manifest['binary'],
                                  yaml.safe_load(Path(manifest['base']).read_text()),
                                  manifest['plugins'])
        results = json.loads((work / 'results.json').read_text())
        results['startup_overhead'] = result
        (work / 'results.json').write_text(json.dumps(results, indent=2))
        return
    # Never print the inherited environment, which may contain credentials.
    for key in list(os.environ):
        if key.lower().endswith('_proxy'):
            os.environ.pop(key)
    builder = ComparisonBuilder(work)
    binary, base, config = builder.build()
    for plugin in builder.variants.values():
        probe = dict(config, plugins=[plugin])
        inspector.preflight(binary, probe)
    manifest = {'binary': binary, 'base': str(base), 'plugins': builder.variants,
                'suricata_version': install_suricata.SURICATA_VERSION,
                'ndpi_version': install_suricata.NDPI_VERSION}
    (work / 'manifest.json').write_text(json.dumps(manifest, indent=2))
    print('[comparison] Both real plugins built and validated', flush=True)
    from ndpi_mask_benchmark import compare
    compare(work, binary, yaml.safe_load(base.read_text()), builder.variants)


if __name__ == '__main__':
    main()
