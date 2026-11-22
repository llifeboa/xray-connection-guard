#!/usr/bin/env python3
"""Verify a real Suricata/nDPI engine with a synthetic offline BitTorrent capture."""
import argparse
import json
import socket
import struct
import subprocess
import tempfile
from pathlib import Path

import yaml

import inspector


def checksum(data):
    data += b"\0" * (len(data) % 2)
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def packet(reverse, sequence, acknowledgement, flags, payload=b""):
    source, destination = map(socket.inet_aton, ("198.18.0.1", "198.18.0.2"))
    sport, dport = 40000, 6881
    if reverse:
        source, destination, sport, dport = destination, source, dport, sport
    tcp = struct.pack("!HHIIBBHHH", sport, dport, sequence, acknowledgement, 5 << 4, flags, 65535, 0, 0)
    pseudo = source + destination + struct.pack("!BBH", 0, 6, len(tcp) + len(payload))
    tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp + payload)) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40 + len(payload), 1, 0, 64, 6, 0, source, destination)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    return ip + tcp + payload


def check(binary, original):
    handshake = b"\x13BitTorrent protocol" + bytes(8) + b"i" * 20 + b"-TEST00-" + b"p" * 12
    packets = [packet(False, 100, 0, 2), packet(True, 200, 101, 18),
               packet(False, 101, 201, 16), packet(False, 101, 201, 24, handshake),
               packet(True, 201, 101 + len(handshake), 16)]
    with tempfile.TemporaryDirectory(prefix="xray-bittorrent-capture-") as folder:
        root = Path(folder)
        capture = root / "bittorrent.pcap"
        with capture.open("wb") as file:
            file.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 101))
            for n, data in enumerate(packets):
                file.write(struct.pack("<IIII", 1700000000 + n, 0, len(data), len(data)))
                file.write(data)
        paths = inspector.Paths(root)
        paths.config.mkdir(parents=True)
        paths.rules.write_text(inspector.RULE)
        eve = root / "eve.json"
        config = inspector.configuration(original, paths, eve)
        paths.yaml.write_text(inspector.dump_config(config))
        result = subprocess.run([binary, "-c", str(paths.yaml), "-r", str(capture),
                                 "--runmode", "single", "--simulate-ips", "-l", folder],
                                capture_output=True, text=True, timeout=60, check=False)
        if result.returncode:
            raise RuntimeError(result.stdout + result.stderr)
        alerts = [json.loads(line) for line in eve.read_text().splitlines()]
        assert any(row.get("alert", {}).get("signature_id") == inspector.SID and
                   row["alert"].get("action") == "blocked" for row in alerts), alerts
    print("PASS: real nDPI recognizes the BitTorrent handshake and emits a blocked alert", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary")
    parser.add_argument("config")
    args = parser.parse_args()
    check(args.binary, yaml.safe_load(Path(args.config).read_text()))
