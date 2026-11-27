#!/usr/bin/env python3
"""Check external VLESS connectivity before inspection; reports omit credentials."""
import argparse
import contextlib
import http.client
import json
import logging
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.parse
from pathlib import Path

import test_linux_tun as transport


def parse_vless(path):
    uri = urllib.parse.urlsplit(path.read_text(encoding="utf-8").strip())
    query = urllib.parse.parse_qs(uri.query)
    if uri.scheme != "vless" or not uri.username or not uri.hostname or not uri.port:
        raise ValueError("Expected a complete VLESS URI")
    if query.get("security") != ["reality"]:
        raise ValueError("This test requires a REALITY outbound")
    user = {"id": urllib.parse.unquote(uri.username), "encryption": "none"}
    if query.get("flow"):
        user["flow"] = query["flow"][0]
    return {"tag": "TO_EXTERNAL", "protocol": "vless", "settings": {"vnext": [{
        "address": uri.hostname, "port": uri.port, "users": [user]}]},
        "streamSettings": {"network": query.get("type", ["raw"])[0], "security": "reality",
                           "realitySettings": {"serverName": query["sni"][0],
                                               "fingerprint": query.get("fp", ["firefox"])[0],
                                               "publicKey": query["pbk"][0],
                                               "shortId": query.get("sid", [""])[0]}}}


def http_probe(port, host, path="/", secured=True, address=None, timeout=15):
    stream, _ = transport.socks_request(port, 1, address or host, 443 if secured else 80)
    stream.settimeout(timeout)
    with stream, contextlib.ExitStack() as cleanup:
        connection = cleanup.enter_context(ssl.create_default_context().wrap_socket(
            stream, server_hostname=host)) if secured else stream
        connection.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
        response = http.client.HTTPResponse(connection)
        response.begin()
        return {"status": response.status, "body": response.read(4096).decode(errors="replace")}


def probe(args, root, outbound):
    with socket.socket() as available:
        available.bind(("127.0.0.1", 0))
        port = available.getsockname()[1]
    config = {"log": {"loglevel": "debug"}, "inbounds": [{"listen": "127.0.0.1", "port": port,
              "protocol": "socks", "settings": {"udp": True}}], "outbounds": [outbound]}
    with tempfile.TemporaryDirectory(prefix="xray-external-credentials-") as private:
        path = transport.save_config(Path(private), "client", config)
        path.chmod(0o600)
        transport.run([args.xray, "run", "-test", "-c", str(path)])
        with contextlib.ExitStack() as cleanup:
            transport.launch(cleanup, [args.xray, "run", "-c", str(path)], root, "probe-xray")
            transport.wait_for(lambda: transport.listening("127.0.0.1", port), "probe SOCKS")
            probes = []
            for host, path, secured in (("api.ipify.org", "/", True),
                                       ("www.cloudflare.com", "/cdn-cgi/trace", True),
                                       ("example.com", "/", False)):
                try:
                    response = http_probe(port, host, path, secured)
                    probes.append({"host": host, "passed": True, **response})
                except (OSError, EOFError, http.client.HTTPException) as error:
                    probes.append({"host": host, "passed": False, "error": str(error)})
                time.sleep(0.2)
            stream_settings = outbound.get("streamSettings", {})
            remote = outbound["settings"].get("vnext", [{"users": [{}]}])[0]
            result = {"status": "passed" if any(probe["passed"] for probe in probes) else "failed",
                      "protocol": outbound["protocol"],
                      "transport": stream_settings.get("network", ""),
                      "security": stream_settings.get("security", ""),
                      "flow": remote["users"][0].get("flow", ""),
                      "inspection_tested": False,
                      "probes": probes, "xray": transport.run([args.xray, "version"]).stdout}
            (root / "probe.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
            print(json.dumps(result), flush=True)
            if result["status"] != "passed":
                raise RuntimeError("Test outbound did not forward any of the HTTP/HTTPS probes")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--uri-file", type=Path)
    source.add_argument("--direct", action="store_true", help="Check the same probes through freedom")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--xray", default="/usr/local/bin/xray")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    root = args.output.resolve()
    root.mkdir(mode=0o700)
    try:
        outbound = ({"tag": "DIRECT", "protocol": "freedom", "settings": {}}
                    if args.direct else parse_vless(args.uri_file))
        probe(args, root, outbound)
    except (OSError, ValueError, RuntimeError, EOFError, AssertionError, subprocess.SubprocessError) as error:
        (root / "failure.json").write_text(json.dumps({"status": "failed", "error": str(error)}),
                                           encoding="utf-8")
        raise


if __name__ == "__main__":
    main()
