"""
hoffa.recon.stages — recon pipeline stages.

Stage 1: full TCP port discovery (nmap -p-).
Stage 2: service identification (-sC -sV) + web-service parsing from XML.
Stage 3: per-service gobuster (dir / vhost) with wildcard-length retry loop.
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

from .core import (
    WEB_PRODUCT_HINTS,
    WEB_SERVICE_NAMES,
    Settings,
    WebService,
    _LENGTH_RE,
    run_captured,
    run_streamed,
)


# ---------------------------------------------------------------------------
# Stage 1: port discovery
# ---------------------------------------------------------------------------

def stage_port_discovery(target: str, outdir: Path, rate: int) -> list[int]:
    xml_path = outdir / "discovery.xml"
    cmd = [
        "nmap", "-p-", f"--min-rate={rate}", "-T3", "-Pn",
        "-oX", str(xml_path),
        "-oN", str(outdir / "discovery.nmap"),
        target,
    ]
    if run_streamed(cmd) != 0:
        sys.exit("[!] Port discovery failed.")

    try:
        ports = _parse_open_ports(xml_path)
    except ET.ParseError as e:
        sys.exit(f"[!] Could not parse discovery XML ({e}). nmap may have been interrupted.")
    (outdir / "open_ports.txt").write_text("\n".join(str(p) for p in ports) + "\n")
    print(f"[+] Open ports ({len(ports)}): {ports}")
    return ports


def _parse_open_ports(xml_path: Path) -> list[int]:
    tree = ET.parse(xml_path)
    ports: list[int] = []
    for port in tree.iter("port"):
        state = port.find("state")
        if state is not None and state.get("state") == "open":
            ports.append(int(port.get("portid")))
    return sorted(set(ports))


# ---------------------------------------------------------------------------
# Stage 2: service identification
# ---------------------------------------------------------------------------

def stage_service_id(target: str, ports: list[int], outdir: Path) -> Path:
    xml_path = outdir / "services.xml"
    cmd = [
        "nmap", "-sC", "-sV", "-Pn",
        "-p", ",".join(str(p) for p in ports),
        "-oX", str(xml_path),
        "-oN", str(outdir / "active_services.txt"),
        target,
    ]
    if run_streamed(cmd) != 0:
        print("[!] Service ID returned non-zero; continuing with whatever was written.", file=sys.stderr)
    return xml_path


def parse_web_services(xml_path: Path) -> list[WebService]:
    try:
        tree = ET.parse(xml_path)
    except (ET.ParseError, FileNotFoundError) as e:
        print(f"[!] Could not parse services XML ({e}); no web services derived.", file=sys.stderr)
        return []

    web: list[WebService] = []
    for port in tree.iter("port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue
        portid = int(port.get("portid"))
        service = port.find("service")
        if service is None:
            continue

        name = (service.get("name") or "").lower()
        product = (service.get("product") or "").lower()
        tunnel = (service.get("tunnel") or "").lower()

        is_web = (
            name in WEB_SERVICE_NAMES
            or name.startswith("http")
            or any(hint in product for hint in WEB_PRODUCT_HINTS)
        )
        if not is_web:
            continue

        scheme = "https" if (tunnel == "ssl" or "https" in name or "ssl" in name) else "http"
        web.append(WebService(port=portid, scheme=scheme, name=name, product=product))
    return web


# ---------------------------------------------------------------------------
# Stage 3: web enumeration
# ---------------------------------------------------------------------------

def _parse_wildcard_length(output: str) -> int | None:
    """Extract the wildcard/soft-404 length gobuster reports on abort."""
    # Only inspect lines that indicate the wildcard abort, to avoid grabbing
    # a length from an ordinary result row.
    for line in output.splitlines():
        low = line.lower()
        if "wildcard" in low or "please exclude" in low or "to continue" in low:
            m = _LENGTH_RE.search(line)
            if m:
                return int(m.group(1))
    # Fallback: any Length token in the tail of the output.
    m = _LENGTH_RE.search(output)
    return int(m.group(1)) if m else None


def _build_gobuster_cmd(
    mode: str, target: str, ws: WebService, wordlist: Path,
    out: Path, threads: int, exclude: set[int], extensions: str,
    user_agent: str,
) -> list[str]:
    cmd = [
        "gobuster", mode,
        "-u", ws.url(target),
        "-w", str(wordlist),
        "-t", str(threads),
        "-o", str(out),
        "--no-error",
    ]
    if user_agent:
        cmd += ["-a", user_agent]
    if mode == "dir" and extensions:
        cmd += ["-x", extensions]
    if mode == "vhost":
        cmd.append("--append-domain")
    if ws.scheme == "https":
        cmd.append("-k")
    if exclude:
        cmd += ["--exclude-length", ",".join(str(n) for n in sorted(exclude))]
    return cmd


def run_gobuster(
    mode: str, target: str, ws: WebService, wordlist: Path,
    outdir: Path, s: Settings,
) -> None:
    """Run gobuster, auto-retrying with an accumulating exclude-length set."""
    out = outdir / f"gobuster_{mode}_{ws.port}_{ws.scheme}.txt"
    exclude = set(s.exclude_lengths)  # seed from manual -xl, per-job copy
    attempts = 0

    while attempts <= s.max_retries:
        attempts += 1
        cmd = _build_gobuster_cmd(
            mode, target, ws, wordlist, out, s.gobuster_threads,
            exclude, s.extensions, s.user_agent,
        )
        rc, output = run_captured(cmd, timeout=s.gobuster_timeout)

        if rc == 0:
            return
        if rc == 124:  # timeout — don't loop on a tarpit
            print(f"[!] gobuster {mode} :{ws.port} timed out; leaving partial output.", file=sys.stderr)
            return

        length = _parse_wildcard_length(output)
        if length is None:
            print(f"[!] gobuster {mode} :{ws.port} failed (rc={rc}), no wildcard length found; not retrying.", file=sys.stderr)
            return
        if length in exclude:
            print(f"[!] gobuster {mode} :{ws.port} re-reported length {length} already excluded; aborting retry loop.", file=sys.stderr)
            return

        exclude.add(length)
        print(f"[~] gobuster {mode} :{ws.port} wildcard length {length}; retrying with exclude set {sorted(exclude)} (attempt {attempts}/{s.max_retries}).")

    print(f"[!] gobuster {mode} :{ws.port} exhausted {s.max_retries} retries; exclude set {sorted(exclude)}.", file=sys.stderr)
