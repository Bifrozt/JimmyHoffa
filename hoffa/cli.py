"""
hoffa.cli — argument parsing and the main() dispatch.

Routes to KB operations (--kb-*) or the web recon pipeline. Recon flag
defaults are None so resolve_settings() can tell 'user set it' from
'fall back to cfg/default'.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import sys
from pathlib import Path

from .kb import KnowledgeBase
from .recon.scope import Scope, ScopeError, enforce as scope_enforce
from .recon.manifest import Manifest, capture_tool_versions
from .recon.core import Settings
from .recon import (
    check_tool,
    is_ip_literal,
    parse_web_services,
    resolve_settings,
    run_gobuster,
    stage_port_discovery,
    stage_service_id,
)


def _csv_ints(raw: str) -> set[int]:
    try:
        return {int(x) for x in raw.split(",") if x.strip()}
    except ValueError:
        raise argparse.ArgumentTypeError("expected comma-separated integers")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="jimmy",
        description="hoffa — integrated recon pipeline and knowledge base",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  KB operations:
    %(prog)s --kb-list
    %(prog)s --kb-show ssrf
    %(prog)s --kb-grep "aws credential"

  Web recon (requires target):
    %(prog)s 10.0.0.1 -w /path/to/dirlist.txt
    %(prog)s 10.0.0.1 -c hoffa.toml
        """
    )

    # KB operations (mutually exclusive with recon)
    kb_group = p.add_argument_group("knowledge base operations")
    kb_group.add_argument("--kb-list", action="store_true", help="List all KB blocks grouped by topic")
    kb_group.add_argument("--kb-show", metavar="<key>", help="Retrieve block by exact name or tag")
    kb_group.add_argument("--kb-grep", metavar="<term>", help="Full-text search in KB blocks")
    kb_group.add_argument("--kb-dir", default=None, help="Path to kb/ directory (default: ./kb)")

    # Recon operations (requires target)
    p.add_argument("target", nargs="?", help="Target IP or hostname (must be in engagement scope)")
    p.add_argument("-c", "--config", help="Path to config TOML (default: ~/.hoffa.toml if present)")

    # Defaults are None so we can distinguish 'user set it' from 'use cfg/default'.
    p.add_argument("-o", "--outdir", default=None, help="Base output directory")
    p.add_argument("-w", "--dir-wordlist", dest="dir_wordlist", default=None, help="Wordlist for gobuster dir")
    p.add_argument("-W", "--vhost-wordlist", dest="vhost_wordlist", default=None, help="Wordlist for gobuster vhost")
    p.add_argument("-x", "--extensions", default=None, help="gobuster dir extensions, e.g. php,html,txt")
    p.add_argument("-xl", "--exclude-length", type=_csv_ints, default=None,
                   help="Seed gobuster --exclude-length (comma-separated ints)")
    p.add_argument("--skip-vhost", action="store_true", help="Skip vhost scanning even if eligible")
    p.add_argument("--no-web-recon", "-NWR", dest="no_web_recon", action="store_true",
                   help="Skip the entire web enumeration stage (stage 3). For re-runs that "
                        "test newly-found creds against services without repeating gobuster.")
    p.add_argument("--rate", type=int, default=None, help="nmap --min-rate for stage 1")
    p.add_argument("--workers", type=int, default=None, help="Parallel web scans")
    p.add_argument("--gobuster-threads", dest="gobuster_threads", type=int, default=None, help="gobuster -t value")
    p.add_argument("--gobuster-timeout", dest="gobuster_timeout", type=int, default=None, help="Per-gobuster timeout (s)")
    p.add_argument("--max-retries", dest="max_retries", type=int, default=None, help="Gobuster wildcard retry bound")
    p.add_argument("--user-agent", dest="user_agent", default=None,
                   help="User-Agent for HTTP tools (default: generic browser UA; avoids self-identifying)")

    return p.parse_args()


def _run_kb(args: argparse.Namespace) -> None:
    kb_dir = Path(args.kb_dir) if args.kb_dir else None
    kb = KnowledgeBase(kb_dir=kb_dir)
    kb.load()

    if args.kb_list:
        print(kb.list_blocks())
    elif args.kb_show:
        result = kb.show_block(args.kb_show)
        if result:
            print(result)
        else:
            print(f"[!] Block or tag not found: {args.kb_show}", file=sys.stderr)
            sys.exit(1)
    elif args.kb_grep:
        result = kb.grep_blocks(args.kb_grep)
        if result:
            print(result)
        else:
            print(f"[!] No matches for: {args.kb_grep}", file=sys.stderr)
            sys.exit(1)


def _run_recon(args: argparse.Namespace) -> None:
    if not args.target:
        print("[!] target required for web recon (or use --kb-* for knowledge base operations)", file=sys.stderr)
        sys.exit(1)

    s = resolve_settings(args)

    # Scope enforcement — fail-closed. No stage runs until the target is
    # confirmed within the configured engagement allowlist.
    scope = Scope.from_entries(s.scope_allow)
    try:
        scope_enforce(scope, args.target)
    except ScopeError as e:
        print(f"[!] SCOPE REFUSED: {e}", file=sys.stderr)
        sys.exit(2)
    print(f"[*] Scope OK: {args.target} within {scope.raw}")

    for tool in ("nmap", "gobuster"):
        check_tool(tool)

    target = args.target
    outdir = Path(s.outdir) / target.replace("/", "_")
    outdir.mkdir(parents=True, exist_ok=True)

    # Manifest — canonical run record. Version capture feeds reproducibility.
    manifest = Manifest(
        target=target,
        outdir=str(outdir),
        args=_manifest_args(args, s),
        scope=list(scope.raw),
        tool_versions=capture_tool_versions(["nmap", "gobuster"]),
    )
    manifest.flush()

    # Wordlists are only required if the web stage will actually run.
    dir_wl: Path | None = None
    vhost_wl: Path | None = None
    if not s.no_web_recon:
        if not s.dir_wordlist:
            manifest.finalize("aborted")
            sys.exit("[!] No dir wordlist set (use -w or set wordlists.dir_wordlist in cfg).")
        dir_wl = Path(s.dir_wordlist)
        if not dir_wl.is_file():
            manifest.finalize("aborted")
            sys.exit(f"[!] Directory wordlist not found: {dir_wl}")
        if s.vhost_wordlist:
            vhost_wl = Path(s.vhost_wordlist)
            if not vhost_wl.is_file():
                manifest.finalize("aborted")
                sys.exit(f"[!] Vhost wordlist not found: {vhost_wl}")

    # Credential / session-mode summary.
    if s.null_session:
        print("[*] No credentials supplied — NULL/unauthenticated session.")
    else:
        print(f"[*] {len(s.credentials)} credential(s) loaded: {[c.label() for c in s.credentials]}")

    # Stage 1 — port discovery.
    print(f"[*] Stage 1: port discovery -> {outdir}")
    rec = manifest.stage_start("port_discovery")
    ports = stage_port_discovery(target, outdir, s.rate)
    if not ports:
        manifest.stage_end(rec, "failed", "no open ports",
                           outputs=[str(outdir / "open_ports.txt")])
        manifest.finalize("aborted")
        sys.exit("[!] No open ports discovered. Halting.")
    manifest.stage_end(rec, "ok", f"{len(ports)} open",
                       outputs=[str(outdir / "open_ports.txt")])

    # Stage 2 — service identification.
    print(f"[*] Stage 2: service identification on {len(ports)} ports")
    rec = manifest.stage_start("service_id")
    services_xml = stage_service_id(target, ports, outdir)
    manifest.stage_end(rec, "ok", outputs=[str(services_xml)])

    if s.no_web_recon:
        print("[*] --no-web-recon set; skipping web enumeration (stage 3).")
        manifest.stage_start("web_enum")  # record as skipped
        manifest.stage_end(manifest.stages[-1], "skipped", "--no-web-recon")
        manifest.finalize("complete")
        print(f"[+] Pipeline complete. Output: {outdir}")
        return

    # Stage 3 — service-class dispatch. Today only the web handler exists;
    # the dispatch table is the extension seam for future handlers (SMB,
    # DNS, SSH, ...). parse_web_services derives the web service list; each
    # identified class routes to its handler here.
    print("[*] Stage 3: service-class dispatch")
    rec = manifest.stage_start("web_enum")
    web_services = parse_web_services(services_xml)

    handler = SERVICE_HANDLERS.get("web")
    if not web_services:
        manifest.stage_end(rec, "skipped", "no web services identified")
        manifest.finalize("complete")
        print("[+] No web services identified. Pipeline complete.")
        return

    print(f"[+] Web services identified: {[(ws.scheme, ws.port, ws.product or ws.name) for ws in web_services]}")
    web_outputs = handler(
        target=target, services=web_services, outdir=outdir,
        s=s, dir_wl=dir_wl, vhost_wl=vhost_wl,
    )
    manifest.stage_end(rec, "ok", f"{len(web_services)} web service(s)",
                       outputs=web_outputs)

    manifest.finalize("complete")
    print(f"[+] Pipeline complete. Output: {outdir}")


def _manifest_args(args: argparse.Namespace, s: Settings) -> dict:
    """Resolved run parameters recorded in the manifest (no secrets)."""
    return {
        "target": args.target,
        "outdir": s.outdir,
        "rate": s.rate,
        "workers": s.workers,
        "gobuster_threads": s.gobuster_threads,
        "extensions": s.extensions,
        "skip_vhost": s.skip_vhost,
        "no_web_recon": s.no_web_recon,
        "user_agent": s.user_agent,
        "credentials_loaded": len(s.credentials),
        "null_session": s.null_session,
    }


def _web_handler(target: str, services, outdir: Path, s: "Settings",
                 dir_wl, vhost_wl) -> list[str]:
    """Stage-3 web enumeration handler (gobuster dir/vhost per service).

    Returns the list of output file paths produced. This is the handler the
    dispatch table routes 'web' service classes to; future handlers (SMB,
    etc.) implement the same shape.
    """
    web_outdir = outdir / "web"
    web_outdir.mkdir(exist_ok=True)

    do_vhost = (
        not s.skip_vhost
        and vhost_wl is not None
        and not is_ip_literal(target)
    )
    if s.vhost_wordlist and not do_vhost and not s.skip_vhost and is_ip_literal(target):
        print("[!] vhost wordlist provided but target is an IP literal; skipping vhost stage.")

    outputs: list[str] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=s.workers) as pool:
        futures = []
        for ws in services:
            futures.append(pool.submit(run_gobuster, "dir", target, ws, dir_wl, web_outdir, s))
            outputs.append(str(web_outdir / f"gobuster_dir_{ws.port}_{ws.scheme}.txt"))
            if do_vhost:
                futures.append(pool.submit(run_gobuster, "vhost", target, ws, vhost_wl, web_outdir, s))
                outputs.append(str(web_outdir / f"gobuster_vhost_{ws.port}_{ws.scheme}.txt"))

        for f in concurrent.futures.as_completed(futures):
            exc = f.exception()
            if exc is not None:
                print(f"[!] Worker error: {exc}", file=sys.stderr)
    return outputs


# Service-class dispatch table. The extension seam for future handlers.
# Keyed on service class; each handler shares the (target, services, outdir,
# s, dir_wl, vhost_wl) signature. SMB/DNS/SSH handlers slot in here.
SERVICE_HANDLERS = {
    "web": _web_handler,
}


def main() -> None:
    args = parse_args()

    # KB operations take precedence and short-circuit the recon pipeline.
    if args.kb_list or args.kb_show or args.kb_grep:
        _run_kb(args)
        return

    _run_recon(args)
