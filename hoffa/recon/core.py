"""
hoffa.recon.core — shared recon data classes, settings, helpers, config.

Holds everything stages.py and the CLI need that isn't a pipeline stage:
WebService / Credential / Settings, tool/process helpers, target checks,
and the defaults < cfg < CLI settings resolution.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import shutil
import stat
import subprocess
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path


# Default config location and the permission mode enforced on it.
DEFAULT_CONFIG_PATH = Path.home() / ".hoffa.toml"
CONFIG_REQUIRED_MODE = 0o600


# Service-name and product hints used to classify a port as a web service.
WEB_SERVICE_NAMES = {
    "http", "https", "http-proxy", "http-alt", "https-alt",
    "www", "www-http", "http-rpc-epmap",
}
WEB_PRODUCT_HINTS = (
    "nginx", "apache", "iis", "tomcat", "jetty", "node",
    "lighttpd", "caddy", "httpd", "express", "gunicorn", "kestrel",
)

# Built-in defaults. Overridden by cfg, then by CLI.
DEFAULTS = {
    "outdir": "recon_output",
    "dir_wordlist": None,
    "vhost_wordlist": None,
    "rate": 1000,
    "workers": 4,
    "gobuster_threads": 30,
    "extensions": "",          # e.g. "php,html,txt"
    "skip_vhost": False,
    "gobuster_timeout": 1800,  # seconds, per gobuster invocation
    "max_retries": 3,          # gobuster wildcard-length retry bound
    # Generic UA applied to HTTP tools so they don't self-identify by default.
    # Override via [general] user_agent in cfg or --user-agent.
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
}

# Matches the length gobuster reports in its wildcard/soft-404 abort message.
# Tolerant of dir-mode and vhost-mode phrasings; both surface "Length: N".
_LENGTH_RE = re.compile(r"[Ll]ength:?\s*(\d+)")


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class WebService:
    port: int
    scheme: str  # "http" or "https"
    name: str
    product: str

    def url(self, host: str) -> str:
        return f"{self.scheme}://{host}:{self.port}"


@dataclass(frozen=True)
class Credential:
    """A single known-good credential.

    Exactly one of password / nthash is set (secret). domain is optional;
    empty string means local account (tools receive '.' or the target as
    workgroup depending on the handler — resolved at use site, not here).
    """
    username: str
    password: str | None
    nthash: str | None
    domain: str

    @property
    def is_hash(self) -> bool:
        return self.nthash is not None

    @property
    def secret(self) -> str:
        return self.nthash if self.nthash is not None else (self.password or "")

    def label(self) -> str:
        dom = f"{self.domain}\\" if self.domain else ""
        kind = "hash" if self.is_hash else "pass"
        return f"{dom}{self.username} ({kind})"


# Sentinel for the unauthenticated / null-session case (no creds supplied).
NULL_SESSION: list[Credential] = []


@dataclass
class Settings:
    outdir: str
    dir_wordlist: str | None
    vhost_wordlist: str | None
    rate: int
    workers: int
    gobuster_threads: int
    extensions: str
    skip_vhost: bool
    gobuster_timeout: int
    max_retries: int
    user_agent: str = ""
    no_web_recon: bool = False
    credentials: list[Credential] = field(default_factory=list)
    exclude_lengths: set[int] = field(default_factory=set)

    @property
    def null_session(self) -> bool:
        return len(self.credentials) == 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def check_tool(name: str) -> None:
    if shutil.which(name) is None:
        sys.exit(f"[!] Required tool not found in PATH: {name}")


def run_streamed(cmd: list[str], timeout: int | None = None) -> int:
    """Run a command, stream output live, return exit code. Used for nmap."""
    print(f"[*] {' '.join(cmd)}")
    try:
        proc = subprocess.run(cmd, check=False, timeout=timeout)
        return proc.returncode
    except FileNotFoundError as e:
        print(f"[!] {e}", file=sys.stderr)
        return 127
    except subprocess.TimeoutExpired:
        print(f"[!] Timed out after {timeout}s: {' '.join(cmd)}", file=sys.stderr)
        return 124


def run_captured(cmd: list[str], timeout: int | None = None) -> tuple[int, str]:
    """Run a command, capture combined output, also echo it. Used for gobuster."""
    print(f"[*] {' '.join(cmd)}")
    try:
        proc = subprocess.run(
            cmd, check=False, timeout=timeout,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        if proc.stdout:
            print(proc.stdout, end="")
        return proc.returncode, proc.stdout or ""
    except FileNotFoundError as e:
        print(f"[!] {e}", file=sys.stderr)
        return 127, ""
    except subprocess.TimeoutExpired as e:
        captured = e.stdout or ""
        if isinstance(captured, bytes):
            captured = captured.decode(errors="replace")
        if captured:
            print(captured, end="")
        print(f"[!] Timed out after {timeout}s: {' '.join(cmd)}", file=sys.stderr)
        return 124, captured


def is_ip_literal(target: str) -> bool:
    """True if target is an IPv4 or IPv6 literal (not a hostname)."""
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Config resolution
# ---------------------------------------------------------------------------

def resolve_config_path(cli_config: str | None) -> Path | None:
    """Resolve which config file to use.

    Explicit -c always wins. Otherwise fall back to ~/.hoffa.toml if it
    exists. Returns None when no config is available (built-in defaults +
    CLI only).
    """
    if cli_config:
        return Path(cli_config)
    if DEFAULT_CONFIG_PATH.is_file():
        return DEFAULT_CONFIG_PATH
    return None


def enforce_config_perms(path: Path) -> None:
    """Ensure the config file is mode 0600; tighten it if it is not.

    The config may contain plaintext credentials, so group/other access is
    not acceptable. If the current mode is anything other than 0600 the
    permission bits are reset to 0600 in place. A symlinked config is
    rejected outright to avoid following a link to a file we then chmod.
    """
    try:
        st = path.lstat()
    except OSError as e:
        sys.exit(f"[!] Config file not accessible: {e}")

    if stat.S_ISLNK(st.st_mode):
        sys.exit(f"[!] Config file is a symlink; refusing to follow: {path}")

    current = stat.S_IMODE(st.st_mode)
    if current != CONFIG_REQUIRED_MODE:
        try:
            os.chmod(path, CONFIG_REQUIRED_MODE)
        except OSError as e:
            sys.exit(f"[!] Config {path} has mode {current:04o}; failed to enforce 0600: {e}")
        print(f"[*] Config {path} mode was {current:04o}; reset to 0600.", file=sys.stderr)


def load_cfg(path: Path) -> tuple[dict, list[Credential]]:
    """Parse the TOML config into (flat settings dict, credential list).

    Returns recognized scalar settings flattened to top-level keys, plus a
    parsed/validated list of Credential objects. Unknown keys are ignored.

    The file's permissions are enforced to 0600 before parsing (it may hold
    plaintext credentials).
    """
    enforce_config_perms(path)
    try:
        with path.open("rb") as fh:
            data = tomllib.load(fh)
    except tomllib.TOMLDecodeError as e:
        sys.exit(f"[!] Config TOML parse error: {e}")
    except OSError as e:
        sys.exit(f"[!] Config file not readable: {e}")

    cfg: dict = {}

    def take(section: str, key: str, dest: str | None = None):
        sec = data.get(section, {})
        if isinstance(sec, dict) and key in sec:
            cfg[dest or key] = sec[key]

    take("general", "outdir")
    take("general", "user_agent")
    take("wordlists", "dir_wordlist")
    take("wordlists", "vhost_wordlist")
    take("performance", "rate")
    take("performance", "workers")
    take("performance", "gobuster_threads")
    take("performance", "gobuster_timeout")
    take("gobuster", "extensions")
    take("gobuster", "max_retries")
    take("gobuster", "skip_vhost")

    creds = _parse_credentials(data.get("cred", []))
    return cfg, creds


def _parse_credentials(raw) -> list[Credential]:
    """Validate the [[cred]] array-of-tables into Credential objects.

    Each entry requires username and exactly one of password / nthash.
    domain is optional (defaults to ''). Malformed entries are fatal — a
    silently dropped credential is worse than a hard error on a CTF.
    """
    if not isinstance(raw, list):
        sys.exit("[!] cfg 'cred' must be an array of tables ([[cred]]).")

    creds: list[Credential] = []
    for i, entry in enumerate(raw, 1):
        if not isinstance(entry, dict):
            sys.exit(f"[!] cred #{i}: not a table.")
        user = entry.get("username")
        if not user:
            sys.exit(f"[!] cred #{i}: missing 'username'.")
        pw = entry.get("password")
        nt = entry.get("nthash")
        if (pw is None) == (nt is None):
            sys.exit(f"[!] cred #{i} ({user}): set exactly one of 'password' or 'nthash'.")
        domain = entry.get("domain", "") or ""
        creds.append(Credential(
            username=str(user),
            password=str(pw) if pw is not None else None,
            nthash=str(nt) if nt is not None else None,
            domain=str(domain),
        ))
    return creds


def resolve_settings(args: argparse.Namespace) -> Settings:
    """Merge defaults < cfg < CLI. CLI values left as None do not override."""
    merged = dict(DEFAULTS)
    creds: list[Credential] = []

    cfg_path = resolve_config_path(args.config)
    if cfg_path is not None:
        if not cfg_path.is_file():
            sys.exit(f"[!] Config file not found: {cfg_path}")
        cfg_scalars, creds = load_cfg(cfg_path)
        merged.update(cfg_scalars)

    # CLI overrides: only keys explicitly provided (not None / not False-by-absence).
    cli_keys = (
        "outdir", "dir_wordlist", "vhost_wordlist", "rate",
        "workers", "gobuster_threads", "extensions", "gobuster_timeout",
        "max_retries", "user_agent",
    )
    for key in cli_keys:
        val = getattr(args, key, None)
        if val is not None:
            merged[key] = val

    # store_true flags: only override when set.
    if args.skip_vhost:
        merged["skip_vhost"] = True

    s = Settings(
        outdir=merged["outdir"],
        dir_wordlist=merged["dir_wordlist"],
        vhost_wordlist=merged["vhost_wordlist"],
        rate=int(merged["rate"]),
        workers=int(merged["workers"]),
        gobuster_threads=int(merged["gobuster_threads"]),
        extensions=merged["extensions"] or "",
        skip_vhost=bool(merged["skip_vhost"]),
        gobuster_timeout=int(merged["gobuster_timeout"]),
        max_retries=int(merged["max_retries"]),
        user_agent=merged["user_agent"] or "",
        no_web_recon=bool(args.no_web_recon),
        credentials=creds,
    )

    # Manual -xl override seeds the exclude set.
    if args.exclude_length:
        s.exclude_lengths.update(args.exclude_length)
    return s
