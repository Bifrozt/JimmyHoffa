# hoffa / jimmy

A personal, practitioner-scoped web-application reconnaissance orchestrator with an
integrated technique knowledge base. `hoffa` is the importable package; `jimmy` is the
thin `~/bin` wrapper invoked from the command line. The tool is scoped as an individual
instrument for authorized engagements, not an enterprise product.

## What it does

Two subsystems behind one entry point.

**Recon pipeline** — a staged web-recon flow driven by a service-class dispatch model:

1. **Port discovery** — full TCP sweep (`nmap -p-`), open ports parsed from XML.
2. **Service identification** — `nmap -sC -sV -Pn` on the open ports; web services parsed
   from the result.
3. **Service-class dispatch** — each identified service class routes to a handler. Today
   the `web` handler runs `gobuster` (dir + vhost) per service, in parallel, with a
   wildcard/soft-404 auto-retry loop that accumulates `--exclude-length` values. The
   dispatch table (`SERVICE_HANDLERS`) is the extension seam for future handlers (SMB,
   DNS, SSH).

Every run is bounded by fail-closed **scope enforcement** and produces a structured
**run manifest** (see below).

**Knowledge base** — flat-file `.kb` technique blocks (`kb/*.kb`) parsed into an
in-memory index, retrievable by name, tag, or full-text search. Independent of the
recon pipeline; usable standalone.

## Install

`install.sh` deploys to co-located locations under `~/bin`:

```
~/bin/hoffa/     # package
~/bin/kb/        # knowledge base (sibling of the package)
~/bin/jimmy      # wrapper, chmod 0700 - the PATH command
~/.hoffa.toml    # config, chmod 0600 - not overwritten if present
```

```
git clone https://github.com/Bifrozt/JimmyHoffa.git
cd JimmyHoffa
bash install.sh
```

Override targets via `HOFFA_BIN_DIR` and `HOFFA_CONFIG_PATH`. Ensure `~/bin` is on
`PATH`. Requires Python 3.11+ (`tomllib`), and `nmap` + `gobuster` on `PATH` for the
recon pipeline. The KB subsystem has no external dependencies.

## Configuration

Config resolves as **built-in defaults < config file < CLI flags**. The config file
defaults to `~/.hoffa.toml`; its permissions are checked on every run and reset to
`0600` if they differ (it may hold plaintext credentials). A symlinked config is
rejected.

Sections:

```toml
# Engagement allowlist. FAIL-CLOSED: with no allow entries, hoffa refuses every
# target. A bare domain permits its subdomains. Hostname targets are NOT resolved
# against CIDR entries (DNS must not control scope).
[scope]
allow = ["10.10.10.0/24", "192.168.56.0/24", "target.example.com"]

[general]
outdir = "."   # <target>/ is created under this base; "." = current working dir

[wordlists]
dir_wordlist   = "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt"
vhost_wordlist = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt"

[performance]
rate             = 1000   # nmap --min-rate (stage 1)
workers          = 4      # parallel web scans
gobuster_threads = 30
gobuster_timeout = 1800   # seconds, per gobuster invocation

[gobuster]
extensions  = "php,html,txt"
max_retries = 3           # wildcard-length retry bound
skip_vhost  = false
```

Credentials (optional) are declared as an array of tables. Exactly one of `password`
or `nthash` per entry; `domain` optional. Parsed and validated today; consumed by the
forthcoming SMB handler, not the web pipeline.

```toml
[[cred]]
username = "svc_web"
password = "REDACTED"
domain   = "CORP"

[[cred]]
username = "admin"
nthash   = "aad3b435b51404ee..."
```

## Usage

Invoke with `jimmy`. A target is required for recon; KB operations run without one.

**Recon**

```
jimmy 10.10.10.5                       # full pipeline (scope must permit target)
jimmy target.example.com -w /list.txt  # override dir wordlist
jimmy 10.10.10.5 --no-web-recon        # stages 1-2 only, skip gobuster
jimmy 10.10.10.5 -x php,html -xl 1234  # extensions + seed exclude-length
```

Output lands in `<outdir>/<target>/` (default `./<target>/`), containing per-stage nmap
output, a `web/` subdirectory of gobuster results, and `manifest.json`.

Key flags (full list via `jimmy --help`): `-c/--config`, `-o/--outdir`,
`-w/--dir-wordlist`, `-W/--vhost-wordlist`, `-x/--extensions`, `-xl/--exclude-length`,
`--skip-vhost`, `--no-web-recon`, `--rate`, `--workers`, `--gobuster-threads`,
`--gobuster-timeout`, `--max-retries`, `--user-agent`. HTTP tools default to a generic
browser User-Agent so they do not self-identify.

**Knowledge base**

```
jimmy --kb-list             # all blocks, grouped by topic
jimmy --kb-show ssrf        # blocks by exact name or tag
jimmy --kb-grep "imds"      # full-text search
jimmy --kb-dir /path/to/kb  # override KB directory
```

## Scope enforcement

No stage executes until the target is confirmed within `[scope] allow`. An out-of-scope
target is refused before any tooling runs (exit code 2). An empty or absent allowlist
refuses everything - the tool is structurally unable to act out of scope. Combined with
the `outdir = "."` default, the working directory becomes the engagement context: one
directory per engagement holds both the scope definition (via a local config) and the
output.

## Run manifest

Each run writes `<target>/manifest.json`: target, UTC timestamps, resolved run
parameters (no credential secrets), captured tool versions, the scope in force, and
per-stage status, timing, and output paths, plus a final `hoffa_status`
(`complete` / `aborted`). It is flushed after each stage, so an interrupted run leaves a
valid partial record. The manifest is the canonical run record; reporting and
cross-run diffing consume it.

## Status

Implemented: staged recon pipeline, scope enforcement, run manifest with tool-version
capture, service-class dispatch seam, KB subsystem. The SMB handler, credential
consumption, resume/idempotency, and external-tool integrations (httpx, nuclei,
feroxbuster) are tracked in `ROADMAP.md` and not yet implemented.

## License

See `LICENSE`.
