# hoffa — development roadmap

Agreed improvements to implement, ordered by priority. Derived from the
post-refactor functional review.

## High priority

1. **Scope enforcement** — DONE (hoffa/recon/scope.py)
   - CIDR/host allowlist from cfg [scope] allow; fail-closed (empty = refuse
     all); refuse-on-miss before any stage; exit 2 on refusal.
   - Hostname targets not resolved against CIDRs (DNS must not control scope).
   - Bare-domain entry permits subdomains.

2. **Structured run manifest** — DONE (hoffa/recon/manifest.py)
   - manifest.json per run: target, timestamps, resolved args (no secrets),
     tool versions, per-stage status/timing, output paths, scope, final
     hoffa_status (complete/aborted). Flushed after each stage so an
     interrupted run leaves a valid partial record.
   - Folds in item 5 (version capture) — capture_tool_versions().

3. **SMB enumeration handler (PRIO 1 of stage expansion)** — SEAM DONE, HANDLER PENDING
   - Service-class dispatch table implemented (SERVICE_HANDLERS in cli.py);
     web path ported onto it as _web_handler with a stable handler signature.
     SMB handler slots in as a new table entry — needs a live SMB service to
     verify enumeration output, so deferred to hands-on session.
   - Remaining: share listing, null/guest check, OS/signing info, Credential
     subsystem consumption, per-handler capability check.

## Medium priority

4. **Idempotency / resume**
   - Gate stages on existing output (skip discovery if `discovery.xml`
     present and `--resume` set).
   - Matches the resume model in `webrecon/`.

5. **Per-tool version capture** — DONE (folded into manifest, item 2)
   - `nmap --version` / `gobuster version` into the manifest.
   - Findings reproducibility for regulated deliverables.

6. **Privilege-aware scan type**
   - Detect `CAP_NET_RAW` / euid; opt into `-sS` (SYN) when available,
     fall back to `-sT` (connect) when not.
   - Avoids requiring the whole tool to run as root while reclaiming
     speed/stealth lost when `-A`/sudo were removed.

7. **Active web-service fallback probe**
   - HTTP HEAD/GET against open ports nmap could not classify, to catch
     web services on non-standard ports / mislabeled TLS.

8. **KB injection into findings**
   - When a service class is identified in stage 3, surface matching KB
     blocks automatically (ties into the planned SSRF payload generator).

## Lower priority / optional

9. **Credential subsystem consumption**
   - Wire parsed creds into an authenticated scanning stage. Currently
     parsed/validated/printed but unused — make `--no-web-recon` cred-test
     path actually test creds.

10. **feroxbuster backend option**
    - Recursive discovery + native wildcard handling; reduces reliance on
      the gobuster wildcard-retry loop.

11. **Engagement timing profiles**
    - Named cfg profiles (`stealth` / `standard` / `aggressive`) mapping to
      `-T`, `--min-rate`, worker counts. Cleaner than per-engagement flag
      recall; supports TIBER noise/timing constraints.

## Packaging (separate track)

- Add `pyproject.toml` so `pip install -e .` works and the `~/bin` wrapper's
  `sys.path` injection stops being load-bearing.

## Output layout — DONE

- `<target>/` is created relative to CWD (outdir default "."), engagement-
  dir-as-context. `-o` / general.outdir still override the base.
- recon_output/ wrapper removed from the default path role.

## Technology fingerprinting (deferred — pending tool evaluation)

IT-hygiene use case: clients want software/framework/version inventory for
each web service. Replace the manual Wappalyzer-plugin + copy-paste workflow
with a structured, parseable stage.

- Leading candidate: **webanalyze** (Go). Uses the Wappalyzer fingerprint
  database, runs headless, emits JSON/CSV. Per-service output normalized into
  the target directory (e.g. `tech_<port>_<scheme>.json`), parallel to the
  gobuster stage, reusing the existing per-service loop and run_captured.
- Alternative: in-package lightweight fingerprinter (headers, meta generator,
  cookie names, favicon hash). Keeps zero-dependency principle but thinner
  version coverage; reimplements a subset of webanalyze.
- STATUS: not implemented. User to test webanalyze first and confirm exact
  scope/output before this is built. Do not add until evaluated.

Notes for when built:
- Active (fetches target) -> must sit inside the scope guardrail.
- Detected versions are reported-not-confirmed (banners stripped/spoofed in
  prod). Flag as such in any client-facing hygiene output.
- Feeds the run manifest once that lands; structured versions enable diffing
  across re-tests.

## Tooling evaluation (candidates per stage — not committed)

Candidate external tools to evaluate against the current nmap + gobuster
pipeline. All are mature OSS, JSON-capable (the recurring parse pain point),
and consistent with the existing design — the recon stages already shell out
to external binaries; the zero-dependency rule was scoped to the KB subsystem
only. None adopted until tested.

Stage 1 (port discovery):
- **Naabu** (ProjectDiscovery) — fast port sweep, native JSON. Direct analog
  to the nmap -p- sweep.
- **RustScan** — fast front-end that hands open ports to nmap for service ID.
- **masscan** — fastest for large ranges; overkill for single-box CTF, useful
  for wide client scopes.
- Pattern to consider: fast sweep (Naabu/RustScan/masscan) -> nmap only on
  open ports for fingerprint depth. Keeps nmap's version detection, cuts -p-
  time.

Stage 2 (service ID):
- Keep **nmap** — nothing matches its fingerprint depth.
- **httpx** (ProjectDiscovery) — fast HTTP probe to insert between stages 2
  and 3. Confirms which open ports are live web services (title, status,
  tech, TLS) and catches web services on non-standard ports that nmap
  mislabels. Directly addresses the current parse_web_services gap. HIGHEST
  PRIORITY of these candidates — smallest change, fixes a known weakness.

Stage 3 (web content discovery):
- **feroxbuster** — recursive discovery, native wildcard handling (already
  noted on the roadmap as a gobuster alternative).
- **dirsearch** — alternative content brute-forcer.
- **Katana** (ProjectDiscovery) — crawler; spiders the live app for real
  endpoints. Complements brute-force rather than replacing it (crawl + brute
  = better coverage).

Fingerprinting / hygiene (ties to the deferred section above):
- **Nuclei** (ProjectDiscovery) — template-based scanner, thousands of YAML
  templates. Does tech/version fingerprinting AND known-CVE flagging in
  structured output. Arguably a better fit than webanalyze for the IT-hygiene
  deliverable, since "what versions run" usually comes with "are any known-
  vulnerable." Evaluate alongside webanalyze.

Integration note: the ProjectDiscovery tools (Naabu, httpx, Katana, Nuclei,
Subfinder) share config/output conventions, so adopting several is less work
than the same number of unrelated tools.

Suggested evaluation order: httpx -> nuclei -> (Naabu or RustScan if stage-1
speed becomes a constraint).

## Reporting (low priority)

- **Self-contained HTML report.** Generate a single report.html per
  engagement, openable locally with no web server and no external assets
  (inline CSS, no CDN/fonts/remote JS). Good for the output that reads
  badly raw: SMB share tables, tech/version hygiene inventory, TLS cipher
  lists.
- DESIGN CONSTRAINT: HTML is a render layer, not storage. Canonical data
  stays JSON (the run manifest); HTML is generated from it. Do not make
  HTML the primary store — that loses diffability/machine-readability and
  recreates the parse-your-own-output problem. One generator reads the
  manifest and emits the report; stages keep writing structured output and
  stay HTML-unaware.
- Optional downstream: HTML->PDF if a client reporting standard wants PDF;
  generate both from the same JSON.
- STATUS: parked pending decision. Not a near-term objective. Presentation
  follows the data model — manifest/JSON work lands first.
