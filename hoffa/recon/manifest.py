"""
hoffa.recon.manifest — structured per-run provenance record.

One JSON document per run, written to <target_dir>/manifest.json. Captures
enough to reproduce and audit the run: target, timestamps, resolved args,
tool versions, per-stage status and timing, and output paths.

Design: the manifest is the canonical run record. Presentation layers
(reporting, diffing across re-tests) consume it; stages only append to it.
It is written incrementally — flushed after each stage — so an interrupted
run still leaves a partial, valid record distinguishing completed stages
from an abort.
"""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class StageRecord:
    name: str
    status: str = "pending"        # pending | running | ok | failed | skipped
    started_at: str | None = None
    ended_at: str | None = None
    detail: str = ""
    outputs: list[str] = field(default_factory=list)


@dataclass
class Manifest:
    target: str
    outdir: str
    args: dict = field(default_factory=dict)
    tool_versions: dict = field(default_factory=dict)
    started_at: str = field(default_factory=_utc_now)
    ended_at: str | None = None
    scope: list[str] = field(default_factory=list)
    stages: list[StageRecord] = field(default_factory=list)
    hoffa_status: str = "running"  # running | complete | aborted

    # --- path -------------------------------------------------------------
    def _path(self) -> Path:
        return Path(self.outdir) / "manifest.json"

    # --- stage lifecycle --------------------------------------------------
    def stage_start(self, name: str) -> StageRecord:
        rec = StageRecord(name=name, status="running", started_at=_utc_now())
        self.stages.append(rec)
        self.flush()
        return rec

    def stage_end(self, rec: StageRecord, status: str, detail: str = "",
                  outputs: list[str] | None = None) -> None:
        rec.status = status
        rec.ended_at = _utc_now()
        if detail:
            rec.detail = detail
        if outputs:
            rec.outputs.extend(outputs)
        self.flush()

    def finalize(self, status: str) -> None:
        self.hoffa_status = status
        self.ended_at = _utc_now()
        self.flush()

    # --- serialization ----------------------------------------------------
    def to_dict(self) -> dict:
        d = asdict(self)
        return d

    def flush(self) -> None:
        """Write the manifest to disk. Best-effort; never raises into a run."""
        try:
            self._path().write_text(json.dumps(self.to_dict(), indent=2) + "\n")
        except OSError as e:
            print(f"[!] manifest write failed: {e}", file=sys.stderr)


def capture_tool_versions(tools: list[str]) -> dict:
    """Best-effort version capture for reproducibility.

    Runs a version query per tool. Records the first non-empty output line,
    or a marker if the tool is absent / errors. Never raises.
    """
    version_flags = {
        "nmap": ["--version"],
        "gobuster": ["version"],
        "httpx": ["-version"],
        "nuclei": ["-version"],
        "feroxbuster": ["--version"],
    }
    out: dict = {}
    for tool in tools:
        flags = version_flags.get(tool, ["--version"])
        try:
            proc = subprocess.run(
                [tool, *flags], check=False, timeout=10,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            )
            line = next((l.strip() for l in (proc.stdout or "").splitlines() if l.strip()), "")
            out[tool] = line or f"(no version output, rc={proc.returncode})"
        except FileNotFoundError:
            out[tool] = "(not found on PATH)"
        except subprocess.TimeoutExpired:
            out[tool] = "(version query timed out)"
        except OSError as e:
            out[tool] = f"(error: {e})"
    return out
