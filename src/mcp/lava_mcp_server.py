#!/usr/bin/env python3
"""
LAVA - MCP server (agentic AI provider)
======================================
This server is LAVA's third AI provider mode. In local (Ollama) and cloud
(Gemini) modes `classifier.py` hands the LLM a ready-made prompt package; in MCP
mode the LLM (Claude Code / Claude Desktop / Antigravity CLI) connects as an
**active agent**: it explores the EMBA log directory via its own tool calls,
reads the files it decides it needs, and writes its verdicts back to LAVA with
another tool call.

The output (`verdicts.json`) schema is IDENTICAL to local/Gemini mode; this
server derives that schema from the merged-findings produced by
`src/core/parser.py` (parser is not modified, only imported as a library).

Runs over stdio transport:

    python src/mcp/lava_mcp_server.py --log-dir /path/to/emba_log \\
        --fw-root /path/to/extracted_fw [--verdicts-out /path/to/verdicts.json]

All file-reading tools are path-sandboxed: any request that escapes
`--log-dir` / `--fw-root` is rejected.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

try:  # mcp < 2
    from mcp.server.fastmcp import FastMCP  # type: ignore
except ModuleNotFoundError:  # mcp >= 2 (FastMCP -> MCPServer)
    from mcp.server.mcpserver import MCPServer as FastMCP  # type: ignore

# --- load parser.py as a library (unmodified) ------------------------------
_CORE_DIR = Path(__file__).resolve().parents[1] / "core"
if str(_CORE_DIR) not in sys.path:
    sys.path.insert(0, str(_CORE_DIR))
import parser as emba_parser  # noqa: E402  (src/core/parser.py)


# ---------------------------------------------------------------------------
# Global configuration (filled from CLI arguments)
# ---------------------------------------------------------------------------
class ServerConfig:
    log_dir: Path = Path(".")
    fw_root: Path = Path(".")
    verdicts_out: Path = Path("verdicts.json")


CFG = ServerConfig()

# finding_id -> merged finding record
REGISTRY: dict[str, dict] = {}

_TEXT_MAX_SCAN_BYTES = 2_000_000  # upper limit per file scanned during search/grep
_SEARCH_RESULT_CAP = 300


def log(msg: str) -> None:
    """stdio transport uses stdout, so ALL logs go to stderr."""
    print(f"[lava-mcp] {msg}", file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------
# Path sandbox
# ---------------------------------------------------------------------------
def _safe_resolve(root: Path, user_path: str) -> Path:
    """Resolves user_path under root. Anything escaping root raises ValueError.

    Normalized with `os.path.realpath` (handles symlinks and '..')."""
    root_real = Path(os.path.realpath(root))
    raw = (user_path or "").strip().replace("\\", "/")
    # Always treat absolute / drive-rooted input as relative to root
    raw = raw.lstrip("/")
    raw = re.sub(r"^[A-Za-z]:/", "", raw)
    candidate = Path(os.path.realpath(root_real / raw))
    if candidate != root_real and root_real not in candidate.parents:
        raise ValueError(
            f"Path '{user_path}' is outside the sandbox (must stay under {root_real}). Rejected."
        )
    return candidate


def _read_text_capped(path: Path, max_bytes: int) -> str:
    data = path.read_bytes()
    truncated = len(data) > max_bytes
    text = data[:max_bytes].decode("utf-8", errors="replace")
    if truncated:
        text += f"\n\n... [TRUNCATED - showing the first {max_bytes} bytes of the file, {len(data)} bytes total]"
    return text


def _looks_binary(path: Path, sniff: int = 1024) -> bool:
    try:
        with open(path, "rb") as f:
            return b"\x00" in f.read(sniff)
    except OSError:
        return True


# ---------------------------------------------------------------------------
# Finding registry (source of the verdicts.json schema)
# ---------------------------------------------------------------------------
def _finding_id(file_path: str, matched_content: str) -> str:
    h = hashlib.sha1(f"{file_path}|{matched_content}".encode("utf-8", "replace")).hexdigest()
    return f"lava_{h[:12]}"


def build_registry(log_dir: Path, custom_findings_path: Path | None = None) -> dict[str, dict]:
    """Builds the finding registry from parser.py's merge_and_corroborate output.
    This keeps the file-name / type schema of the verdicts.json produced in MCP
    mode identical to local/Gemini mode. If custom_findings_path is given, the
    custom grep findings are folded into the same merge (so the agent verdicts
    EMBA and custom findings together, and each carries a `source` tag)."""
    reg: dict[str, dict] = {}
    csv_dir = log_dir / "csv_logs"
    all_findings: list[dict] = []
    try:
        all_findings += emba_parser.parse_s45(csv_dir / "s45_pass_file_check.csv")
        all_findings += emba_parser.parse_s107(csv_dir / "s107_deep_password_search.csv")
        all_findings += emba_parser.parse_s108(
            log_dir / "s108_stacs_password_search" / "stacs_pw_hashes.json"
        )
        all_findings += emba_parser.parse_s106(log_dir / "s106_deep_key_search")
        all_findings += emba_parser.parse_s99(log_dir / "s99_grepit")
    except Exception as e:  # noqa: BLE001 - if the registry stays empty the tools still return an explanatory error
        log(f"WARNING: error while building the registry: {e!r}")
        return reg

    if custom_findings_path and Path(custom_findings_path).exists():
        try:
            extra = json.loads(Path(custom_findings_path).read_text(encoding="utf-8"))
            if isinstance(extra, list):
                all_findings += extra
                log(f"loaded {len(extra)} custom grep findings from {custom_findings_path}")
        except (json.JSONDecodeError, OSError) as e:
            log(f"WARNING: could not read custom findings: {e}")

    merged = emba_parser.merge_and_corroborate(all_findings)
    for m in merged:
        fid = _finding_id(m["file_path"], m["matched_content"])
        reg[fid] = {
            "finding_id": fid,
            "file_path": m["file_path"],
            "matched_content": m["matched_content"],
            "found_by_modules": m["found_by_modules"],
            "corroboration_count": m["corroboration_count"],
            "source": m.get("source", "emba"),
            "line_no": m.get("line_no"),
            "candidate_value": (m.get("extra") or {}).get("value"),
        }
    return reg


# ---------------------------------------------------------------------------
# Writing verdicts.json  (identical to the classifier.py run-mode schema)
# ---------------------------------------------------------------------------
def _atomic_write_json(data: Any, path: Path) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.parent.mkdir(parents=True, exist_ok=True)
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, path)


def write_findings_snapshot() -> None:
    """In MCP mode parser.py/enricher.py do NOT run as separate steps. Since the
    dashboard's 'total findings' counter reads enriched_findings.json, we dump
    the registry next to verdicts.json under that name once (the context field
    is a placeholder here because in MCP mode the agent collects it via tools)."""
    if not REGISTRY:
        return
    snapshot = [
        {**rec, "context": {"status": "mcp_agent_mode"}}
        for rec in REGISTRY.values()
    ]
    try:
        _atomic_write_json(snapshot, CFG.verdicts_out.parent / "enriched_findings.json")
    except OSError as e:
        log(f"WARNING: could not write enriched_findings.json: {e}")


def _load_existing_verdicts() -> list[dict]:
    if CFG.verdicts_out.exists():
        try:
            data = json.loads(CFG.verdicts_out.read_text(encoding="utf-8"))
            if isinstance(data, list):
                return data
        except (json.JSONDecodeError, OSError):
            pass
    return []


def _verdict_record(finding: dict, verdict: str, confidence: float, reasoning: str) -> dict:
    """Field-for-field identical to the object produced by run_full_mode in local/Gemini mode."""
    return {
        "file_path": finding["file_path"],
        "matched_content": finding["matched_content"],
        "found_by_modules": finding["found_by_modules"],
        "corroboration_count": finding["corroboration_count"],
        "source": finding.get("source", "emba"),
        "line_no": finding.get("line_no"),
        "predicted_verdict": verdict,
        "confidence": confidence,
        "model_reasoning": reasoning,
        "attempts": 1,
    }


def _normalize_verdict(verdict: str) -> str:
    v = str(verdict).strip().upper()
    if v in ("TP", "TRUE POSITIVE", "TRUE_POSITIVE"):
        return "TP"
    if v in ("FP", "FALSE POSITIVE", "FALSE_POSITIVE"):
        return "FP"
    raise ValueError(f"verdict must be 'TP' or 'FP', got: {verdict!r}")


def _clamp_conf(confidence: float) -> float:
    try:
        c = float(confidence)
    except (TypeError, ValueError):
        return 0.0
    if c > 1.0:  # e.g. 80 -> 0.80
        c = c / 100.0
    return max(0.0, min(1.0, round(c, 4)))


def _write_verdicts(new_records: dict[str, dict]) -> None:
    """new_records: finding_id -> verdict_record. Writes in registry order and
    preserves records already in the file that are not in the registry."""
    existing = _load_existing_verdicts()
    by_key: dict[tuple, dict] = {
        (r.get("file_path"), r.get("matched_content")): r for r in existing
    }
    for fid, rec in new_records.items():
        by_key[(rec["file_path"], rec["matched_content"])] = rec

    ordered: list[dict] = []
    seen: set[tuple] = set()
    for fid, fnd in REGISTRY.items():
        key = (fnd["file_path"], fnd["matched_content"])
        if key in by_key:
            ordered.append(by_key[key])
            seen.add(key)
    for key, rec in by_key.items():  # leftovers not in the registry
        if key not in seen:
            ordered.append(rec)
    _atomic_write_json(ordered, CFG.verdicts_out)


# ---------------------------------------------------------------------------
# MCP server and tools
# ---------------------------------------------------------------------------
mcp = FastMCP("lava")


@mcp.tool()
def list_findings() -> list[dict]:
    """Returns EVERY hardcoded-credential finding for this firmware (with its
    finding_id). This is the starting point: every finding_id must eventually
    receive a submit_verdict / submit_all_verdicts call.

    Fields: finding_id, file_path, matched_content, found_by_modules,
    corroboration_count, line_no, source ("emba" = EMBA modules only,
    "custom" = LAVA's own grep rules only, "both" = confirmed by both),
    candidate_value (the exact secret a CUSTOM: rule captured, if any)."""
    return list(REGISTRY.values())


@mcp.tool()
def get_hardcoded_keys_module_output() -> str:
    """Returns the RAW output logs of EMBA's hardcoded-credential modules
    (S45 pass_file_check, S106 deep_key_search, S107 deep_password_search,
    S108 stacs_password_search, S99 grepit cryptocred) directly. Start your
    exploration here and drill in with the other tools if needed."""
    ld = CFG.log_dir
    chunks: list[str] = []

    def _add(title: str, p: Path, limit: int = 40000) -> None:
        if p.exists() and p.is_file():
            chunks.append(f"===== {title} ({p.relative_to(ld) if p.is_relative_to(ld) else p}) =====\n"
                          + _read_text_capped(p, limit))

    _add("S45 pass_file_check", ld / "csv_logs" / "s45_pass_file_check.csv")
    _add("S107 deep_password_search", ld / "csv_logs" / "s107_deep_password_search.csv")
    _add("S108 stacs_pw_hashes", ld / "s108_stacs_password_search" / "stacs_pw_hashes.json")
    for d, label in ((ld / "s106_deep_key_search", "S106"), (ld / "s99_grepit", "S99")):
        if d.is_dir():
            for txt in sorted(d.glob("*.txt")):
                _add(f"{label} {txt.name}", txt, 20000)

    if not chunks:
        return (f"No recognized hardcoded-credential module output was found in this log directory ({ld}). "
                "Inspect the directory structure with list_log_files.")
    return "\n\n".join(chunks)


@mcp.tool()
def list_log_files(subdir: str = "") -> list[str]:
    """Lists files and folders in the EMBA log directory (--log-dir). If `subdir`
    is given, that subdirectory's contents are listed. Directories get a
    trailing '/'. Sandbox: stays under --log-dir only."""
    try:
        base = _safe_resolve(CFG.log_dir, subdir)
    except ValueError as e:
        return [f"[error] {e}"]
    if not base.exists():
        return [f"[error] no such path: {subdir}"]
    if base.is_file():
        return [subdir]
    out: list[str] = []
    for p in sorted(base.iterdir()):
        rel = p.relative_to(Path(os.path.realpath(CFG.log_dir))).as_posix()
        out.append(rel + "/" if p.is_dir() else rel)
    return out or ["[empty directory]"]


@mcp.tool()
def read_log_file(path: str, max_bytes: int = 20000) -> str:
    """Reads a log file under --log-dir. Large files are truncated with a
    TRUNCATED notice. Sandbox: under --log-dir only."""
    try:
        p = _safe_resolve(CFG.log_dir, path)
    except ValueError as e:
        return f"[error] {e}"
    if not p.exists() or not p.is_file():
        return f"[error] no such file: {path}"
    return _read_text_capped(p, max(1000, int(max_bytes)))


@mcp.tool()
def read_firmware_file(path: str, max_bytes: int = 20000) -> str:
    """Reads a file from the firmware filesystem EMBA extracted (--fw-root). Use
    this to verify whether a hardcoded credential is real and actually used
    (init scripts, config files, etc.). Sandbox: under --fw-root only."""
    try:
        p = _safe_resolve(CFG.fw_root, path)
    except ValueError as e:
        return f"[error] {e}"
    if not p.exists() or not p.is_file():
        return f"[error] no such file: {path} (searched under --fw-root)"
    if _looks_binary(p):
        return f"[info] '{path}' looks binary (contains a null byte); text context is meaningless."
    return _read_text_capped(p, max(1000, int(max_bytes)))


@mcp.tool()
def search_log_content(pattern: str, subdir: str = "") -> list[dict]:
    """grep-like search inside --log-dir. Compiled as a regex first; if the regex
    is invalid it falls back to a literal search via re.escape. Returns:
    [{file, line_no, line, regex}] (at most 300 results). Sandbox: --log-dir."""
    try:
        base = _safe_resolve(CFG.log_dir, subdir)
    except ValueError as e:
        return [{"error": str(e)}]
    if not base.exists():
        return [{"error": f"no such path: {subdir}"}]
    try:
        rx = re.compile(pattern)
        used_regex = True
    except re.error:
        rx = re.compile(re.escape(pattern))
        used_regex = False

    root_real = Path(os.path.realpath(CFG.log_dir))
    files = [base] if base.is_file() else [p for p in base.rglob("*") if p.is_file()]
    results: list[dict] = []
    for fp in files:
        try:
            if fp.stat().st_size > _TEXT_MAX_SCAN_BYTES or _looks_binary(fp):
                continue
            with open(fp, "r", encoding="utf-8", errors="replace") as fh:
                for i, line in enumerate(fh, start=1):
                    if rx.search(line):
                        results.append({
                            "file": fp.relative_to(root_real).as_posix(),
                            "line_no": i,
                            "line": line.rstrip("\n")[:500],
                            "regex": used_regex,
                        })
                        if len(results) >= _SEARCH_RESULT_CAP:
                            results.append({"note": f"results capped at {_SEARCH_RESULT_CAP}"})
                            return results
        except OSError:
            continue
    return results or [{"note": "no match", "regex": used_regex}]


class VerdictIn(BaseModel):
    finding_id: str = Field(description="finding_id from list_findings")
    verdict: str = Field(description="'TP' (True Positive) or 'FP' (False Positive)")
    confidence: float = Field(description="confidence score between 0.0 and 1.0")
    reasoning: str = Field(description="1-2 sentence SHORT ENGLISH rationale")


def _submit_one(v: VerdictIn, sink: dict[str, dict]) -> str:
    finding = REGISTRY.get(v.finding_id)
    if finding is None:
        valid = ", ".join(list(REGISTRY)[:8])
        return (f"[error] unknown finding_id: {v.finding_id!r}. "
                f"Get valid ids with list_findings (e.g. {valid} ...)")
    verdict = _normalize_verdict(v.verdict)
    rec = _verdict_record(finding, verdict, _clamp_conf(v.confidence), str(v.reasoning).strip())
    sink[v.finding_id] = rec
    return f"[ok] {v.finding_id} -> {verdict} (conf={rec['confidence']})"


@mcp.tool()
def submit_verdict(finding_id: str, verdict: str, confidence: float, reasoning: str) -> str:
    """Writes the verdict for a single finding to verdicts.json (same schema,
    same file, atomic - as in local/Gemini mode). verdict='TP'|'FP',
    confidence=0.0-1.0, reasoning=short English rationale."""
    sink: dict[str, dict] = {}
    msg = _submit_one(
        VerdictIn(finding_id=finding_id, verdict=verdict, confidence=confidence, reasoning=reasoning),
        sink,
    )
    if sink:
        _write_verdicts(sink)
    return msg


@mcp.tool()
def submit_all_verdicts(verdicts: list[VerdictIn]) -> str:
    """Writes the verdicts for ALL findings in ONE call (the preferred method).
    Each item is {finding_id, verdict, confidence, reasoning}. verdicts.json is
    written in the exact same schema as local/Gemini mode."""
    sink: dict[str, dict] = {}
    lines: list[str] = []
    for v in verdicts:
        lines.append(_submit_one(v, sink))
    if sink:
        _write_verdicts(sink)

    submitted = set(sink)
    missing = [fid for fid in REGISTRY if fid not in submitted]
    summary = [f"[written] {len(sink)} verdicts -> {CFG.verdicts_out}"]
    if missing:
        summary.append(f"[warning] {len(missing)} finding_id(s) without a verdict: "
                       + ", ".join(missing[:20]) + (" ..." if len(missing) > 20 else ""))
    else:
        summary.append("[done] a verdict was written for every finding_id.")
    return "\n".join(summary + lines)


# ---------------------------------------------------------------------------
def main() -> None:
    ap = argparse.ArgumentParser(description="LAVA MCP server (agentic AI provider, stdio transport)")
    ap.add_argument("--log-dir", required=True, help="EMBA log directory")
    ap.add_argument("--fw-root", required=True, help="root of the firmware filesystem EMBA extracted")
    ap.add_argument("--verdicts-out", default=None,
                    help="verdicts.json output path (default: <cwd>/verdicts.json)")
    ap.add_argument("--custom-findings", default=None,
                    help="custom_scan.py output (custom_findings.json) to fold into the registry")
    args = ap.parse_args()

    CFG.log_dir = Path(args.log_dir).expanduser().resolve()
    CFG.fw_root = Path(args.fw_root).expanduser().resolve()
    CFG.verdicts_out = (Path(args.verdicts_out).expanduser().resolve() if args.verdicts_out
                        else Path.cwd() / "verdicts.json")
    custom_findings = (Path(args.custom_findings).expanduser().resolve()
                       if args.custom_findings else None)

    if not CFG.log_dir.is_dir():
        log(f"WARNING: --log-dir does not exist: {CFG.log_dir}")
    if not CFG.fw_root.exists():
        log(f"WARNING: --fw-root does not exist: {CFG.fw_root}")

    REGISTRY.clear()
    REGISTRY.update(build_registry(CFG.log_dir, custom_findings))
    write_findings_snapshot()
    log(f"registry: {len(REGISTRY)} findings | log-dir={CFG.log_dir} | fw-root={CFG.fw_root} "
        f"| verdicts-out={CFG.verdicts_out}")

    mcp.run()  # stdio transport (default)


if __name__ == "__main__":
    main()
