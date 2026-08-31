#!/usr/bin/env python3
"""
LAVA - context enrichment
=========================
For every finding in merged_findings.json, adds +/-N lines of context from the
REAL firmware file that EMBA extracted to disk. This gives the LLM an actual
code/config snippet showing where and how the line appears, instead of an
isolated string.

Usage:
    python3 enricher.py --merged merged_findings.json --log-dir emba_log --out enriched_findings.json
"""

import argparse
import json
from pathlib import Path

# Shared path helpers (also used by parser.py, custom_scan.py, ground_truth.py).
# Re-exported here for backward compatibility with existing imports.
from fw_paths import (  # noqa: F401
    find_extraction_roots,
    resolve_real_path,
    is_probably_binary,
    normalize_path,
)


def extract_context(path: Path, line_no: int | None, matched_content: str, window: int = 10) -> dict | None:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    lines = text.splitlines()

    idx = None
    if line_no is not None and 1 <= line_no <= len(lines):
        idx = line_no - 1
    else:
        # No line_no (S45/S106/S107/S108): find the line containing
        # matched_content inside the file.
        needle = matched_content.strip()
        if needle:
            needle_lines = needle.splitlines()
            if len(needle_lines) == 1:
                for i, ln in enumerate(lines):
                    if needle in ln:
                        idx = i
                        break
            else:
                for i in range(len(lines) - len(needle_lines) + 1):
                    match = True
                    for j, n_line in enumerate(needle_lines):
                        if n_line.strip() and n_line not in lines[i+j]:
                            match = False
                            break
                    if match:
                        idx = i
                        break

    if idx is not None:
        start = max(0, idx - window)
        end = min(len(lines), idx + window + 1)
        return {
            "context_lines": lines[start:end],
            "matched_line_index_in_context": idx - start,
            "total_file_lines": len(lines),
            "exact_match_located": True,
        }

    # Fallback: the matched line was not found - e.g. S45_pass_file_check's
    # generic "flagged as password-related file" message is not the file's real
    # content and never appears literally inside it. Instead of silently leaving
    # it context-free, we give a sample from the start of the file so the model
    # at least sees the REAL content and does not just guess from the file name.
    if not lines:
        return None
    end = min(len(lines), window * 2 + 1)
    return {
        "context_lines": lines[:end],
        "matched_line_index_in_context": None,
        "total_file_lines": len(lines),
        "exact_match_located": False,
    }


def enrich(merged_findings: list[dict], log_dir: Path, window: int) -> tuple[int, int, int]:
    roots = find_extraction_roots(log_dir)
    enriched_count = 0
    binary_skipped = 0
    not_found = 0

    for group in merged_findings:
        rel_path = group["file_path"]
        real_path = resolve_real_path(rel_path, log_dir, roots)

        if real_path is None:
            group["context"] = {"status": "file_not_found"}
            not_found += 1
            continue

        if is_probably_binary(real_path):
            group["context"] = {"status": "binary_file_skipped"}
            binary_skipped += 1
            continue

        # line_no is only present for S99_grepit; take it from there.
        line_no = None
        for src in group.get("source_findings", []):
            ln = src.get("extra", {}).get("line_no")
            if ln is not None:
                try:
                    line_no = int(ln)
                except (TypeError, ValueError):
                    pass
                break

        ctx = extract_context(real_path, line_no, group["matched_content"], window)
        if ctx is None:
            group["context"] = {"status": "context_not_located"}
        else:
            group["context"] = {"status": "ok", **ctx}
            enriched_count += 1

    return enriched_count, binary_skipped, not_found


def main():
    ap = argparse.ArgumentParser(description="Adds real file context to EMBA findings.")
    ap.add_argument("--merged", required=True, help="merged_findings.json produced by parser.py")
    ap.add_argument("--log-dir", required=True, help="EMBA log directory (must contain the firmware/ subfolder)")
    ap.add_argument("--out", default="enriched_findings.json")
    ap.add_argument("--window", type=int, default=10, help="Number of lines to take above/below the matched line")
    args = ap.parse_args()

    merged = json.loads(Path(args.merged).read_text(encoding="utf-8"))
    log_dir = Path(args.log_dir)

    enriched, binary_skipped, not_found = enrich(merged, log_dir, args.window)

    Path(args.out).write_text(json.dumps(merged, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"[+] Context added: {enriched}")
    print(f"[+] Skipped as binary: {binary_skipped}")
    print(f"[+] Real file not found: {not_found}")
    print(f"[+] Output: {args.out}")


if __name__ == "__main__":
    main()
