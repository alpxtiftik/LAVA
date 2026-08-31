#!/usr/bin/env python3
"""
LAVA - ground truth context enrichment
======================================
Adds +/-N lines of context from the real firmware file to every record in
ground_truth.json (few_shot + test_set), using the same logic as enricher.py.
Unlike merged_findings.json this format is a flat list (no source_findings), so
the line is located by searching for matched_content directly, without line_no.

Usage:
    python3 ground_truth.py --ground-truth ground_truth.json --log-dir emba_log --out ground_truth.json
"""

import argparse
import json
from pathlib import Path

from enricher import (
    find_extraction_roots,
    resolve_real_path,
    is_probably_binary,
    extract_context,
)


def enrich_list(items: list[dict], log_dir: Path, roots: list[Path], window: int) -> tuple[int, int, int]:
    enriched_count = 0
    binary_skipped = 0
    not_found = 0

    for item in items:
        rel_path = item["file_path"]
        real_path = resolve_real_path(rel_path, log_dir, roots)

        if real_path is None:
            item["context"] = {"status": "file_not_found"}
            not_found += 1
            continue

        if is_probably_binary(real_path):
            item["context"] = {"status": "binary_file_skipped"}
            binary_skipped += 1
            continue

        # ground_truth.json does not store line_no as a separate field, so we
        # pass None - extract_context will locate the line by searching for
        # matched_content itself.
        ctx = extract_context(real_path, None, item["matched_content"], window)
        if ctx is None:
            item["context"] = {"status": "context_not_located"}
        else:
            item["context"] = {"status": "ok", **ctx}
            enriched_count += 1

    return enriched_count, binary_skipped, not_found


def main():
    ap = argparse.ArgumentParser(description="Adds real file context to ground_truth.json.")
    ap.add_argument("--ground-truth", required=True)
    ap.add_argument("--log-dir", required=True)
    ap.add_argument("--out", default="ground_truth_enriched.json")
    ap.add_argument("--window", type=int, default=10)
    args = ap.parse_args()

    data = json.loads(Path(args.ground_truth).read_text(encoding="utf-8"))
    log_dir = Path(args.log_dir)
    roots = find_extraction_roots(log_dir)

    total_enriched = total_binary = total_not_found = 0

    for section in ("few_shot", "test_set"):
        if section not in data:
            continue
        e, b, n = enrich_list(data[section], log_dir, roots, args.window)
        total_enriched += e
        total_binary += b
        total_not_found += n
        print(f"[+] {section}: context added={e}, binary skipped={b}, not found={n}")

    Path(args.out).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"[+] TOTAL: context added={total_enriched}, binary skipped={total_binary}, not found={total_not_found}")
    print(f"[+] Output: {args.out}")


if __name__ == "__main__":
    main()
