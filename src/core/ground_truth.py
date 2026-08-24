#!/usr/bin/env python3
"""
LAVA - Ground Truth Context Enrichment
=========================================
ground_truth.json (few_shot + test_set) icindeki her kayda, enrich_context.py
ile ayni mantigi kullanarak gercek dosyadan +-N satirlik context ekler.
merged_findings.json'dan farkli olarak bu format duz bir liste (source_findings
yok), bu yuzden line_no bilgisi olmadan dogrudan matched_content aranarak
satir bulunur.

Kullanim:
    python3 enrich_ground_truth.py --ground-truth ground_truth.json --log-dir lava_iotgoat_log --out ground_truth.json
"""

import argparse
import json
from pathlib import Path

from enrich_context import (
    find_extraction_roots,
    resolve_real_path,
    is_probably_binary,
    extract_context,
)


def enrich_list(items: list[dict], roots: list[Path], window: int) -> tuple[int, int, int]:
    enriched_count = 0
    binary_skipped = 0
    not_found = 0

    for item in items:
        rel_path = item["file_path"]
        real_path = resolve_real_path(rel_path, roots)

        if real_path is None:
            item["context"] = {"status": "file_not_found"}
            not_found += 1
            continue

        if is_probably_binary(real_path):
            item["context"] = {"status": "binary_file_skipped"}
            binary_skipped += 1
            continue

        # ground_truth.json'da line_no ayrı bir alan olarak saklanmıyor,
        # bu yüzden None geçiyoruz - extract_context matched_content'i arayarak
        # satırı kendisi bulacak.
        ctx = extract_context(real_path, None, item["matched_content"], window)
        if ctx is None:
            item["context"] = {"status": "context_not_located"}
        else:
            item["context"] = {"status": "ok", **ctx}
            enriched_count += 1

    return enriched_count, binary_skipped, not_found


def main():
    ap = argparse.ArgumentParser(description="ground_truth.json'a gerçek dosya bağlamı ekler.")
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
        e, b, n = enrich_list(data[section], roots, args.window)
        total_enriched += e
        total_binary += b
        total_not_found += n
        print(f"[+] {section}: context eklenen={e}, binary atlanan={b}, bulunamayan={n}")

    Path(args.out).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"[+] TOPLAM: context eklenen={total_enriched}, binary atlanan={total_binary}, bulunamayan={total_not_found}")
    print(f"[+] Çıktı: {args.out}")


if __name__ == "__main__":
    main()
