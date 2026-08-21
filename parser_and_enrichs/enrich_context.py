#!/usr/bin/env python3
"""
LAVA - Context Enrichment
==========================
merged_findings.json icindeki her bulgu icin, EMBA'nin extraction sirasinda
diske cikardigi GERCEK firmware dosyasindan +-N satirlik context ekler.
Boylece LLM'e izole bir string yerine, o satirin dosyada nerede/nasil
gectigini gosteren gercek bir kod/config parcasi verilir.

Kullanim:
    python3 enrich_context.py --merged merged_findings.json --log-dir lava_iotgoat_log --out enriched_findings.json
"""

import argparse
import json
from pathlib import Path


def find_extraction_roots(log_dir: Path) -> list[Path]:
    """EMBA'nin olusturdugu tum '<...>_extract' dizinlerini bulur (squashfs,
    fat, vs. birden fazla partisyon olabilir). En spesifik/derin olanlar
    once denenir ki dogru dosyayi yanlislikla baska bir extraction'dan almayalim."""
    roots = [p for p in log_dir.rglob("*_extract") if p.is_dir()]
    roots.sort(key=lambda p: len(str(p)), reverse=True)
    return roots


def resolve_real_path(relative_path: str, roots: list[Path]) -> Path | None:
    """normalize_path() tarafindan kisaltilmis path'i (orn. 'etc/shadow')
    gercek extraction dizinindeki fiziksel dosyaya geri baglar."""
    rel = relative_path.lstrip("/")
    for root in roots:
        candidate = root / rel
        if candidate.is_file():
            return candidate
    return None


def is_probably_binary(path: Path, sniff_bytes: int = 512) -> bool:
    """Null byte iceren dosyalari binary sayariz - text context cikarmak
    anlamsiz (ELF, .so, sikistirilmis dosya vb.)."""
    try:
        with open(path, "rb") as f:
            chunk = f.read(sniff_bytes)
        return b"\x00" in chunk
    except OSError:
        return True


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
        # line_no yoksa (S45/S106/S107/S108), matched_content'i iceren
        # satiri dosya icinde arayarak buluyoruz.
        needle = matched_content.strip()
        if needle:
            for i, ln in enumerate(lines):
                if needle in ln:
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

    # Fallback: eslesen satir bulunamadi - orn. S45_pass_file_check'in
    # jenerik "flagged as password-related file" mesaji dosyanin gercek
    # icerigi degil, dosyanin icinde literal olarak hic gecmiyor. Bu durumda
    # sessizce context'siz birakmak yerine dosyanin basindan bir ornek
    # veriyoruz - model en azindan GERCEK icerigi gorsun, sadece dosya
    # adina bakip tahmin yurutmesin.
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
        real_path = resolve_real_path(rel_path, roots)

        if real_path is None:
            group["context"] = {"status": "file_not_found"}
            not_found += 1
            continue

        if is_probably_binary(real_path):
            group["context"] = {"status": "binary_file_skipped"}
            binary_skipped += 1
            continue

        # line_no bilgisi sadece S99_grepit'te var; oradan alalim.
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
    ap = argparse.ArgumentParser(description="EMBA findings'e gercek dosya baglami (context) ekler.")
    ap.add_argument("--merged", required=True, help="parse_emba_findings.py'nin urettigi merged_findings.json")
    ap.add_argument("--log-dir", required=True, help="EMBA log dizini (firmware/ alt klasorunu icermeli)")
    ap.add_argument("--out", default="enriched_findings.json")
    ap.add_argument("--window", type=int, default=10, help="Eslesen satirin ustunden/altindan kac satir alinacak")
    args = ap.parse_args()

    merged = json.loads(Path(args.merged).read_text(encoding="utf-8"))
    log_dir = Path(args.log_dir)

    enriched, binary_skipped, not_found = enrich(merged, log_dir, args.window)

    Path(args.out).write_text(json.dumps(merged, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"[+] Context eklenen: {enriched}")
    print(f"[+] Binary oldugu icin atlanan: {binary_skipped}")
    print(f"[+] Gercek dosya bulunamadi: {not_found}")
    print(f"[+] Cikti: {args.out}")


if __name__ == "__main__":
    main()