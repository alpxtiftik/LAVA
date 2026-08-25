#!/usr/bin/env python3
"""
LAVA - EMBA Hardcoded Credential Findings Parser
==================================================
S45_pass_file_check, S99_grepit (cryptocred alt kümesi), S106_deep_key_search,
S107_deep_password_search, S108_stacs_password_search çıktılarını tek bir
normalize şemaya indirger ve modüller-arası doğrulamayı (corroboration) hesaplar.

Kullanım:
    python3 parse_emba_findings.py --log-dir /path/to/lava_iotgoat_log --out findings.json
"""

import argparse
import csv
import json
import re
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Sadece gerçekten credential-odaklı S99_grepit kategorileri (MVP whitelist).
# ciphers_*, ssl_usage_*, tls_usage_*, dev_random, x509 gibi "kripto kullanımı
# tespiti" kategorileri bilinçli olarak dışarıda bırakıldı (bkz. sohbet notu).
# ---------------------------------------------------------------------------
S99_CATEGORY_WHITELIST = {
    "1_cryptocred_passwd_or_shadow_files",
    "1_cryptocred_certificates_and_keys_narrow_private-key",
    "2_cryptocred_certificates_and_keys_narrow_begin-certificate",
    "2_cryptocred_certificates_and_keys_narrow_public-key",
    "2_cryptocred_encryption_key",
    "2_cryptocred_passphrase_narrow",
    "2_cryptocred_password_colon_narrow",
    "2_cryptocred_password_equals_narrow",
    "2_cryptocred_password_equals_switch",
    "2_cryptocred_secret_narrow",
    "2_cryptocred_sign_key",
    # "3_cryptocred_mysql_old_hashes" - kaldırıldı: 138 bulgunun neredeyse
    # tamamı binary dosyalar içindeki rastgele byte dizileriydi, regex'in
    # kapsamı gerçek MySQL-style hash'lerden çok daha geniş yakalıyor.
    "4_cryptocred_certificates_and_keys_wide_private-key",
    "4_cryptocred_crypt_call",
    "4_cryptocred_passphrase_generic",
    "4_cryptocred_password",
    "5_cryptocred_authentication",
    "5_cryptocred_authorization",
    "5_cryptocred_certificates_and_keys_wide_begin-certificate",
    "5_cryptocred_certificates_and_keys_wide_public-key",
    "5_cryptocred_credentials_wide",
    "5_cryptocred_passphrase_wide",
    "5_cryptocred_pw_capitalcase",
    "5_cryptocred_pwd_capitalcase",
    "5_cryptocred_pwd_lowercase",
    "5_cryptocred_pwd_uppercase",
    "5_cryptocred_secret_wide",
}


def content_is_mostly_printable(text: str, min_ratio: float = 0.85) -> bool:
    """matched_content'in çoğunlukla okunabilir metin olup olmadığını kontrol
    eder. Binary dosyalar içinden geçen çöp eşleşmeleri (örn. rpcd, opkg gibi
    derlenmiş binary'lerdeki rastgele byte dizileri) elemek için kullanılır."""
    if not text:
        return False
    printable = sum(1 for c in text if c.isprintable() or c in "\t\n")
    return (printable / len(text)) >= min_ratio

# EMBA extraction dizinlerinin ortak öneki - path'leri kısaltıp okunur hale
# getirmek için bu belirteçten sonrasını alıyoruz.
EXTRACT_MARKERS = [
    "squashfs_v4_le_extract/",
    "fat_extract/",
    "unblob_extracted/firmware_extract/",
    "squashfs-root/",  # binwalk'ın klasik cpio/squashfs extraction dizini
    "cpio-root/",
    "jffs2-root/",
]

_fid_counter = 0

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def strip_ansi(text: str) -> str:
    """grep --color=always çıktısındaki ANSI renk kodlarını temizler."""
    return _ANSI_RE.sub("", text)


def looks_like_valid_path(path: str) -> bool:
    """Binary çöp verinin (kernel blob, image içinden geçen rastgele metin
    gibi) path olarak yanlışlıkla parse edilmesini engelleyen basit filtre."""
    if not path or len(path) > 300:
        return False
    # Tab dışında herhangi bir kontrol karakteri varsa muhtemelen binary çöp.
    if any(ord(c) < 32 for c in path if c != "\t"):
        return False
    return True


def normalize_path(raw_path: str) -> str:
    """EMBA'nın uzun extraction path'ini firmware-içi göreli yola indirger."""
    for marker in EXTRACT_MARKERS:
        if marker in raw_path:
            return raw_path.split(marker, 1)[1]
    return raw_path


def new_finding(module: str, file_path: str, content: str, extra: dict | None = None) -> dict:
    global _fid_counter
    _fid_counter += 1
    return {
        "finding_id": f"{module}_{_fid_counter:05d}",
        "module": module,
        "file_path": normalize_path(file_path),
        "matched_content": content.strip(),
        "extra": extra or {},
    }


# ---------------------------------------------------------------------------
# S45 - pass_file_check.csv  (format: "password file;<path>;")
# ---------------------------------------------------------------------------
def parse_s45(csv_path: Path) -> list[dict]:
    out = []
    if not csv_path.exists():
        return out
    with open(csv_path, newline="", encoding="utf-8", errors="replace") as f:
        for row in csv.reader(f, delimiter=";"):
            if len(row) >= 2 and row[0] == "password file":
                out.append(new_finding("S45_pass_file_check", row[1], "flagged as password-related file"))
    return out


# ---------------------------------------------------------------------------
# S107 - deep_password_search.csv  (format: "PW_PATH;PW_HASH;")
# ---------------------------------------------------------------------------
def parse_s107(csv_path: Path) -> list[dict]:
    out = []
    if not csv_path.exists():
        return out
    with open(csv_path, newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.reader(f, delimiter=";")
        next(reader, None)  # header: PW_PATH;PW_HASH;
        for row in reader:
            if len(row) >= 2 and row[0]:
                out.append(new_finding("S107_deep_password_search", row[0], row[1]))
    return out


# ---------------------------------------------------------------------------
# S108 - stacs_pw_hashes.json (SARIF formatı)
# ---------------------------------------------------------------------------
def parse_s108(json_path: Path) -> list[dict]:
    out = []
    if not json_path.exists():
        return out
    data = json.loads(json_path.read_text(encoding="utf-8", errors="replace"))
    for run in data.get("runs", []):
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            message = result.get("message", {}).get("text", "")
            for loc in result.get("locations", []):
                phys = loc.get("physicalLocation", {})
                uri = phys.get("artifactLocation", {}).get("uri", "")
                snippet = phys.get("region", {}).get("snippet", {}).get("text", "")
                out.append(
                    new_finding(
                        "S108_stacs_password_search",
                        uri,
                        snippet,
                        {"rule_id": rule_id, "message": message},
                    )
                )
    return out


# ---------------------------------------------------------------------------
# S106 - deep_key_search_<binary>.txt (her bulunan dosya için ayrı txt)
# Not: bu modülün "eşleşen satır" çıktısı sık sık binary çöplük içeriyor,
# bu yüzden ham metnin ilk 500 karakterini context olarak saklıyoruz;
# gerçek okunur içerik gerekiyorsa ayrıca `strings` ile taranmalı.
# ---------------------------------------------------------------------------
def parse_s106(s106_dir: Path) -> list[dict]:
    out = []
    if not s106_dir.exists():
        return out
    for txt_path in s106_dir.glob("*.txt"):
        text = strip_ansi(txt_path.read_text(encoding="utf-8", errors="replace"))
        m_path = re.search(r"\[\*\]\s*FILE_PATH:\s*(.+?)\s*\(", text)
        file_path = m_path.group(1).strip() if m_path else txt_path.stem

        m_results = re.search(r"\[\*\]\s*Deep search results:\s*\n\s*(\d+)\s*:\s*(.+)", text)
        count = m_results.group(1) if m_results else None
        pattern = m_results.group(2).strip() if m_results else None

        out.append(
            new_finding(
                "S106_deep_key_search",
                file_path,
                f"{count or '?'} match(es) for pattern: {pattern or '?'}",
                {"raw_excerpt": text[:500]},
            )
        )
    return out


# ---------------------------------------------------------------------------
# S99 - grepit txt dosyaları (grep -A/-B context ile, "--" ile ayrılmış bloklar)
# Format: path:line:content        -> asıl eşleşme
#         path-line-content        -> context satırı (before/after)
# Sadece S99_CATEGORY_WHITELIST'teki dosyalar taranır.
# ---------------------------------------------------------------------------
# Gerçek eşleşme satırları EMBA'da her zaman firmware extraction kökünden
# (mutlak "/") başlar: "/logs/firmware/.../etc/passwd:1:root:...". Başlıktaki
# "[*] Grepit state info - ..." satırları da içinde ":" barındırdığı için
# path'in "/" ile başlama zorunluluğu olmadan yanlışlıkla eşleşiyordu.
_MATCH_LINE_RE = re.compile(r"^(/[^\n]+?):(\d+):(.*)$")

_skipped_binary_noise = 0


def parse_s99(s99_dir: Path) -> list[dict]:
    global _skipped_binary_noise
    out = []
    if not s99_dir.exists():
        return out
    for txt_path in s99_dir.glob("*.txt"):
        category = txt_path.stem
        if category not in S99_CATEGORY_WHITELIST:
            continue
        text = strip_ansi(txt_path.read_text(encoding="utf-8", errors="replace"))
        for block in text.split("\n--\n"):
            for line in block.strip().splitlines():
                m = _MATCH_LINE_RE.match(line)
                if m:
                    raw_path = m.group(1)
                    content = m.group(3)
                    if not looks_like_valid_path(raw_path) or not content_is_mostly_printable(content):
                        _skipped_binary_noise += 1
                        break  # bu blok binary çöp - atla, bir sonraki bloğa geç
                    out.append(
                        new_finding(
                            "S99_grepit",
                            raw_path,
                            content,
                            {"category": category, "line_no": m.group(2)},
                        )
                    )
                    break  # blok başına sadece asıl eşleşmeyi al, context satırlarını atla
    return out


# ---------------------------------------------------------------------------
# Corroboration: aynı (file_path, matched_content) birden fazla modülde
# geçiyorsa, bu güçlü bir TP sinyalidir - modele feature olarak veriyoruz.
# ---------------------------------------------------------------------------
def merge_and_corroborate(findings: list[dict]) -> list[dict]:
    grouped: dict[tuple, list[dict]] = {}
    for f in findings:
        key = (f["file_path"], f["matched_content"])
        grouped.setdefault(key, []).append(f)

    merged = []
    for (file_path, matched_content), group in grouped.items():
        modules = sorted({g["module"] for g in group})
        merged.append(
            {
                "file_path": file_path,
                "matched_content": matched_content,
                "found_by_modules": modules,
                "corroboration_count": len(modules),
                "source_findings": group,
            }
        )
    # En çok doğrulananlar önce gelsin
    merged.sort(key=lambda x: x["corroboration_count"], reverse=True)
    return merged


def main():
    ap = argparse.ArgumentParser(description="EMBA hardcoded credential çıktılarını normalize eder.")
    ap.add_argument("--log-dir", required=True, help="EMBA log dizini (örn. lava_iotgoat_log)")
    ap.add_argument("--out", default="findings.json", help="Ham (birleştirilmemiş) findings çıktısı")
    ap.add_argument("--merged-out", default="merged_findings.json", help="Corroboration'lı birleşik çıktı")
    args = ap.parse_args()

    log_dir = Path(args.log_dir)
    
    if not (log_dir / "csv_logs").exists() and not (log_dir / "s99_grepit").exists():
        print(f"[!] HATA: Secilen klasor gecerli bir EMBA log dizini degil!")
        print(f"    '{log_dir}' icinde 'csv_logs' veya 's99_grepit' klasorleri bulunamadi.")
        print(f"    Eger EMBA loglarini zip'ten cikardiysaniz, bir alt klasoru secmis olabilirsiniz.")
        print(f"    Lutfen icinde 'csv_logs', 'firmware' vb. klasorlerin oldugu asil log dizinini secin.")
        sys.exit(1)

    all_findings: list[dict] = []
    all_findings += parse_s45(log_dir / "csv_logs" / "s45_pass_file_check.csv")
    all_findings += parse_s107(log_dir / "csv_logs" / "s107_deep_password_search.csv")
    all_findings += parse_s108(log_dir / "s108_stacs_password_search" / "stacs_pw_hashes.json")
    all_findings += parse_s106(log_dir / "s106_deep_key_search")
    all_findings += parse_s99(log_dir / "s99_grepit")

    Path(args.out).write_text(json.dumps(all_findings, indent=2, ensure_ascii=False), encoding="utf-8")

    merged = merge_and_corroborate(all_findings)
    Path(args.merged_out).write_text(json.dumps(merged, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"[+] Toplam ham finding: {len(all_findings)}")
    print(f"[+] Modül dağılımı:")
    per_module: dict[str, int] = {}
    for f in all_findings:
        per_module[f["module"]] = per_module.get(f["module"], 0) + 1
    for mod, cnt in sorted(per_module.items()):
        print(f"      {mod}: {cnt}")
    print(f"[+] Birleştirme sonrası benzersiz finding: {len(merged)}")
    multi = [m for m in merged if m["corroboration_count"] > 1]
    print(f"[+] Birden fazla modül tarafından doğrulanan: {len(multi)}")
    print(f"[+] S99_grepit'te binary çöp olarak atlanan blok: {_skipped_binary_noise}")
    print(f"[+] Çıktılar: {args.out}, {args.merged_out}")


if __name__ == "__main__":
    main()