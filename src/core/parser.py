#!/usr/bin/env python3
"""
LAVA - EMBA hardcoded credential findings parser
================================================
Reduces the output of S45_pass_file_check, S99_grepit (cryptocred subset),
S106_deep_key_search, S107_deep_password_search and S108_stacs_password_search
to a single normalized schema, and computes cross-module corroboration.

Usage:
    python3 parser.py --log-dir /path/to/emba_log --out findings.json
"""

import argparse
import csv
import json
import os
import re
import sys
from pathlib import Path

from fw_paths import normalize_path

# ---------------------------------------------------------------------------
# S99_grepit (crass "cryptocred" regex bank) selection.
#
# grepit is a SOURCE-AUDIT tool: most of its ~30 "cryptocred_*" categories match
# a bare word (`password:`, `secret=`, `Authentication`) and cannot tell a
# hardcoded literal from ordinary code. LAVA's job is to let the AI make that
# call - so by default LAVA passes everything through and only removes matches
# that provably cannot be a real credential (unreadable binary bytes).
#
# LAVA_S99_SCAN - three levels, most permissive first:
#   raw (default) - every cryptocred_* category. The ONLY thing removed is a
#                   match whose line is unreadable binary garbage / not a real
#                   path. The AI triages the rest.
#   light         - raw, minus two things that structurally cannot be a config
#                   credential: (a) matches inside a compiled binary's string
#                   table (*.so / ELF / *_elf.raw), (b) static web assets
#                   (minified JS libs, images, .html, locale bundles). For the
#                   two structural categories (shadow files / PEM private keys)
#                   the matched line is also verified.
#   off           - skip S99 entirely.
#
# Cross-extractor duplicates (same file grepped under binwalk AND unblob, or
# re-extracted as a *.raw blob) are collapsed to one finding in every level.
# ---------------------------------------------------------------------------
S99_MODES = ("off", "light", "raw")
S99_DEFAULT_MODE = "raw"

S99_STRUCTURAL_CATEGORIES = {
    "1_cryptocred_passwd_or_shadow_files",
    "1_cryptocred_certificates_and_keys_narrow_private-key",
}
# Kept for compatibility (ground_truth.py / tests import this name).
S99_CATEGORY_WHITELIST = S99_STRUCTURAL_CATEGORIES

_S99_SHADOW_RE = re.compile(
    r"^[A-Za-z0-9_.\-]{1,32}:(\$[0-9a-z]{1,4}\$\S{6,}|[A-Za-z0-9./+]{13,})[:$]")
_S99_PEM_PRIV_RE = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
# ELF / compiled-object paths: a "shadow line" or "PRIVATE KEY" here is a
# format string baked into a binary (libssh, libcrypto, smbd, busybox ...), not
# a real credential file. EMBA's re-extracted "*_0_pem_private_key.raw" blobs
# are NOT binaries - keep those.
_S99_BINARY_PATH_RE = re.compile(
    r"(?i)\.(?:so|so\.[0-9.]+|ko|o|a|bin|elf|axf|dylib)(?:$|[/_])"
    r"|_[0-9]+_elf(?:\.raw)?$"
    r"|_[0-9]+_unknown\.raw$")
_S99_WEB_ASSET_RE = re.compile(r"""(?ix)
      \.(html?|xhtml|css|scss|less|map|png|jpe?g|gif|bmp|ico|svg|tiff?|webp|
         woff2?|ttf|eot|otf|swf|mp[34]|md|rst|po|mo|pot)$
    | \.min\.(js|css)$
    | (?:^|/)(?:jquery|bootstrap|angular|backbone|underscore|lodash|modernizr|
         prototype|mootools|react|vue|ember|dojo)[.\-][^/]*$
    | /(?:www|web|webs|webpages|wwwroot|htdocs|luci-static|i18n|
         locale|locales|lang|help|manual|docs?)/
""")


def _s99_scan_mode() -> str:
    mode = os.environ.get("LAVA_S99_SCAN", S99_DEFAULT_MODE).strip().lower()
    # old names (strict / gated / narrow / broad) -> the surviving filtered mode
    mode = {"strict": "light", "gated": "light",
            "narrow": "light", "broad": "light"}.get(mode, mode)
    return mode if mode in S99_MODES else S99_DEFAULT_MODE


def _s99_category_allowed(category: str, mode: str) -> bool:
    if mode == "off":
        return False
    return "cryptocred" in category  # light / raw: every cryptocred category


def _s99_keep_match(category: str, path: str, content: str, mode: str) -> bool:
    """`raw` keeps everything the caller already deemed printable. `light` also
    drops matches that structurally cannot be a config credential."""
    if mode == "raw":
        return True

    # light: matches inside a compiled binary's string table or a static web
    # asset are never a real hardcoded credential.
    if _S99_BINARY_PATH_RE.search(path) or _S99_WEB_ASSET_RE.search(path):
        return False

    # light: verify the two structurally-unambiguous categories
    if category in S99_STRUCTURAL_CATEGORIES:
        c = content.strip()
        if "private-key" in category:
            return bool(_S99_PEM_PRIV_RE.search(c))
        return bool(_S99_SHADOW_RE.match(c))

    return True


# EMBA re-extracts embedded blobs and appends "_<offset>_<type>[.raw]" to the
# file name, and runs several extractors over the same image. Both make one
# physical file look like several distinct paths. Strip that so the merge sees
# one file.
_EXTRACT_ARTIFACT_SUFFIX_RE = re.compile(
    r"(?:"
    r"_\d+_[a-z0-9_]+\.raw"
    r"|_\d+_(?:elf|pem_private_key|pem_certificate|pem_public_key|pem|"
    r"unknown|copyright|copy|ascii|gif|png|jpe?g|zlib|gzip|lzma|xz|bzip2)"
    r"|\.extracted(?:/.*)?"
    r")$", re.IGNORECASE)


def _canon_finding_path(path: str) -> str:
    """Collapse the same physical file (found under several EMBA extractors, or
    re-extracted as a *.raw blob) down to one key so merge_and_corroborate can
    dedup it. Works on both raw EMBA paths and normalize_path() output."""
    path = normalize_path(path)
    seg = [s for s in path.split("/") if s]
    while seg and ("extract" in seg[0].lower() or "squashfs" in seg[0].lower()
                   or seg[0] in ("logs", "firmware", "firmware_extract",
                                 "squashfs-root", "rootfs", "root", "jffs2-root",
                                 "cpio-root", "ubifs-root", "_rootfs")
                   or seg[0].isdigit()
                   or re.fullmatch(r"[0-9A-Fa-f-]{4,}", seg[0])
                   or seg[0].endswith(("_extract", ".uncompressed", "-root"))):
        seg.pop(0)
    out = "/".join(seg) or path
    prev = None
    while prev != out:
        prev = out
        out = _EXTRACT_ARTIFACT_SUFFIX_RE.sub("", out)
    return out or path


# backwards-compatible alias (parse_s99 dedup)
_canon_s99_path = _canon_finding_path

# A "file-level flag": the module is just saying "this file looks credential-
# related" without pinning a specific secret (S45 by filename, S106 by a match
# count). If a real finding already lands in the same file, the flag is noise.
_FILE_FLAG_CONTENT_RE = re.compile(
    r"^(?:flagged as password-related file"
    r"|\d+ match\(es\) for pattern"
    r"|\d+ match(?:es)? for pattern)")

# "Which secret is this" - two findings with the same token are the same leak.
_CRYPT_HASH_RE = re.compile(r"\$[0-9a-z]{1,6}\$[^\s:$][^\s:]{7,}")
_API_TOKEN_RE = re.compile(
    r"\b(AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|xox[baprs]-[0-9A-Za-z-]{10,}"
    r"|gh[pousr]_[0-9A-Za-z]{36,}|sk_live_[0-9A-Za-z]{20,})")
_PEM_MARKER_RE = re.compile(r"-----(?:BEGIN|END) [A-Z0-9 ]*PRIVATE KEY-----")
_PEM_BODY_RE = re.compile(r"^(?:MII[A-Za-z0-9+/]{16,}|[A-Za-z0-9+/]{40,}={0,3})\s*$")


def _is_file_flag(f: dict) -> bool:
    return bool(_FILE_FLAG_CONTENT_RE.match(f.get("matched_content", "").strip()))


def _credential_token(content: str):
    """A stable id for the secret in `content`, or None for generic text."""
    m = _CRYPT_HASH_RE.search(content)
    if m:
        return "hash:" + m.group(0)
    m = _API_TOKEN_RE.search(content)
    if m:
        return "token:" + m.group(1)
    return None


def _is_pem_privkey_material(content: str) -> bool:
    c = content.strip()
    if _PEM_MARKER_RE.search(c) or "PRIVATE KEY" in c.upper():
        return True
    first = c.splitlines()[0] if c else ""
    return bool(_PEM_BODY_RE.match(first))


def content_is_mostly_printable(text: str, min_ratio: float = 0.85) -> bool:
    """Checks whether matched_content is mostly readable text. Used to drop
    junk matches from inside binary files (random byte sequences in compiled
    binaries such as rpcd or opkg)."""
    if not text:
        return False
    printable = sum(1 for c in text if c.isprintable() or c in "\t\n")
    return (printable / len(text)) >= min_ratio

_fid_counter = 0

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def strip_ansi(text: str) -> str:
    """Strips ANSI color codes from `grep --color=always` output."""
    return _ANSI_RE.sub("", text)


def looks_like_valid_path(path: str) -> bool:
    """Simple filter to stop binary junk (kernel blobs, random text from inside
    an image) from being parsed as a path by mistake."""
    if not path or len(path) > 300:
        return False
    # Any control character other than tab means it is probably binary junk.
    if any(ord(c) < 32 for c in path if c != "\t"):
        return False
    return True


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
# S108 - stacs_pw_hashes.json (SARIF format)
# ---------------------------------------------------------------------------
def parse_s108(json_path: Path) -> list[dict]:
    out = []
    if not json_path.exists():
        return out
    try:
        data = json.loads(json_path.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError, ValueError) as e:
        print(f"[!] WARNING: {json_path.name} is unreadable / invalid JSON, skipping S108: {e}",
              file=sys.stderr)
        return out
    if not isinstance(data, dict):
        return out
    for run in data.get("runs", []):
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            message = result.get("message", {}).get("text", "")
            for loc in result.get("locations", []):
                phys = loc.get("physicalLocation", {})
                uri = phys.get("artifactLocation", {}).get("uri", "")
                snippet = phys.get("region", {}).get("snippet", {}).get("text", "")
                # empty snippet or a binwalk extraction artifact (*.raw) -> skip
                if not snippet.strip() or uri.endswith(".raw"):
                    continue
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
# S106 - deep_key_search_<binary>.txt (one txt per matched file)
# Note: this module's "matched line" output is often binary junk, so we keep
# the first 500 characters of the raw text as context; if real readable
# content is needed it must be scanned separately with `strings`.
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
# S99 - grepit txt files (grep -A/-B context, blocks separated by "--")
# Format: path:line:content        -> the actual match
#         path-line-content        -> a context line (before/after)
# Only files listed in S99_CATEGORY_WHITELIST are scanned.
# ---------------------------------------------------------------------------
# The actual match lines were being matched incorrectly without requiring the
# path to start with "/", because EMBA's "[*] Grepit state info - ..." lines also
# contain ":". Grep context lines (path-line-content) also confused the regex
# because of their ":" characters. Using [^:]+ makes the first two colons end
# the file name.
_MATCH_LINE_RE = re.compile(r"^(/[^:]+):(\d+):(.*)$")

_skipped_binary_noise = 0
_s99_gate_rejected = 0


def parse_s99(s99_dir: Path) -> list[dict]:
    global _skipped_binary_noise, _s99_gate_rejected
    out = []
    mode = _s99_scan_mode()
    if mode == "off" or not s99_dir.exists():
        return out
    seen: set[tuple] = set()  # (canon_path, category, content) - cross-extractor dedup
    for txt_path in s99_dir.glob("*.txt"):
        category = txt_path.stem
        if not _s99_category_allowed(category, mode):
            continue
        text = strip_ansi(txt_path.read_text(encoding="utf-8", errors="replace"))
        for block in text.split("\n--\n"):
            for line in block.strip().splitlines():
                m = _MATCH_LINE_RE.match(line)
                if not m:
                    continue
                raw_path = m.group(1)
                content = m.group(3)
                if not looks_like_valid_path(raw_path) or not content_is_mostly_printable(content):
                    _skipped_binary_noise += 1
                    break  # this block is binary junk - skip to the next block
                if not _s99_keep_match(category, raw_path, content, mode):
                    _s99_gate_rejected += 1
                    break
                key = (_canon_s99_path(raw_path), category, content.strip()[:160])
                if key in seen:
                    break
                seen.add(key)
                out.append(
                    new_finding(
                        "S99_grepit",
                        raw_path,
                        content,
                        {"category": category, "line_no": m.group(2)},
                    )
                )
                break  # take only the actual match per block, skip context lines
    return out


def _finding_line_no(f: dict):
    """Returns the int line number of a finding, or None. Only S99_grepit and
    the custom grep layer provide one."""
    ln = f.get("extra", {}).get("line_no")
    try:
        return int(ln) if ln is not None else None
    except (TypeError, ValueError):
        return None


def _derive_source(modules: list[str]) -> str:
    """'custom' if every module is a CUSTOM: rule, 'emba' if none is, else 'both'."""
    custom = [m for m in modules if m.startswith("CUSTOM:")]
    if not custom:
        return "emba"
    if len(custom) == len(modules):
        return "custom"
    return "both"


# ---------------------------------------------------------------------------
# Corroboration. Two findings are the same leak if, after collapsing the file
# path to its canonical form (_canon_finding_path drops per-extractor and
# re-extracted-blob variants), they share ANY of:
#   * the same matched_content
#   * the same line number
#   * the same credential token (a crypt hash / API key that appears in both,
#     e.g. the bare "$1$salt$hash" from stacs and the full "user:$1$..." line)
#   * PEM private-key material in a file that also has a BEGIN/END marker (all
#     lines of one key block, matched by different modules, collapse to one)
# A "file-level flag" (S45 "flagged as password-related file", S106 "N match(es)
# for pattern ...") is dropped when a real finding already covers that file.
# When >1 module lands on the same leak that is a strong TP signal and it also
# drives the EMBA / Grep / overlap split in the UI.
# ---------------------------------------------------------------------------
def merge_and_corroborate(findings: list[dict]) -> list[dict]:
    n = len(findings)
    parent = list(range(n))

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: int, b: int) -> None:
        parent[find(a)] = find(b)

    cpaths = [_canon_finding_path(f["file_path"]) for f in findings]

    by_content: dict[tuple, int] = {}
    by_line: dict[tuple, int] = {}
    by_token: dict[tuple, int] = {}
    pem_anchor: dict[str, int] = {}   # canon_path -> a finding index with a PEM marker
    for i, f in enumerate(findings):
        cp = cpaths[i]
        content = f["matched_content"]

        ck = (cp, content)
        union(i, by_content.setdefault(ck, i))

        ln = _finding_line_no(f)
        if ln is not None:
            union(i, by_line.setdefault((cp, ln), i))

        if not _is_file_flag(f):
            tok = _credential_token(content)
            if tok:
                union(i, by_token.setdefault((cp, tok), i))
            if _PEM_MARKER_RE.search(content):
                pem_anchor.setdefault(cp, i)

    # PEM collapse: every PEM-ish finding in a file that has a BEGIN/END marker
    # is the same key block.
    for i, f in enumerate(findings):
        anc = pem_anchor.get(cpaths[i])
        if anc is not None and _is_pem_privkey_material(f["matched_content"]):
            union(i, anc)

    groups: dict[int, list[int]] = {}
    for i in range(n):
        groups.setdefault(find(i), []).append(i)

    # Which canonical files have a "real" (non-flag) finding?
    real_cpaths = {cpaths[i] for i in range(n) if not _is_file_flag(findings[i])}

    merged = []
    for idxs in groups.values():
        group = [findings[i] for i in idxs]
        # Drop a group that is only file-level flags for a file already covered
        # by a real finding elsewhere.
        if all(_is_file_flag(g) for g in group) and cpaths[idxs[0]] in real_cpaths:
            continue

        modules = sorted({g["module"] for g in group})
        specific = [g for g in group if not _is_file_flag(g)] or group
        # Representative content: prefer a line that shows the actual secret
        # (a PEM marker or a crypt hash), then the longest.
        def _rep_score(g):
            c = g.get("matched_content", "")
            return (bool(_PEM_MARKER_RE.search(c) or _CRYPT_HASH_RE.search(c)), len(c))
        rep = max(specific, key=_rep_score)
        # nicest path: one that is already canonical, else the shortest
        paths = [g["file_path"] for g in group]
        canon_exact = [pp for pp in paths if _canon_finding_path(pp) == pp]
        best_path = min(canon_exact or paths, key=len)

        line_nos = sorted({ln for g in group if (ln := _finding_line_no(g)) is not None})
        merged_extra: dict = {}
        for g in group:
            for k, v in g.get("extra", {}).items():
                merged_extra.setdefault(k, v)
        merged.append(
            {
                "file_path": best_path,
                "matched_content": rep["matched_content"],
                "found_by_modules": modules,
                "corroboration_count": len(modules),
                "source": _derive_source(modules),
                "line_no": line_nos[0] if line_nos else None,
                "extra": merged_extra,
                "source_findings": group,
            }
        )
    # Most-corroborated findings first
    merged.sort(key=lambda x: x["corroboration_count"], reverse=True)
    return merged


def main():
    ap = argparse.ArgumentParser(description="Normalizes EMBA hardcoded credential output.")
    ap.add_argument("--log-dir", required=True, help="EMBA log directory (e.g. emba_iotgoat_log)")
    ap.add_argument("--out", default="findings.json", help="Raw (unmerged) findings output")
    ap.add_argument("--merged-out", default="merged_findings.json", help="Merged output with corroboration")
    ap.add_argument("--extra-findings", action="append", default=[],
                    help="Extra findings JSON (same schema as --out) to fold into the merge, "
                         "e.g. custom_scan.py output. May be given more than once.")
    args = ap.parse_args()

    log_dir = Path(args.log_dir)

    # Same acceptance test as run_lava.sh's _is_emba_logdir() - stay consistent so
    # a dir that the launcher accepted is not then rejected here.
    if not any((log_dir / m).exists() for m in
               ("csv_logs", "s99_grepit", "s106_deep_key_search", "emba.log")):
        print("[!] ERROR: the selected folder is not a valid EMBA log directory.")
        print(f"    None of csv_logs/, s99_grepit/, s106_deep_key_search/, emba.log found in '{log_dir}'.")
        print("    If you extracted the EMBA logs from a zip, you may have selected a subfolder.")
        print("    Please select the actual log directory that contains 'csv_logs', 'firmware', etc.")
        sys.exit(1)

    all_findings: list[dict] = []
    all_findings += parse_s45(log_dir / "csv_logs" / "s45_pass_file_check.csv")
    all_findings += parse_s107(log_dir / "csv_logs" / "s107_deep_password_search.csv")
    all_findings += parse_s108(log_dir / "s108_stacs_password_search" / "stacs_pw_hashes.json")
    all_findings += parse_s106(log_dir / "s106_deep_key_search")
    all_findings += parse_s99(log_dir / "s99_grepit")
    emba_count = len(all_findings)

    extra_count = 0
    for extra_path in args.extra_findings:
        p = Path(extra_path)
        if not p.exists():
            print(f"[!] WARNING: --extra-findings not found, skipping: {extra_path}")
            continue
        try:
            extra = json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            print(f"[!] WARNING: could not read {extra_path}: {e}")
            continue
        if isinstance(extra, list):
            all_findings += extra
            extra_count += len(extra)

    Path(args.out).write_text(json.dumps(all_findings, indent=2, ensure_ascii=False), encoding="utf-8")

    merged = merge_and_corroborate(all_findings)
    Path(args.merged_out).write_text(json.dumps(merged, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"[+] Total raw findings: {len(all_findings)} (EMBA: {emba_count}, custom: {extra_count})")
    print("[+] Per-module breakdown:")
    per_module: dict[str, int] = {}
    for f in all_findings:
        per_module[f["module"]] = per_module.get(f["module"], 0) + 1
    for mod, cnt in sorted(per_module.items()):
        print(f"      {mod}: {cnt}")
    print(f"[+] Unique findings after merge: {len(merged)}")
    by_source: dict[str, int] = {}
    for m in merged:
        by_source[m["source"]] = by_source.get(m["source"], 0) + 1
    if extra_count or by_source.get("custom") or by_source.get("both"):
        print(f"      by source: emba={by_source.get('emba', 0)}, "
              f"custom={by_source.get('custom', 0)}, overlap={by_source.get('both', 0)}")
    multi = [m for m in merged if m["corroboration_count"] > 1]
    print(f"[+] Confirmed by more than one module: {len(multi)}")
    print(f"[+] S99_grepit ({_s99_scan_mode()}): {_skipped_binary_noise} blocks skipped as "
          f"binary noise, {_s99_gate_rejected} removed by the coverage filter")
    print(f"[+] Outputs: {args.out}, {args.merged_out}")


if __name__ == "__main__":
    main()
