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
# S99_grepit (crass "cryptocred" regex bank) selection + quality gate.
#
# grepit is a SOURCE-AUDIT tool: it flags "code that touches passwords" for a
# human reviewer. Most of its ~30 "cryptocred_*" categories match a bare word
# (`password:`, `secret=`, `Authentication`) with NO way to tell a hardcoded
# literal from ordinary code (`if ($pass != "")`, `"&password=".$password`,
# error strings in an ELF). On real firmware that is hundreds of false positives.
#
# Two categories ARE structurally unambiguous:
#   1_cryptocred_passwd_or_shadow_files              -> /etc/shadow $1$salt$hash
#   1_cryptocred_certificates_and_keys_narrow_private-key -> PEM PRIVATE KEY block
# Those are the only ones LAVA trusts by default. Everything else "KEY=value"
# is better covered by EMBA S107 and by LAVA's own custom grep layer (which
# requires a concrete quoted value with entropy).
#
# LAVA_S99_SCAN:
#   narrow (default) - ONLY the two structural categories, gated to real hits.
#   broad            - also the word-match categories, run through a heuristic
#                      value gate (still noisy; for AI_PROVIDER=local/gemini +
#                      manual triage). Never for MCP agent mode.
#   off              - skip S99 entirely (S45/S106/S107/S108 + custom grep only).
# ---------------------------------------------------------------------------
S99_STRUCTURAL_CATEGORIES = {
    "1_cryptocred_passwd_or_shadow_files",
    "1_cryptocred_certificates_and_keys_narrow_private-key",
}
# Kept for compatibility (ground_truth.py / tests import this name).
S99_CATEGORY_WHITELIST = S99_STRUCTURAL_CATEGORIES

# broad-mode extras: value-bearing but noisy.
S99_VALUE_CATEGORIES = {
    "2_cryptocred_passphrase_narrow",
    "2_cryptocred_password_colon_narrow",
    "2_cryptocred_password_equals_narrow",
    "2_cryptocred_password_equals_switch",
    "2_cryptocred_secret_narrow",
    "4_cryptocred_crypt_call",
    "5_cryptocred_pw_capitalcase",
    "5_cryptocred_pwd_capitalcase",
}

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

# broad-mode value gate ---------------------------------------------------------
_S99_WEB_ASSET_RE = re.compile(r"""(?ix)
      \.(html?|xhtml|css|scss|less|map|png|jpe?g|gif|bmp|ico|svg|tiff?|webp|
         woff2?|ttf|eot|otf|swf|mp[34]|md|rst|po|mo|pot)$
    | \.min\.(js|css)$
    | (?:^|/)(?:jquery|bootstrap|angular|backbone|underscore|lodash|modernizr|
         prototype|mootools|react|vue|ember|dojo)[.\-][^/]*$
    | /(?:www|web|webs|webpages|wwwroot|htdocs|luci-static|i18n|
         locale|locales|lang|help|manual|docs?)/
""")
_S99_ASSIGN_RE = re.compile(r"""(?ix)
    (?:pass(?:word|wd|phrase|code|key)?|pwd|pw|secret|psk|passwort)
    \s*(?P<op>[:=])\s*(?P<v>.*)$""")
_S99_VALUE_REJECT_RE = re.compile(r"""(?ix) ^\s*(?:
      $
    | ["'`]{1,2}\s*[;,)\]}]?\s*$
    | [{\[(<%$]
    | \\?\$?\{
    | (?:true|false|null|nil|none|undefined|nan|required|optional|auto|yes|no|
        on|off|enabled?|disabled?|function|typeof|return|var|let|const|new|
        i18n|gettext|query|get|set|document|window|this|self)\b
    | [A-Za-z_]\w*\s*\(
    | .{0,120}[=!]=
)""")


def _s99_scan_mode() -> str:
    mode = os.environ.get("LAVA_S99_SCAN", "narrow").strip().lower()
    return mode if mode in ("narrow", "broad", "off") else "narrow"


def _s99_category_allowed(category: str, mode: str) -> bool:
    if mode == "off":
        return False
    if category in S99_STRUCTURAL_CATEGORIES:
        return True
    if mode != "broad":
        return False
    return category in S99_VALUE_CATEGORIES or "cryptocred" in category


def _s99_keep_match(category: str, path: str, content: str) -> bool:
    """The quality gate. Returns True only for a match that plausibly points at
    a hardcoded secret (not code that merely mentions one)."""
    c = content.strip()
    if category in S99_STRUCTURAL_CATEGORIES:
        if _S99_BINARY_PATH_RE.search(path):
            return False
        if "private-key" in category:
            return bool(_S99_PEM_PRIV_RE.search(c))
        return bool(_S99_SHADOW_RE.match(c))  # passwd/shadow

    # broad-mode word-match categories -> heuristic gate
    if _S99_WEB_ASSET_RE.search(path):
        return False
    m = _S99_ASSIGN_RE.search(c)
    if not m:
        return False
    val = m.group("v").strip().strip("\"'` ,;)")
    if len(val) < 4 or _S99_VALUE_REJECT_RE.match(m.group("v")):
        return False
    # value is just another variable / accessor
    if re.fullmatch(r"\$?\{?[A-Za-z_][\w.]*\}?", val) or re.search(
            r"\.(query|get|value|val)\b", m.group("v")):
        return False
    return True


_S99_RAW_SUFFIX_RE = re.compile(
    r"_\d+_(?:pem_private_key|elf|copyright|unknown|copy|ascii)\b.*$"
    r"|_\d+_copy(?:right)?$")


def _canon_s99_path(path: str) -> str:
    """Collapse the same file found under several EMBA extractors / re-extracted
    as a *.raw blob down to one key, so merge_and_corroborate dedups them."""
    seg = [s for s in path.split("/") if s]
    while seg and ("extract" in seg[0].lower() or "squashfs" in seg[0].lower()
                   or seg[0] in ("logs", "firmware", "firmware_extract",
                                 "squashfs-root", "rootfs", "root", "jffs2-root",
                                 "cpio-root", "ubifs-root", "_rootfs")
                   or seg[0].isdigit()
                   or re.fullmatch(r"[0-9A-Fa-f-]{4,}", seg[0])
                   or seg[0].endswith(("_extract", ".uncompressed", "-root"))):
        seg.pop(0)
    if seg:
        seg[-1] = _S99_RAW_SUFFIX_RE.sub("", seg[-1])
    return "/".join(seg) or path


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
    data = json.loads(json_path.read_text(encoding="utf-8", errors="replace"))
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
                if not _s99_keep_match(category, raw_path, content):
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
# Corroboration: two findings are the same leak if they share
# (file_path, matched_content) OR (file_path, line_no). When more than one
# module (EMBA module or CUSTOM: rule) lands on the same leak, that is a strong
# TP signal and it also drives the EMBA / Grep / overlap split in the UI.
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

    by_content: dict[tuple, int] = {}
    by_line: dict[tuple, int] = {}
    for i, f in enumerate(findings):
        fp = f["file_path"]
        ck = (fp, f["matched_content"])
        if ck in by_content:
            union(i, by_content[ck])
        else:
            by_content[ck] = i
        ln = _finding_line_no(f)
        if ln is not None:
            lk = (fp, ln)
            if lk in by_line:
                union(i, by_line[lk])
            else:
                by_line[lk] = i

    groups: dict[int, list[dict]] = {}
    for i, f in enumerate(findings):
        groups.setdefault(find(i), []).append(f)

    merged = []
    for group in groups.values():
        modules = sorted({g["module"] for g in group})
        # Representative content: prefer the longest matched_content (more context).
        rep = max(group, key=lambda g: len(g.get("matched_content", "")))
        line_nos = sorted({ln for g in group if (ln := _finding_line_no(g)) is not None})
        merged_extra: dict = {}
        for g in group:
            for k, v in g.get("extra", {}).items():
                merged_extra.setdefault(k, v)
        merged.append(
            {
                "file_path": rep["file_path"],
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

    if not (log_dir / "csv_logs").exists() and not (log_dir / "s99_grepit").exists():
        print("[!] ERROR: the selected folder is not a valid EMBA log directory.")
        print(f"    No 'csv_logs' or 's99_grepit' folder found inside '{log_dir}'.")
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
    print(f"[+] S99_grepit: {_skipped_binary_noise} blocks skipped as binary noise, "
          f"{_s99_gate_rejected} rejected by the credential gate")
    print(f"[+] Outputs: {args.out}, {args.merged_out}")


if __name__ == "__main__":
    main()
