#!/usr/bin/env python3
"""
LAVA - custom credential grep layer
===================================
Runs a user-editable set of regex rules (a "scan profile") over the firmware
filesystem EMBA extracted, and emits findings in the SAME schema as
parser.py's --out. Its purpose is to catch cleartext credentials / keys that
EMBA's credential modules (S45/S99/S106/S107/S108) tend to miss.

The output is folded into the normal pipeline via `parser.py --extra-findings`,
so every custom finding goes through merge/enrich/classify exactly like an EMBA
finding. Each one is tagged with module = "CUSTOM:<rule_id>", which is what the
GUI uses to split the results into EMBA / Grep / overlap views.

Usage:
    python3 custom_scan.py --log-dir <EMBA_LOG> [--profile iot-testing] \\
        --out custom_findings.json
"""

from __future__ import annotations

import argparse
import json
import math
import re
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path

from fw_paths import find_extraction_roots, is_probably_binary
from parser import new_finding

PROFILE_DIR = Path(__file__).resolve().parents[2] / "config" / "scan_profiles"
_ROOTFS_MARKERS = ("etc", "bin", "sbin", "usr", "lib", "www", "var", "root", "home")
_MATCHED_CONTENT_CAP = 400


# ---------------------------------------------------------------------------
# Profile loading
# ---------------------------------------------------------------------------
def load_profile(name_or_path: str) -> dict:
    p = Path(name_or_path)
    if not p.exists():
        candidate = name_or_path if name_or_path.endswith(".json") else name_or_path + ".json"
        p = PROFILE_DIR / candidate
    if not p.exists():
        raise SystemExit(f"[!] scan profile not found: {name_or_path} (looked in {PROFILE_DIR})")
    try:
        prof = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise SystemExit(f"[!] scan profile is invalid JSON ({p}): {e}")
    prof["_path"] = str(p)
    return prof


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------
def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


class Rule:
    def __init__(self, spec: dict, global_reject: list | None = None):
        self.id = spec["id"]
        self.description = spec.get("description", "")
        self.pattern = spec["pattern"]
        self.rx = re.compile(spec["pattern"])
        self.value_group = spec.get("value_group")
        self.min_value_len = int(spec.get("min_value_len", 0))
        self.min_value_entropy = float(spec.get("min_value_entropy", 0.0))
        self.reject = list(global_reject or []) + [re.compile(r) for r in spec.get("reject_values", [])]

    def match(self, line: str) -> tuple[str, str | None] | None:
        """Returns (matched_text, value) if the rule fires and passes its
        value filters, else None."""
        m = self.rx.search(line)
        if not m:
            return None
        value = None
        if self.value_group:
            try:
                value = m.group(self.value_group)
            except (IndexError, re.error):
                value = None
        if value is not None:
            if len(value) < self.min_value_len:
                return None
            if self.min_value_entropy and _shannon_entropy(value) < self.min_value_entropy:
                return None
            for rr in self.reject:
                if rr.search(value):
                    return None
        return (m.group(0), value)


# ---------------------------------------------------------------------------
# Glob helper (used for the pure-Python fallback; rg applies globs itself)
# ---------------------------------------------------------------------------
def _glob_re(pattern: str) -> re.Pattern:
    i, out = 0, ["^"]
    while i < len(pattern):
        if pattern[i:i + 3] == "**/":
            out.append("(?:.*/)?")
            i += 3
        elif pattern[i:i + 2] == "**":
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    out.append("$")
    return re.compile("".join(out))


# ---------------------------------------------------------------------------
# Filesystem roots
# ---------------------------------------------------------------------------
_ROOTFS_HINTS = ("etc", "bin", "sbin", "usr", "lib", "www", "var", "root", "opt", "mnt")
# EMBA's own output dirs (reports, extractor bookkeeping, tmp) can look rootfs-ish
_EXCLUDE_ROOT_PARTS = (
    "/html-report/", "/csv_logs/", "/json_logs/", "/tmp/",
    "_binwalk_extractor", "/SoftwareComponents/", "/p55_", "/p07_", "/p35_",
)


def fs_roots(log_dir: Path) -> list[Path]:
    """The extracted Linux root filesystem(s). A directory qualifies if it holds
    at least `etc/` and `bin/` plus one more rootfs dir. Nested candidates and
    EMBA's own output dirs are dropped; only the outermost real roots are kept.

    This does NOT rely on the directory being named '*extract*' - vendor
    firmware often unpacks to '<hash>/squashfs-root/' etc."""
    fw = log_dir / "firmware"
    search_base = fw if fw.is_dir() else log_dir

    candidates: list[Path] = []
    for p in search_base.rglob("*"):
        if not p.is_dir():
            continue
        s = str(p)
        if any(x in s for x in _EXCLUDE_ROOT_PARTS):
            continue
        if not ((p / "etc").is_dir() and (p / "bin").is_dir()):
            continue
        if sum(1 for m in _ROOTFS_HINTS if (p / m).is_dir()) >= 3:
            candidates.append(p)

    if not candidates:
        # last resort: the old heuristic (name contains 'extract')
        candidates = [r for r in find_extraction_roots(log_dir)
                      if any((r / m).is_dir() for m in _ROOTFS_HINTS)
                      and not any(x in str(r) for x in _EXCLUDE_ROOT_PARTS)]
    if not candidates:
        candidates = find_extraction_roots(log_dir)

    # keep only the outermost of any nested set
    candidates = sorted(set(candidates), key=lambda x: len(str(x)))
    roots: list[Path] = []
    for c in candidates:
        if not any(str(c).startswith(str(r) + "/") for r in roots):
            roots.append(c)
    return roots


_EXTRACT_SEGMENTS = ("squashfs-root", "firmware_extract", "cpio-root", "jffs2-root",
                     "firmware.extracted")


def _canon_path(fp: str) -> str:
    """Strip leading extraction-container segments so the same file found under
    two extractors dedups to one path (binwalk vs unblob)."""
    parts = [p for p in fp.split("/") if p]
    while parts and ("extract" in parts[0].lower() or parts[0] in _EXTRACT_SEGMENTS
                     or re.fullmatch(r"[0-9A-Fa-f]{4,8}", parts[0])):
        parts.pop(0)
    return "/".join(parts) or fp


# ---------------------------------------------------------------------------
# Line producers
# ---------------------------------------------------------------------------
def _rg_lines(root: Path, rules: list[Rule], profile: dict):
    """Yield (abs_path, line_no, line_text) for candidate lines, via ripgrep."""
    if not shutil.which("rg"):
        return None
    max_kb = int(profile.get("max_file_size_kb", 768))
    cmd = ["rg", "--json", "--no-ignore", "--hidden", "--line-number",
           f"--max-filesize={max_kb}K"]
    for g in profile.get("include_paths", []) or ["**"]:
        cmd += ["--glob", g]
    for g in profile.get("exclude_paths", []):
        cmd += ["--glob", "!" + g]
    for r in rules:
        cmd += ["-e", r.pattern]
    cmd.append(str(root))

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
    except subprocess.TimeoutExpired:
        print(f"[!] WARNING: ripgrep timed out on {root}", file=sys.stderr)
        return []
    lines: list[tuple[str, int, str]] = []
    for raw in proc.stdout.splitlines():
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if obj.get("type") != "match":
            continue
        d = obj["data"]
        path = (d.get("path") or {}).get("text")
        text = (d.get("lines") or {}).get("text")
        if path is None or text is None:
            continue
        lines.append((path, d.get("line_number", 0), text.rstrip("\n")))
    return lines


def _py_lines(root: Path, rules: list[Rule], profile: dict):
    """Pure-Python fallback line producer (used when ripgrep is unavailable)."""
    max_bytes = int(profile.get("max_file_size_kb", 768)) * 1024
    text_only = bool(profile.get("text_files_only", True))
    inc = [_glob_re(g) for g in (profile.get("include_paths", []) or ["**"])]
    exc = [_glob_re(g) for g in profile.get("exclude_paths", [])]
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        rel = p.relative_to(root).as_posix()
        if not any(g.match(rel) for g in inc):
            continue
        if any(g.match(rel) for g in exc):
            continue
        try:
            if p.stat().st_size > max_bytes:
                continue
        except OSError:
            continue
        if text_only and is_probably_binary(p):
            continue
        try:
            with open(p, "r", encoding="utf-8", errors="replace") as fh:
                for i, line in enumerate(fh, start=1):
                    yield (str(p), i, line.rstrip("\n"))
        except OSError:
            continue


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------
def scan(log_dir: Path, profile: dict) -> list[dict]:
    _grej = [re.compile(r) for r in profile.get("global_reject_values", [])]
    rules = [Rule(spec, _grej) for spec in profile.get("rules", [])]
    if not rules:
        raise SystemExit("[!] the profile has no rules")

    roots = fs_roots(log_dir)
    if not roots:
        print(f"[!] WARNING: no extraction directory found under {log_dir}", file=sys.stderr)
        return []

    per_rule_cap = int(profile.get("max_hits_per_rule", 200))
    total_cap = int(profile.get("max_total_hits", 1000))
    per_rule_count: Counter = Counter()
    seen: set[tuple] = set()
    findings: list[dict] = []
    used_engine = "ripgrep" if shutil.which("rg") else "python"

    for root in roots:
        producer = _rg_lines(root, rules, profile)
        if producer is None:
            producer = _py_lines(root, rules, profile)

        for abs_path, line_no, text in producer:
            try:
                rel_path = Path(abs_path).resolve().relative_to(root.resolve()).as_posix()
            except ValueError:
                rel_path = Path(abs_path).name
            rel_path = _canon_path(rel_path)

            for rule in rules:
                res = rule.match(text)
                if res is None:
                    continue
                matched_text, value = res
                key = (rel_path, line_no, rule.id, value)
                if key in seen:
                    continue
                if per_rule_count[rule.id] >= per_rule_cap or len(findings) >= total_cap:
                    continue
                seen.add(key)
                per_rule_count[rule.id] += 1
                content = (text.strip() or matched_text)[:_MATCHED_CONTENT_CAP]
                extra = {
                    "rule": rule.id,
                    "profile": profile.get("name", "custom"),
                    "line_no": line_no,
                }
                if value is not None:
                    extra["value"] = value[:_MATCHED_CONTENT_CAP]
                findings.append(new_finding(f"CUSTOM:{rule.id}", rel_path, content, extra))

    findings.sort(key=lambda f: (f["file_path"], f["extra"].get("line_no", 0)))
    _print_summary(profile, roots, used_engine, per_rule_count, len(findings), total_cap)
    return findings


def _print_summary(profile, roots, engine, per_rule_count, n_findings, total_cap):
    print(f"[+] profile   : {profile.get('name')} ({profile['_path']})")
    print(f"[+] engine     : {engine}")
    print(f"[+] fs roots   : {len(roots)}")
    for r in roots:
        print(f"      - {r}")
    print(f"[+] custom findings: {n_findings}" + (" (capped)" if n_findings >= total_cap else ""))
    for rid, cnt in sorted(per_rule_count.items()):
        print(f"      CUSTOM:{rid}: {cnt}")


def main():
    ap = argparse.ArgumentParser(description="LAVA custom credential grep over the extracted firmware.")
    ap.add_argument("--log-dir", required=True, help="EMBA log directory (must contain firmware/…extract…)")
    ap.add_argument("--profile", default="iot-testing", help="profile name in config/scan_profiles/ or a path to a .json")
    ap.add_argument("--out", default="custom_findings.json")
    args = ap.parse_args()

    profile = load_profile(args.profile)
    findings = scan(Path(args.log_dir), profile)
    Path(args.out).write_text(json.dumps(findings, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[+] Output: {args.out}")


if __name__ == "__main__":
    main()
