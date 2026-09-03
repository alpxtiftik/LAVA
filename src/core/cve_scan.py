#!/usr/bin/env python3
"""
LAVA - CVE scan module (v1, no AI)
=================================
Turns the CVE data EMBA already produced into a categorized, filterable list.
This module does NOT query any CVE database itself - EMBA's F17_cve_bin_tool
and S26_kernel_vuln_verifier modules did that. Here we only read their output,
keep the real CVEs, and tag each one with the fields the GUI / report filter on
(attack vector, severity, exploit availability).

Inputs (under --log-dir):
    SBOM/EMBA_sbom_vex_only.json            non-kernel component CVEs (CycloneDX VEX)
    s26_kernel_vuln_verifier/json/*.json    kernel CVEs (same VEX schema, richer)
    s26_kernel_vuln_verifier/KEV.txt        kernel CVEs on CISA's known-exploited list
    s26_kernel_vuln_verifier/cve_results_kernel_*.csv   symbol/compile verification flags

Only identifiers of the form CVE-YYYY-NNNN are kept. cve-bin-tool also pulls in
OSV distribution advisories (AZL-, OESA-, RHSA-, SUSE- ...); those are advisories
for *other* distributions' packaging of the same upstream component and are not
actionable for this firmware, so they are dropped.

Output: cve_findings.json - a list of records, one per (cve, component):
    cve, component, version, source_module ("F17" | "S26"),
    cvss_score, cvss_version, severity, cvss_vector,
    av, ac, pr, ui, impact {c,i,a}, cwe [], description,
    has_exploit, exploit_sources [], exploit_tier, kev,
    verified   (kernel only: "" | "symbols" | "compile"),
    default_hidden   (kernel low/medium noise - hidden until "show all")
"""

from __future__ import annotations

import argparse
import csv
import glob
import json
import re
import sys
from pathlib import Path

_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{3,}$", re.IGNORECASE)
_KERNEL_COMPONENTS = {"kernel", "linux_kernel", "linux", "linux-kernel"}

# EMBA writes exploit refs as properties like {"name":"EMBA:sbom:1:exploit",
# "value":"'EDB:44806'"}. First token before ':' is the source.
_EXPLOIT_WEAPONIZED = {"MSF", "EDB", "ROUTERSPLOIT", "RS"}
_EXPLOIT_POC = {"PSS", "PACKETSTORM", "PS"}
_EXPLOIT_REFERENCE = {"SNYK"}

_AV_NAME = {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"}
_AC_NAME = {"L": "Low", "H": "High", "M": "Medium"}
_PR_NAME = {"N": "None", "L": "Low", "H": "High"}
_UI_NAME = {"N": "None", "R": "Required"}
_IMPACT_NAME = {"N": "None", "L": "Low", "P": "Partial", "C": "Complete", "H": "High"}


# ---------------------------------------------------------------------------
# Locating EMBA's CVE output
# ---------------------------------------------------------------------------
def _find_vex(log_dir: Path) -> Path | None:
    primary = log_dir / "SBOM" / "EMBA_sbom_vex_only.json"
    if primary.is_file():
        return primary
    # the HTML-report copy, or an unusual layout
    for cand in sorted(log_dir.rglob("EMBA_sbom_vex_only.json")):
        if cand.is_file():
            return cand
    return None


def _s26_dir(log_dir: Path) -> Path | None:
    d = log_dir / "s26_kernel_vuln_verifier"
    if d.is_dir():
        return d
    for cand in sorted(log_dir.rglob("s26_kernel_vuln_verifier")):
        if cand.is_dir():
            return cand
    return None


# ---------------------------------------------------------------------------
# VEX parsing helpers
# ---------------------------------------------------------------------------
def _load_vex(path: Path) -> list[dict]:
    """Return the list of vulnerability objects from a CycloneDX VEX file.

    EMBA sometimes writes a bare fragment (no outer braces); tolerate both.
    """
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        print(f"[!] WARNING: cannot read {path}: {e}", file=sys.stderr)
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        try:
            data = json.loads("{" + raw.strip().rstrip(",") + "}")
        except json.JSONDecodeError as e:
            print(f"[!] WARNING: {path.name} is not valid JSON, skipping: {e}", file=sys.stderr)
            return []
    if isinstance(data, dict):
        vs = data.get("vulnerabilities", [])
    elif isinstance(data, list):
        vs = data
    else:
        vs = []
    return [v for v in vs if isinstance(v, dict)]


def _cvss_version(vector: str, method: str) -> str:
    m = re.search(r"CVSS:(\d)(?:\.)?(\d+)?", vector or "")
    if m:
        return f"{m.group(1)}.{m.group(2) or '0'}"
    m2 = re.search(r"CVSSv?(\d)", method or "")
    return f"{m2.group(1)}.0" if m2 else ""


def _parse_vector(vector: str) -> dict:
    """Pull the fields we categorize on out of a CVSS v2/v3/v4 vector string.
    Tolerant of the malformed 'CVSS:31/...' EMBA writes for NVD entries."""
    v = vector or ""

    def tok(pat: str) -> str:
        m = re.search(pat, v)
        return m.group(1).upper() if m else ""

    av = tok(r"AV:([NALP])")
    ac = tok(r"AC:([LHM])")
    pr = tok(r"PR:([NLH])")
    ui = tok(r"UI:([NR])")
    # impact metrics are slash-delimited single letters; anchor so AC:'s C
    # is not mistaken for the confidentiality metric
    ci = tok(r"(?:^|/)C:([NLPCH])")
    ii = tok(r"(?:^|/)I:([NLPCH])")
    ai = tok(r"(?:^|/)A:([NLPCH])")
    return {
        "av": _AV_NAME.get(av, "Unknown"),
        "ac": _AC_NAME.get(ac, ""),
        "pr": _PR_NAME.get(pr, ""),
        "ui": _UI_NAME.get(ui, ""),
        "impact": {
            "c": _IMPACT_NAME.get(ci, ""),
            "i": _IMPACT_NAME.get(ii, ""),
            "a": _IMPACT_NAME.get(ai, ""),
        },
    }


def _severity(score: float | None, given: str) -> str:
    g = (given or "").strip().lower()
    if g in ("critical", "high", "medium", "low", "none"):
        return "unknown" if g == "none" else g
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "unknown"


def _rating(v: dict) -> tuple[float | None, str, str, str]:
    """Return (score, severity_hint, vector, method) from the best rating."""
    best = None
    for r in v.get("ratings") or []:
        if not isinstance(r, dict):
            continue
        if best is None or (r.get("score") or 0) >= (best.get("score") or 0):
            best = r
    if not best:
        return None, "", "", ""
    score = best.get("score")
    try:
        score = float(score) if score is not None else None
    except (TypeError, ValueError):
        score = None
    return score, str(best.get("severity") or ""), str(best.get("vector") or ""), str(best.get("method") or "")


def _exploits(v: dict) -> list[str]:
    out: list[str] = []
    for p in v.get("properties") or []:
        if isinstance(p, dict) and ":exploit" in str(p.get("name", "")):
            val = str(p.get("value", "")).strip().strip("'\"").strip()
            if val:
                out.append(val)
    # stable, de-duplicated
    seen: set[str] = set()
    uniq = []
    for x in out:
        if x not in seen:
            seen.add(x)
            uniq.append(x)
    return uniq


def _exploit_tier(sources: list[str]) -> str:
    prefixes = {s.split(":", 1)[0].upper() for s in sources}
    if prefixes & _EXPLOIT_WEAPONIZED:
        return "weaponized"
    if prefixes & _EXPLOIT_POC:
        return "poc"
    if prefixes & _EXPLOIT_REFERENCE:
        return "reference"
    return "reference" if sources else ""


def _cwes(v: dict) -> list[int]:
    out = []
    for c in v.get("cwes") or []:
        try:
            out.append(int(c))
        except (TypeError, ValueError):
            continue
    return out


def _components(v: dict) -> list[tuple[str, str]]:
    """(component, version) pairs this vuln affects."""
    pairs = []
    for a in v.get("affects") or []:
        if not isinstance(a, dict):
            continue
        for ver in a.get("versions") or []:
            if isinstance(ver, dict):
                pairs.append((str(ver.get("component") or "").strip(),
                              str(ver.get("version") or "").strip()))
    return pairs or [("", "")]


# ---------------------------------------------------------------------------
# S26 side channels
# ---------------------------------------------------------------------------
def _kev_set(s26: Path | None) -> set[str]:
    if not s26:
        return set()
    f = s26 / "KEV.txt"
    if not f.is_file():
        return set()
    txt = f.read_text(encoding="utf-8", errors="replace")
    return {m.upper() for m in re.findall(r"CVE-\d{4}-\d{3,}", txt, re.IGNORECASE)}


def _verified_map(s26: Path | None) -> dict[str, str]:
    """CVE id -> 'symbols' | 'compile' from cve_results_kernel_*.csv."""
    out: dict[str, str] = {}
    if not s26:
        return out
    for csv_path in s26.glob("cve_results_kernel_*.csv"):
        try:
            rows = list(csv.reader(csv_path.open(encoding="utf-8", errors="replace"), delimiter=";"))
        except OSError:
            continue
        for row in rows[1:]:
            # Kernel version;Architecture;CVE;CVSSv2;CVSSv3;Verified with symbols;Verified with compile files
            if len(row) < 7:
                continue
            cve = row[2].strip().upper()
            if not _CVE_ID_RE.match(cve):
                continue
            sym = row[5].strip() not in ("", "0", "NA")
            comp = row[6].strip() not in ("", "0", "NA")
            if sym:
                out[cve] = "symbols"
            elif comp:
                out.setdefault(cve, "compile")
    return out


# ---------------------------------------------------------------------------
# Record building
# ---------------------------------------------------------------------------
def _record(v: dict, component: str, version: str, source_module: str,
            kev: set[str], verified: dict[str, str]) -> dict | None:
    cve = str(v.get("id") or "").strip().upper()
    if not _CVE_ID_RE.match(cve):
        return None

    score, sev_hint, vector, method = _rating(v)
    parts = _parse_vector(vector)
    sev = _severity(score, sev_hint)
    exsrc = _exploits(v)
    is_kev = cve in kev
    has_exploit = bool(exsrc)

    is_kernel = source_module == "S26" or component.lower() in _KERNEL_COMPONENTS
    hidden = False
    if is_kernel:
        hidden = not (sev in ("high", "critical")
                      or (score is not None and score >= 7.0)
                      or is_kev or has_exploit)

    return {
        "cve": cve,
        "component": component or "unknown",
        "version": version,
        "source_module": source_module,
        "cvss_score": score,
        "cvss_version": _cvss_version(vector, method),
        "severity": sev,
        "cvss_vector": vector,
        "av": parts["av"],
        "ac": parts["ac"],
        "pr": parts["pr"],
        "ui": parts["ui"],
        "impact": parts["impact"],
        "cwe": _cwes(v),
        "description": str(v.get("description") or "").strip(),
        "has_exploit": has_exploit,
        "exploit_sources": exsrc,
        "exploit_tier": _exploit_tier(exsrc),
        "kev": is_kev,
        "verified": verified.get(cve, ""),
        "default_hidden": hidden,
    }


def parse_component_cves(log_dir: Path, kev: set[str], verified: dict[str, str]) -> list[dict]:
    vex = _find_vex(log_dir)
    if not vex:
        return []
    print(f"[+] component CVEs  : {vex}")
    out = []
    for v in _load_vex(vex):
        for comp, ver in _components(v):
            if comp.lower() in _KERNEL_COMPONENTS:
                continue  # kernel comes from S26
            rec = _record(v, comp, ver, "F17", kev, verified)
            if rec:
                out.append(rec)
    return out


def parse_kernel_cves(log_dir: Path, kev: set[str], verified: dict[str, str]) -> list[dict]:
    s26 = _s26_dir(log_dir)
    out = []
    if s26 and (s26 / "json").is_dir():
        files = sorted(glob.glob(str(s26 / "json" / "*.json")))
        print(f"[+] kernel CVEs     : {s26 / 'json'} ({len(files)} files)")
        for fn in files:
            try:
                v = json.loads(Path(fn).read_text(encoding="utf-8", errors="replace"))
            except (json.JSONDecodeError, OSError):
                continue
            if not isinstance(v, dict):
                continue
            comps = _components(v)
            comp, ver = comps[0]
            rec = _record(v, comp or "linux_kernel", ver, "S26", kev, verified)
            if rec:
                out.append(rec)
        return out

    # fallback: the kernel entries inside the main VEX (usually just a few)
    vex = _find_vex(log_dir)
    if vex:
        print(f"[+] kernel CVEs     : {vex} (S26 not run - using VEX kernel entries)")
        for v in _load_vex(vex):
            for comp, ver in _components(v):
                if comp.lower() not in _KERNEL_COMPONENTS:
                    continue
                rec = _record(v, comp, ver, "F17", kev, verified)
                if rec:
                    out.append(rec)
    return out


def _dedup(records: list[dict]) -> list[dict]:
    """One record per (cve, component). S26 (kernel-verified) beats F17."""
    by_key: dict[tuple[str, str], dict] = {}
    for r in records:
        key = (r["cve"], r["component"].lower())
        cur = by_key.get(key)
        if cur is None:
            by_key[key] = r
            continue
        if cur["source_module"] == "S26" and r["source_module"] != "S26":
            continue
        if r["source_module"] == "S26" and cur["source_module"] != "S26":
            by_key[key] = r
            continue
        # same source: keep the richer one (has exploit / description)
        if (bool(r["exploit_sources"]), len(r["description"])) > \
           (bool(cur["exploit_sources"]), len(cur["description"])):
            by_key[key] = r
    return list(by_key.values())


def collect(log_dir: Path) -> list[dict]:
    s26 = _s26_dir(log_dir)
    kev = _kev_set(s26)
    verified = _verified_map(s26)

    records = parse_component_cves(log_dir, kev, verified) + parse_kernel_cves(log_dir, kev, verified)
    records = _dedup(records)

    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
    records.sort(key=lambda r: (
        not r["kev"],
        not r["has_exploit"],
        sev_rank.get(r["severity"], 5),
        -(r["cvss_score"] or 0),
        r["cve"],
    ))
    return records


def _summary(records: list[dict]) -> None:
    if not records:
        print("[!] No CVE data found. EMBA's F15/F17 (SBOM + cve-bin-tool) and S26 "
              "(kernel) modules produce it - they may have been skipped, or the NVD "
              "database was not downloaded (no internet on the EMBA host).")
        return
    visible = [r for r in records if not r["default_hidden"]]
    from collections import Counter
    av = Counter(r["av"] for r in records)
    sev = Counter(r["severity"] for r in records)
    print(f"[+] CVE findings    : {len(records)} ({len(visible)} shown by default, "
          f"{len(records) - len(visible)} lower-severity kernel CVEs hidden)")
    print(f"      attack vector : " + ", ".join(f"{k}={c}" for k, c in av.most_common()))
    print(f"      severity      : " + ", ".join(f"{k}={c}" for k, c in sev.most_common()))
    print(f"      with exploit  : {sum(1 for r in records if r['has_exploit'])}")
    print(f"      KEV (known-exploited): {sum(1 for r in records if r['kev'])}")
    print(f"      kernel-verified: {sum(1 for r in records if r['verified'])}")


def main():
    ap = argparse.ArgumentParser(
        description="LAVA CVE module - structures EMBA's F17/S26 CVE output (no AI, no external DB).")
    ap.add_argument("--log-dir", required=True, help="EMBA log directory")
    ap.add_argument("--out", default="cve_findings.json")
    args = ap.parse_args()

    log_dir = Path(args.log_dir)
    if not log_dir.is_dir():
        print(f"[!] ERROR: not a directory: {log_dir}")
        sys.exit(1)

    records = collect(log_dir)
    Path(args.out).write_text(json.dumps(records, indent=2, ensure_ascii=False), encoding="utf-8")
    _summary(records)
    print(f"[+] Output: {args.out}")


if __name__ == "__main__":
    main()
