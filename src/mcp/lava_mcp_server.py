#!/usr/bin/env python3
"""
LAVA - MCP Server (agentic AI provider)
======================================
Bu sunucu, LAVA'nin ucuncu AI provider modudur. Local (Ollama) ve Cloud
(Gemini) modlarinda `classifier.py` LLM'e hazir bir prompt paketi verirken,
MCP modunda LLM (Claude Code / Claude Desktop / Antigravity CLI) **aktif bir
ajan** olarak baglanir: EMBA log dizinini kendi tool cagrilariyla kesfeder,
gereken dosyalari kendi karariyla okur ve verdict'lerini yine tool cagrisiyla
LAVA'ya geri yazar.

Cikti (`verdicts.json`) semasi local/Gemini modlariyla BIREBIR aynidir; bu
sunucu semayi `src/core/parser.py`'nin urettigi merged-findings kaydindan
turetir (parser degistirilmez, sadece kutuphane olarak import edilir).

stdio transport ile calisir:

    python src/mcp/lava_mcp_server.py --log-dir /path/to/emba_log \\
        --fw-root /path/to/extracted_fw [--verdicts-out /path/to/verdicts.json]

Tum dosya-okuma tool'lari path-sandbox'lidir: `--log-dir` / `--fw-root`
disina cikan her istek reddedilir.
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

# --- parser.py'yi (degistirmeden) kutuphane olarak yukle --------------------
_CORE_DIR = Path(__file__).resolve().parents[1] / "core"
if str(_CORE_DIR) not in sys.path:
    sys.path.insert(0, str(_CORE_DIR))
import parser as emba_parser  # noqa: E402  (src/core/parser.py)


# ---------------------------------------------------------------------------
# Global yapilandirma (CLI argumanlariyla doldurulur)
# ---------------------------------------------------------------------------
class ServerConfig:
    log_dir: Path = Path(".")
    fw_root: Path = Path(".")
    verdicts_out: Path = Path("verdicts.json")


CFG = ServerConfig()

# finding_id -> merged finding kaydi
REGISTRY: dict[str, dict] = {}

_TEXT_MAX_SCAN_BYTES = 2_000_000  # search/grep sirasinda tek dosyada taranacak ust sinir
_SEARCH_RESULT_CAP = 300


def log(msg: str) -> None:
    """stdio transport stdout'u kullandigi icin TUM loglar stderr'e gider."""
    print(f"[lava-mcp] {msg}", file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------
# Path sandbox
# ---------------------------------------------------------------------------
def _safe_resolve(root: Path, user_path: str) -> Path:
    """user_path'i root altinda cozer. root disina cikan her sey ValueError.

    `os.path.realpath` ile normalize edilir (symlink + '..' dahil)."""
    root_real = Path(os.path.realpath(root))
    raw = (user_path or "").strip().replace("\\", "/")
    # Mutlak/surucu-koklu girdileri her zaman root'a goreli kabul et
    raw = raw.lstrip("/")
    raw = re.sub(r"^[A-Za-z]:/", "", raw)
    candidate = Path(os.path.realpath(root_real / raw))
    if candidate != root_real and root_real not in candidate.parents:
        raise ValueError(
            f"Path '{user_path}' sandbox disinda ({root_real} altinda kalmali). Reddedildi."
        )
    return candidate


def _read_text_capped(path: Path, max_bytes: int) -> str:
    data = path.read_bytes()
    truncated = len(data) > max_bytes
    text = data[:max_bytes].decode("utf-8", errors="replace")
    if truncated:
        text += f"\n\n... [TRUNCATED - dosyanin ilk {max_bytes} byte'i gosterildi, toplam {len(data)} byte]"
    return text


def _looks_binary(path: Path, sniff: int = 1024) -> bool:
    try:
        with open(path, "rb") as f:
            return b"\x00" in f.read(sniff)
    except OSError:
        return True


# ---------------------------------------------------------------------------
# Finding registry (verdicts.json semasinin kaynagi)
# ---------------------------------------------------------------------------
def _finding_id(file_path: str, matched_content: str) -> str:
    h = hashlib.sha1(f"{file_path}|{matched_content}".encode("utf-8", "replace")).hexdigest()
    return f"lava_{h[:12]}"


def build_registry(log_dir: Path) -> dict[str, dict]:
    """parser.py'nin merge_and_corroborate ciktisindan finding registry kurar.
    Bu, MCP modunda uretilecek verdicts.json'un dosya-adi/tip semasini
    local/Gemini moduyla birebir ayni tutar."""
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
    except Exception as e:  # noqa: BLE001 - registry bos kalirsa tool'lar yine de aciklayici hata doner
        log(f"UYARI: registry kurulurken hata: {e!r}")
        return reg

    merged = emba_parser.merge_and_corroborate(all_findings)
    for m in merged:
        fid = _finding_id(m["file_path"], m["matched_content"])
        reg[fid] = {
            "finding_id": fid,
            "file_path": m["file_path"],
            "matched_content": m["matched_content"],
            "found_by_modules": m["found_by_modules"],
            "corroboration_count": m["corroboration_count"],
        }
    return reg


# ---------------------------------------------------------------------------
# verdicts.json yazimi  (classifier.py run-modu semasiyla birebir)
# ---------------------------------------------------------------------------
def _atomic_write_json(data: Any, path: Path) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.parent.mkdir(parents=True, exist_ok=True)
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, path)


def write_findings_snapshot() -> None:
    """MCP modunda parser.py/enricher.py ayri adim olarak KOSMAZ. Dashboard'un
    'toplam bulgu' sayaci enriched_findings.json'u okudugu icin, registry'yi
    verdicts.json'in yanina bu isimle bir kez dokuyoruz (context alani MCP
    modunda ajan tarafindan tool'larla toplandigi icin burada yer tutucudur)."""
    if not REGISTRY:
        return
    snapshot = [
        {**rec, "context": {"status": "mcp_agent_mode"}}
        for rec in REGISTRY.values()
    ]
    try:
        _atomic_write_json(snapshot, CFG.verdicts_out.parent / "enriched_findings.json")
    except OSError as e:
        log(f"UYARI: enriched_findings.json yazilamadi: {e}")


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
    """local/Gemini modundaki run_full_mode ile ALAN-ALAN ayni obje."""
    return {
        "file_path": finding["file_path"],
        "matched_content": finding["matched_content"],
        "found_by_modules": finding["found_by_modules"],
        "corroboration_count": finding["corroboration_count"],
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
    raise ValueError(f"verdict 'TP' veya 'FP' olmali, alinan: {verdict!r}")


def _clamp_conf(confidence: float) -> float:
    try:
        c = float(confidence)
    except (TypeError, ValueError):
        return 0.0
    if c > 1.0:  # 80 -> 0.80 gibi
        c = c / 100.0
    return max(0.0, min(1.0, round(c, 4)))


def _write_verdicts(new_records: dict[str, dict]) -> None:
    """new_records: finding_id -> verdict_record. Registry sirasina gore yazar,
    mevcut dosyadaki (registry disi) kayitlari korur."""
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
    for key, rec in by_key.items():  # registry disi artiklar
        if key not in seen:
            ordered.append(rec)
    _atomic_write_json(ordered, CFG.verdicts_out)


# ---------------------------------------------------------------------------
# MCP sunucusu ve tool'lar
# ---------------------------------------------------------------------------
mcp = FastMCP("lava")


@mcp.tool()
def list_findings() -> list[dict]:
    """EMBA'nin bu firmware icin bildirdigi TUM hardcoded-credential bulgularini
    (finding_id ile birlikte) doner. Kesfin baslangic noktasi: her finding_id
    icin sonunda submit_verdict / submit_all_verdicts cagrilmalidir.

    Doner: [{finding_id, file_path, matched_content, found_by_modules,
             corroboration_count}]"""
    return list(REGISTRY.values())


@mcp.tool()
def get_hardcoded_keys_module_output() -> str:
    """EMBA'nin hardcoded-credential modullerinin (S45 pass_file_check,
    S106 deep_key_search, S107 deep_password_search, S108 stacs_password_search,
    S99 grepit cryptocred) HAM cikti loglarini dogrudan doner. Kesfe buradan
    baslayip gerekiyorsa diger tool'larla derinlesin."""
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
        return (f"Bu log dizininde ({ld}) taninan hardcoded-credential modul ciktisi bulunamadi. "
                "list_log_files ile dizin yapisini inceleyin.")
    return "\n\n".join(chunks)


@mcp.tool()
def list_log_files(subdir: str = "") -> list[str]:
    """EMBA log dizinindeki (--log-dir) dosya ve klasorleri listeler. `subdir`
    verilirse o alt dizinin icerigi listelenir. Klasorler sonuna '/' eklenir.
    Sandbox: sadece --log-dir altinda kalir."""
    try:
        base = _safe_resolve(CFG.log_dir, subdir)
    except ValueError as e:
        return [f"[hata] {e}"]
    if not base.exists():
        return [f"[hata] yol yok: {subdir}"]
    if base.is_file():
        return [subdir]
    out: list[str] = []
    for p in sorted(base.iterdir()):
        rel = p.relative_to(Path(os.path.realpath(CFG.log_dir))).as_posix()
        out.append(rel + "/" if p.is_dir() else rel)
    return out or ["[bos dizin]"]


@mcp.tool()
def read_log_file(path: str, max_bytes: int = 20000) -> str:
    """--log-dir altindaki bir log dosyasini okur. Buyuk dosyalar kesilir ve
    TRUNCATED uyarisi eklenir. Sandbox: sadece --log-dir altinda."""
    try:
        p = _safe_resolve(CFG.log_dir, path)
    except ValueError as e:
        return f"[hata] {e}"
    if not p.exists() or not p.is_file():
        return f"[hata] dosya yok: {path}"
    return _read_text_capped(p, max(1000, int(max_bytes)))


@mcp.tool()
def read_firmware_file(path: str, max_bytes: int = 20000) -> str:
    """EMBA'nin extract ettigi firmware filesystem'inden (--fw-root) dosya okur.
    Hardcoded credential'in gercekten kullanilip kullanilmadigini dogrulamak
    icin kullanin (init script'leri, config dosyalari vb.). Sandbox: sadece
    --fw-root altinda."""
    try:
        p = _safe_resolve(CFG.fw_root, path)
    except ValueError as e:
        return f"[hata] {e}"
    if not p.exists() or not p.is_file():
        return f"[hata] dosya yok: {path} (--fw-root altinda aranir)"
    if _looks_binary(p):
        return f"[bilgi] '{path}' binary gorunuyor (null byte iceriyor); text context anlamsiz."
    return _read_text_capped(p, max(1000, int(max_bytes)))


@mcp.tool()
def search_log_content(pattern: str, subdir: str = "") -> list[dict]:
    """--log-dir icinde grep benzeri arama. Once regex olarak derlenir; gecersiz
    regex ise otomatik olarak re.escape ile literal aramaya duser. Doner:
    [{file, line_no, line, regex}] (en fazla 300 sonuc). Sandbox: --log-dir."""
    try:
        base = _safe_resolve(CFG.log_dir, subdir)
    except ValueError as e:
        return [{"error": str(e)}]
    if not base.exists():
        return [{"error": f"yol yok: {subdir}"}]
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
                            results.append({"note": f"sonuclar {_SEARCH_RESULT_CAP} ile sinirlandi"})
                            return results
        except OSError:
            continue
    return results or [{"note": "eslesme yok", "regex": used_regex}]


class VerdictIn(BaseModel):
    finding_id: str = Field(description="list_findings'ten alinan finding_id")
    verdict: str = Field(description="'TP' (True Positive) veya 'FP' (False Positive)")
    confidence: float = Field(description="0.0 - 1.0 arasi guven skoru")
    reasoning: str = Field(description="1-2 cumlelik KISA INGILIZCE gerekce")


def _submit_one(v: VerdictIn, sink: dict[str, dict]) -> str:
    finding = REGISTRY.get(v.finding_id)
    if finding is None:
        valid = ", ".join(list(REGISTRY)[:8])
        return (f"[hata] bilinmeyen finding_id: {v.finding_id!r}. "
                f"list_findings ile gecerli id'leri alin (orn: {valid} ...)")
    verdict = _normalize_verdict(v.verdict)
    rec = _verdict_record(finding, verdict, _clamp_conf(v.confidence), str(v.reasoning).strip())
    sink[v.finding_id] = rec
    return f"[ok] {v.finding_id} -> {verdict} (conf={rec['confidence']})"


@mcp.tool()
def submit_verdict(finding_id: str, verdict: str, confidence: float, reasoning: str) -> str:
    """Tek bir bulgu icin verdict'i verdicts.json'a yazar (local/Gemini moduyla
    ayni sema, ayni dosya, atomik). verdict='TP'|'FP', confidence=0.0-1.0,
    reasoning=kisa Ingilizce gerekce."""
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
    """Tum bulgular icin verdict'leri TEK seferde yazar (tercih edilen yontem).
    Her ogesi {finding_id, verdict, confidence, reasoning}. verdicts.json
    local/Gemini moduyla birebir ayni semada yazilir."""
    sink: dict[str, dict] = {}
    lines: list[str] = []
    for v in verdicts:
        lines.append(_submit_one(v, sink))
    if sink:
        _write_verdicts(sink)

    submitted = set(sink)
    missing = [fid for fid in REGISTRY if fid not in submitted]
    summary = [f"[yazildi] {len(sink)} verdict -> {CFG.verdicts_out}"]
    if missing:
        summary.append(f"[uyari] verdict verilmeyen {len(missing)} finding_id: "
                       + ", ".join(missing[:20]) + (" ..." if len(missing) > 20 else ""))
    else:
        summary.append("[tamam] tum finding_id'ler icin verdict yazildi.")
    return "\n".join(summary + lines)


# ---------------------------------------------------------------------------
def main() -> None:
    ap = argparse.ArgumentParser(description="LAVA MCP sunucusu (agentic AI provider, stdio transport)")
    ap.add_argument("--log-dir", required=True, help="EMBA log dizini")
    ap.add_argument("--fw-root", required=True, help="EMBA'nin extract ettigi firmware filesystem koku")
    ap.add_argument("--verdicts-out", default=None,
                    help="verdicts.json cikti yolu (varsayilan: <cwd>/verdicts.json)")
    args = ap.parse_args()

    CFG.log_dir = Path(args.log_dir).expanduser().resolve()
    CFG.fw_root = Path(args.fw_root).expanduser().resolve()
    CFG.verdicts_out = (Path(args.verdicts_out).expanduser().resolve() if args.verdicts_out
                        else Path.cwd() / "verdicts.json")

    if not CFG.log_dir.is_dir():
        log(f"UYARI: --log-dir mevcut degil: {CFG.log_dir}")
    if not CFG.fw_root.exists():
        log(f"UYARI: --fw-root mevcut degil: {CFG.fw_root}")

    REGISTRY.clear()
    REGISTRY.update(build_registry(CFG.log_dir))
    write_findings_snapshot()
    log(f"registry: {len(REGISTRY)} finding | log-dir={CFG.log_dir} | fw-root={CFG.fw_root} "
        f"| verdicts-out={CFG.verdicts_out}")

    mcp.run()  # stdio transport (varsayilan)


if __name__ == "__main__":
    main()
