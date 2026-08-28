#!/usr/bin/env python3
"""
LAVA - LLM Classifier
=======================
enriched_findings.json (veya ground_truth.json'daki test_set) icindeki her
hardcoded-credential bulgusunu, yerel bir LocalAI sunucusuna sorup TP/FP
olarak siniflandirir.

Iki mod:
  test  -> ground_truth.json'daki test_set'i calistirir, gercek etiketlerle
           karsilastirip accuracy/precision/recall raporlar.
  run   -> enriched_findings.json'daki TUM bulgular icin verdict uretir,
           karsilastirma yapmaz (gercek etiket yok).

Kullanim:
    # Test modu - cevap anahtarina karsi olculur
    python3 llm_classifier.py --mode test --config config/ai_config.env \\
        --ground-truth ground_truth.json --out verdicts_test.json

    # Run modu - gercek pipeline
    python3 llm_classifier.py --mode run --config config/ai_config.env \\
        --enriched enriched_findings.json --out verdicts.json
"""

import os
import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import requests

# MCP (agentic) provider modu icin sabitler
# --------------------------------------------------------------------------
# Ajan (claude / agy) headless kosumunun ust sinir suresi. Asilirsa subprocess
# sonlandirilip hata olarak raporlanir (sonsuz bekleme riski yok).
AGENT_TIMEOUT_SECONDS = int(os.environ.get("LAVA_AGENT_TIMEOUT_SECONDS", str(60 * 60)))
MCP_SERVER_PATH = Path(__file__).resolve().parents[2] / "src" / "mcp" / "lava_mcp_server.py"
# verdicts.json'da bulunmasi ZORUNLU alanlar (local/Gemini run-modu semasi)
_VERDICT_REQUIRED_FIELDS = {
    "file_path", "matched_content", "predicted_verdict", "confidence", "model_reasoning",
}

def atomic_save(data: dict | list, file_path: str):
    path = Path(file_path)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp_path, path)

# ---------------------------------------------------------------------------
# Modele hatirlatma amacli sabit bilgi notu - kucuk modellerin hash format
# prefixlerini karistirmamasi icin. EMBA'nin S107/S108 ciktilarinda gordugumuz
# tum formatlar burada.
# ---------------------------------------------------------------------------
HASH_CHEATSHEET = """\
Known crypt() hash format prefixes (these are REAL, working hashes, strong TP signal):
  $1$  -> MD5-crypt
  $5$  -> SHA-256-crypt
  $6$  -> SHA-512-crypt
  $2a$/$2b$/$2y$ -> bcrypt
If a line in /etc/passwd or /etc/shadow contains one of these prefixes and has the correct
number of fields (user:hash:lastchg:min:max:warn:inactive:expire), it is generally a real TP."""

SYSTEM_PROMPT_TEMPLATE = """You are a firmware security analyst. Your task is to review "hardcoded \
credential/secret" candidates found by the EMBA firmware analysis tool and decide whether each one \
is a REAL credential leak (TP - True Positive) or a false alarm (FP - False Positive).

{hash_cheatsheet}

When evaluating, pay attention to:
- The file path (is it a config file, a binary/library, a script, or UI code?)
- Whether the matched content is an ACTUAL value, or just a variable name/definition/comment/UI label
- How many different EMBA modules independently confirmed the same finding (corroboration_count) - higher means a stronger TP signal
- The provided file context (context_lines) - the code/config surrounding the matched line

CRITICAL RULES:
1. If the "matched content" is not a concrete value but a GENERIC module message
   (e.g. "flagged as password-related file" - this is a file classification flag,
   NOT the file's actual content), this alone does NOT count as TP evidence. In this case,
   decide based on the PROVIDED CONTEXT: if you see an actual hash/password VALUE in the
   context, say TP; if not (e.g. all lines contain 'x' or '*' placeholders, or no context
   was found at all), say FP.
2. If the matched code reads from a VARIABLE or is CONDITIONAL provisioning/script logic
   (e.g. "json_get_vars root_password_hash", "sed -i ... /etc/shadow", code that reads a
   value from a config file and applies it if present), this is NOT itself a hardcoded
   credential - the script is merely APPLYING a value coming from another source (board.json,
   config). This is generally FP, because the actual value is not in this file, but in the
   source the script reads from.
3. If the context shows "exact_match_located: false", remember that this context was taken
   from the BEGINNING of the file and does not represent the actual matched line - evaluate
   more cautiously accordingly, and do not say TP just by trusting the file name.
4. If the matched content is in /etc/passwd or /etc/shadow format (e.g. "root:x:0:0...")
   but does NOT contain an actual cryptographic hash starting with $1$, $5$, $6$, $2a$, etc.,
   this is DEFINITELY an FP. Characters like 'x' or '*' are merely placeholders and are NOT
   hashes. Only lines containing an actual, long hash are TP.
5. A private key found in firmware (RSA/EC/DSA, in "-----BEGIN ... PRIVATE KEY-----" format)
   should be treated as TP BY DEFAULT - the fact that the key has a valid/real cryptographic
   format is evidence THAT it is genuine cryptographic material, not evidence that it is safe.
   The only thing that makes a private key FP is CONCRETE evidence that it is explicitly a
   test/example/documentation key (e.g. an OBVIOUS marker such as "example", "test", "sample",
   "dummy" in the file name/path, AND it must be clearly part of the vendor's own build process -
   the "-----BEGIN ... PRIVATE KEY-----" format alone can NEVER be used as FP justification).
   When in doubt, say TP.

Below are examples. Learn from them, then evaluate the NEW finding given to you.

{few_shot_block}

VERY IMPORTANT RULES:
1. Write the "reasoning" field STRICTLY AND ONLY IN ENGLISH.
2. Respond ONLY in the following JSON format, with no other text:
{{"verdict": "TP" or "FP", "confidence": a number between 0.0-1.0, "reasoning": "1-2 sentence short ENGLISH reasoning"}}
"""

FEW_SHOT_ITEM_TEMPLATE = """### Example {n}
File: {file_path}
Module: {module}
Matched content: {matched_content}
Correct answer: {{"verdict": "{verdict}", "confidence": 0.99, "reasoning": "{reasoning}"}}
"""

USER_PROMPT_TEMPLATE = """Now evaluate this finding:

File: {file_path}
Module: {module}
Number of modules that confirmed this (corroboration_count): {corroboration_count}
Matched content: {matched_content}
{context_block}
Respond only in the requested JSON format."""


# ---------------------------------------------------------------------------
# Config okuma - EMBA'nin config/ai_config.env formatiyla aynen uyumlu
# (KEY="value" seklinde bash env satirlari)
# ---------------------------------------------------------------------------
def load_ai_config(config_path: Path) -> dict:
    config = {
        "AI_PROVIDER": "local",
        "GEMINI_API_KEY": "",
        "LOCAL_AI_IP": "127.0.0.1",
        "LOCAL_AI_MODEL": "",
        "AI_MAX_CHARS_TO_ANALYSE": "5000",
        "LOCAL_AI_PORT": "11434",
    }
    if not config_path.exists():
        return config
    line_re = re.compile(r'^\s*([A-Z_]+)\s*=\s*"?([^"\n]*)"?\s*$')
    for line in config_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = line_re.match(line)
        if m:
            config[m.group(1)] = m.group(2)
    return config


# ---------------------------------------------------------------------------
# Prompt insasi
# ---------------------------------------------------------------------------
def format_context_block(context: dict | None, max_chars: int) -> str:
    if not context or context.get("status") != "ok":
        status = (context or {}).get("status", "context_yok")
        return f"Dosya baglami: mevcut degil ({status})\n"
    lines = context["context_lines"]
    idx = context.get("matched_line_index_in_context")
    exact = context.get("exact_match_located", idx is not None)
    rendered = []
    for i, ln in enumerate(lines):
        marker = ">>> " if (exact and i == idx) else "    "
        rendered.append(f"{marker}{ln}")
    block = "\n".join(rendered)
    if len(block) > max_chars:
        block = block[:max_chars] + "\n... (kirpildi)"
    note = "" if exact else "\n[NOT: eslesen satir tam olarak bulunamadi, bu dosyanin BASINDAN bir ornek - '>>>' isareti YOK, kendi kararini icerige bakarak ver]"
    return f"Dosya baglami{' (>>> = eslesen satir)' if exact else ''}:{note}\n{block}\n"


def build_few_shot_block(few_shot_items: list[dict]) -> str:
    parts = []
    for i, item in enumerate(few_shot_items, start=1):
        parts.append(
            FEW_SHOT_ITEM_TEMPLATE.format(
                n=i,
                file_path=item["file_path"],
                module=item["module"],
                matched_content=item["matched_content"],
                verdict=item["verdict"],
                reasoning=item.get("reasoning", ""),
            )
        )
    return "\n".join(parts)


def build_system_prompt(few_shot_items: list[dict]) -> str:
    return SYSTEM_PROMPT_TEMPLATE.format(
        hash_cheatsheet=HASH_CHEATSHEET,
        few_shot_block=build_few_shot_block(few_shot_items),
    )


def build_user_prompt(item: dict, max_chars: int) -> str:
    return USER_PROMPT_TEMPLATE.format(
        file_path=item["file_path"],
        module=item.get("module", "?"),
        corroboration_count=item.get("corroboration_count", "?"),
        matched_content=item["matched_content"][:max_chars],
        context_block=format_context_block(item.get("context"), max_chars),
    )


# ---------------------------------------------------------------------------
# LocalAI cagrisi - Q03_localai_connector.sh'daki curl cagrisiyla ayni
# endpoint/format (OpenAI-uyumlu /v1/chat/completions)
# ---------------------------------------------------------------------------
def call_localai(base_url: str, model: str, system_prompt: str, user_prompt: str, timeout: int = 600) -> str | None:
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.2,
    }
    try:
        resp = requests.post(
            f"{base_url}/v1/chat/completions",
            json=payload,
            timeout=timeout,
            headers={"Content-Type": "application/json"},
        )
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"]
    except (requests.RequestException, KeyError, IndexError, ValueError) as e:
        print(f"    [!] LocalAI cagri hatasi: {e}")
        return None

class RateLimitException(Exception):
    def __init__(self, delay):
        self.delay = delay
        super().__init__(f"Rate limit asildi, {delay} saniye beklenmeli.")

def call_gemini(api_key: str, system_prompt: str, user_prompt: str, timeout: int = 60) -> str | None:
    if not api_key:
        print("    [!] Gemini API anahtari (GEMINI_API_KEY) eksik!")
        return None
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-3.6-flash:generateContent?key={api_key}"
    payload = {
        "system_instruction": {
            "parts": [{"text": system_prompt}]
        },
        "contents": [{
            "parts": [{"text": user_prompt}]
        }],
        "generationConfig": {
            "temperature": 0.2,
            "responseMimeType": "application/json"
        }
    }
    try:
        resp = requests.post(url, json=payload, timeout=timeout, headers={"Content-Type": "application/json"})
        if resp.status_code == 429:
            delay = 15.0
            try:
                data = resp.json()
                for detail in data.get("error", {}).get("details", []):
                    if "retryDelay" in detail:
                        delay = float(detail["retryDelay"].replace("s", "")) + 1.0
            except Exception:
                pass
            raise RateLimitException(delay)
            
        resp.raise_for_status()
        data = resp.json()
        if "candidates" in data and len(data["candidates"]) > 0:
            return data["candidates"][0]["content"]["parts"][0]["text"]
        return None
    except requests.RequestException as e:
        error_msg = ""
        if hasattr(e, "response") and e.response is not None:
            error_msg = f" API Yaniti: {e.response.text}"
        print(f"    [!] Gemini ag hatasi: {e}{error_msg}")
        return None
    except (KeyError, IndexError, ValueError) as e:
        print(f"    [!] Gemini veri hatasi: {e}")
        return None

_JSON_BLOCK_RE = re.compile(r"\{.*\}", re.DOTALL)


def parse_verdict_response(raw_text: str) -> dict | None:
    if not raw_text:
        return None
    m = _JSON_BLOCK_RE.search(raw_text)
    if not m:
        return None
    try:
        parsed = json.loads(m.group(0))
    except json.JSONDecodeError:
        return None
    verdict = str(parsed.get("verdict", "")).strip().upper()
    if verdict not in ("TP", "FP"):
        return None
        
    conf_raw = parsed.get("confidence")
    conf = 0.0
    if conf_raw is not None:
        try:
            conf_val = float(conf_raw)
            if conf_val > 1.0:
                conf = conf_val / 100.0  # Normalize 80 to 0.80
            else:
                conf = conf_val
        except (ValueError, TypeError):
            pass

    return {
        "verdict": verdict,
        "confidence": conf,
        "reasoning": parsed.get("reasoning", ""),
    }


def classify_item(
    item: dict,
    config: dict,
    system_prompt: str,
    max_chars: int,
    max_retries: int = 3,
) -> dict:
    user_prompt = build_user_prompt(item, max_chars)
    provider = config.get("AI_PROVIDER", "local")
    base_url = f"http://{config['LOCAL_AI_IP']}:{config['LOCAL_AI_PORT']}"
    model = config.get("LOCAL_AI_MODEL", "")
    gemini_key = config.get("GEMINI_API_KEY", "")

    # Ilk denemeden once hangi saglayicinin kullanildigini logla
    if not hasattr(classify_item, "provider_logged"):
        print(f"\n[+] Using AI Provider: {provider.upper()}")
        classify_item.provider_logged = True

    last_error_details = ""
    for attempt in range(1, max_retries + 1):
        try:
            if provider == "gemini":
                raw = call_gemini(gemini_key, system_prompt, user_prompt)
            else:
                raw = call_localai(base_url, model, system_prompt, user_prompt)
        except RateLimitException as e:
            last_error_details = str(e)
            print(f"    [!] Deneme {attempt}/{max_retries} basarisiz ({provider.upper()}). Kota doldu. {e.delay} sn bekleniyor...")
            time.sleep(e.delay)
            continue
        
        result = parse_verdict_response(raw) if raw else None
        if result is not None:
            result["attempts"] = attempt
            return result
        
        last_error_details = "Alinan Raw Cevap: None" if not raw else f"Alinan Raw Cevap: {raw.strip()[:200]}..."
        print(f"    [!] Deneme {attempt}/{max_retries} basarisiz ({provider.upper()}). Hata detayi: {last_error_details}")
        if attempt < max_retries:
            print("        Tekrar deneniyor (2 sn)...")
            time.sleep(2)
            
    return {"verdict": "ERROR", "confidence": None, "reasoning": f"{provider.upper()} API'den gecerli cevap alinamadi. {last_error_details}", "attempts": max_retries}



# ---------------------------------------------------------------------------
# MCP (agentic) provider modu
# ---------------------------------------------------------------------------
# Local/Gemini modunda burasi requests.post(...) ile Ollama/Gemini'yi cagirir.
# MCP modunda ayni islevin karsiligi: lava_mcp_server.py'yi bir MCP sunucusu
# olarak taniml, secilen CLI'yi (claude / agy) headless modda tetikle, sürec
# bitene kadar bekle. Ajan, MCP tool'lariyla kendi kesfini yapip verdict'leri
# dogrudan verdicts.json'a yazar (sema local/Gemini ile birebir ayni).
# ---------------------------------------------------------------------------

def _build_agent_prompt(ground_truth_path: str | None) -> str:
    """Ajana verilecek gorev promptu. Siniflandirma kurallari/few-shot'lari
    local/Gemini moduyla AYNI kaynaktan (build_system_prompt) gelir."""
    few_shot: list[dict] = []
    if ground_truth_path and Path(ground_truth_path).exists():
        try:
            data = json.loads(Path(ground_truth_path).read_text(encoding="utf-8"))
            few_shot = data.get("few_shot", []) or []
        except (json.JSONDecodeError, OSError):
            pass

    rules = build_system_prompt(few_shot)
    return f"""{rules}

=== TASK (MCP agent mode) ===
You are connected to the LAVA MCP server. Its tools are prefixed `mcp__lava__`
(a.k.a. the "lava" server). Work fully autonomously - do NOT ask questions.

Steps:
1. Call `list_findings` to get every finding and its `finding_id`.
2. Call `get_hardcoded_keys_module_output` to read the raw EMBA module output.
3. For each finding, investigate as needed with `read_log_file`,
   `search_log_content`, `list_log_files`, and especially `read_firmware_file`
   (check whether the credential is real and actually used - init scripts,
   configs, /etc/passwd vs /etc/shadow, etc.).
4. Decide TP or FP for EVERY finding using the rules above.
5. Write results with ONE `submit_all_verdicts` call: a list of
   {{"finding_id": ..., "verdict": "TP"|"FP", "confidence": 0.0-1.0,
     "reasoning": "1-2 sentence English"}}.
   (Use `submit_verdict` only for follow-up corrections.)

Every finding_id returned by `list_findings` must receive a verdict.
When all verdicts are written, stop.
"""


def _mcp_config_dict(log_dir: str, fw_root: str, verdicts_out: str) -> dict:
    return {
        "mcpServers": {
            "lava": {
                "command": sys.executable,
                "args": [
                    str(MCP_SERVER_PATH),
                    "--log-dir", log_dir,
                    "--fw-root", fw_root,
                    "--verdicts-out", verdicts_out,
                ],
            }
        }
    }


_MCP_TOOL_NAMES = [
    "list_findings", "get_hardcoded_keys_module_output", "list_log_files",
    "read_log_file", "read_firmware_file", "search_log_content",
    "submit_verdict", "submit_all_verdicts",
]


def _resolve_cli(name: str) -> str:
    """CLI'yi PATH'te, olmazsa yaygin kurulum konumlarinda arar (installer
    PATH'e eklemeyi atlamis / shell yeniden baslatilmamis olabilir)."""
    found = (shutil.which(name) or shutil.which(f"{name}.cmd")
             or shutil.which(f"{name}.exe"))
    if found:
        return found
    home = Path.home()
    candidates = [
        home / ".local" / "bin" / name,
        home / ".local" / "bin" / f"{name}.exe",
        home / "AppData" / "Local" / name / "bin" / f"{name}.exe",
        home / "AppData" / "Roaming" / "npm" / f"{name}.cmd",
        home / "bin" / name,
        Path("/usr/local/bin") / name,
        Path("/opt") / name / "bin" / name,
    ]
    for c in candidates:
        if c.is_file():
            return str(c)
    return name


def _build_agent_command(
    agent: str, prompt: str, mcp_config_path: str,
) -> tuple[list[str], str | None, list[list[str]], list[list[str]]]:
    """Doner: (ana_komut, stdin_metni, on_hazirlik_komutlari, temizlik_komutlari).

    Prompt cok satirli oldugu icin, argv uzerinden gecirmek yerine (Windows'ta
    .cmd shim'leri newline'lari bozabiliyor) mumkun oldugunca stdin ile verilir.
    """
    if agent in ("claude", "mcp_claude"):
        # --allowedTools degiskin (variadic); "mcp__lava" = sunucunun tum tool'lari.
        allowed = ["mcp__lava", *(f"mcp__lava__{t}" for t in _MCP_TOOL_NAMES)]
        cmd = [
            _resolve_cli("claude"), "-p",
            "--output-format", "json",
            "--permission-mode", "acceptEdits",
            "--strict-mcp-config",
            "--mcp-config", mcp_config_path,
            "--allowedTools", *allowed,  # en sona: sonraki argumani yemesin
        ]
        return cmd, prompt, [], []  # prompt stdin uzerinden

    if agent in ("antigravity", "mcp_antigravity", "agy", "gemini_cli"):
        agy = _resolve_cli("agy")
        cfg = json.loads(Path(mcp_config_path).read_text(encoding="utf-8"))
        srv = cfg["mcpServers"]["lava"]
        # agy'de --mcp-config yok; kalici config'e ekle/guncelle, sonra kaldir.
        pre = [[agy, "mcp", "add", "lava", "--", srv["command"], *srv["args"]]]
        post = [[agy, "mcp", "remove", "lava"]]
        # agy'de -p bir sonraki argumani prompt olarak alir -> en sona koy.
        cmd = [
            agy,
            "--dangerously-skip-permissions",
            "--output-format", "json",
            "--mode", "accept-edits",
            "-p", prompt,
        ]
        return cmd, None, pre, post

    raise ValueError(f"Bilinmeyen MCP ajani: {agent!r} (beklenen: 'claude' | 'antigravity')")


def _validate_verdicts_schema(verdicts_path: str) -> int:
    """verdicts.json'un local/Gemini moduyla ayni semada olup olmadigini dogrular.
    Doner: verdict sayisi."""
    p = Path(verdicts_path)
    if not p.exists():
        raise RuntimeError(f"Ajan kosumu bitti ama verdicts.json yazilmadi: {verdicts_path}")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        raise RuntimeError(f"verdicts.json okunamadi/gecersiz JSON: {e}") from e
    if not isinstance(data, list) or not data:
        raise RuntimeError("verdicts.json bir liste degil veya bos (ajan hic verdict yazmadi).")
    for i, rec in enumerate(data):
        if not isinstance(rec, dict):
            raise RuntimeError(f"verdicts.json[{i}] bir obje degil.")
        missing = _VERDICT_REQUIRED_FIELDS - set(rec)
        if missing:
            raise RuntimeError(f"verdicts.json[{i}] eksik alan(lar): {sorted(missing)}")
        if str(rec["predicted_verdict"]).upper() not in ("TP", "FP", "ERROR"):
            raise RuntimeError(
                f"verdicts.json[{i}] gecersiz predicted_verdict: {rec['predicted_verdict']!r}"
            )
    return len(data)


def classify_via_mcp_agent(
    log_dir: str,
    fw_root: str,
    out_path: str,
    agent: str = "claude",
    ground_truth_path: str | None = None,
    timeout_seconds: int | None = None,
) -> None:
    """MCP sunucusunu bir CLI ajanina (claude / agy) taniml, ajani headless
    modda tetikle, sürec bitene kadar bekle. classify_via_ollama /
    classify_via_gemini ile ayni rolde: orchestrator hangi provider secilirse
    ayni sekilde cagirir, cikti semasi degismez.

        agent: "claude" (Claude Code) veya "antigravity" (Antigravity/agy CLI)
    """
    log_dir = str(Path(log_dir).expanduser().resolve())
    fw_root = str(Path(fw_root).expanduser().resolve())
    out_path = str(Path(out_path).expanduser().resolve())
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    timeout_seconds = int(timeout_seconds or AGENT_TIMEOUT_SECONDS)

    if not MCP_SERVER_PATH.exists():
        raise RuntimeError(f"MCP sunucusu bulunamadi: {MCP_SERVER_PATH}")

    prompt = _build_agent_prompt(ground_truth_path)

    tmpdir = tempfile.mkdtemp(prefix="lava_mcp_")
    mcp_config_path = os.path.join(tmpdir, "mcp_config.json")
    Path(mcp_config_path).write_text(
        json.dumps(_mcp_config_dict(log_dir, fw_root, out_path), indent=2), encoding="utf-8"
    )

    cmd, stdin_text, pre_cmds, post_cmds = _build_agent_command(agent, prompt, mcp_config_path)
    exe = cmd[0]
    cli_name = Path(exe).name
    if not ((os.path.isabs(exe) and os.path.isfile(exe)) or shutil.which(exe)):
        raise RuntimeError(
            f"'{cli_name}' CLI bulunamadi (PATH'te veya yaygin kurulum konumlarinda). "
            f"MCP modu icin once kurup bir kez login olun (bkz. README - 'MCP provider modu')."
        )

    print(f"\n[+] Using AI Provider: MCP agent ({agent})")
    print(f"    MCP server : {MCP_SERVER_PATH}")
    print(f"    log-dir    : {log_dir}")
    print(f"    fw-root    : {fw_root}")
    print(f"    verdicts   : {out_path}")

    try:
        for pc in pre_cmds:
            subprocess.run(pc, capture_output=True, text=True, timeout=120, check=False)
        try:
            result = subprocess.run(
                cmd, input=stdin_text, capture_output=True, text=True,
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired as e:
            raise RuntimeError(
                f"Ajan {timeout_seconds}s icinde bitmedi, sonlandirildi "
                f"(ai_config.env icinde AGENT_TIMEOUT_SECONDS veya "
                f"LAVA_AGENT_TIMEOUT_SECONDS ile artirilabilir)."
            ) from e

        if result.returncode != 0:
            tail = (result.stderr or result.stdout or "").strip()[-1500:]
            raise RuntimeError(f"Ajan kosumu basarisiz (exit {result.returncode}):\n{tail}")

        count = _validate_verdicts_schema(out_path)
        print(f"[OK] MCP ajani {count} verdict yazdi -> {out_path}")
    finally:
        for pc in post_cmds:
            subprocess.run(pc, capture_output=True, text=True, timeout=120, check=False)
        shutil.rmtree(tmpdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Degerlendirme (test modu icin)
# ---------------------------------------------------------------------------
def compute_metrics(results: list[dict]) -> dict:
    """TP sinifini pozitif kabul ederek precision/recall/F1/accuracy hesaplar."""
    tp = fp = tn = fn = errors = 0
    for r in results:
        pred, true = r["predicted_verdict"], r["true_verdict"]
        if pred == "ERROR":
            errors += 1
            continue
        if true == "TP" and pred == "TP":
            tp += 1
        elif true == "FP" and pred == "FP":
            tn += 1
        elif true == "FP" and pred == "TP":
            fp += 1
        elif true == "TP" and pred == "FP":
            fn += 1

    total_scored = tp + tn + fp + fn
    accuracy = (tp + tn) / total_scored if total_scored else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    return {
        "tp": tp, "tn": tn, "fp": fp, "fn": fn, "errors": errors,
        "accuracy": round(accuracy, 3),
        "precision_TP": round(precision, 3),
        "recall_TP": round(recall, 3),
        "f1_TP": round(f1, 3),
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def run_test_mode(args, config: dict):
    data = json.loads(Path(args.ground_truth).read_text(encoding="utf-8"))
    few_shot = data["few_shot"]
    test_set = data["test_set"]

    system_prompt = build_system_prompt(few_shot)
    base_url = f"http://{config['LOCAL_AI_IP']}:{config['LOCAL_AI_PORT']}"
    max_chars = int(config.get("AI_MAX_CHARS_TO_ANALYSE", 5000))

    results = []
    for i, item in enumerate(test_set, start=1):
        print(f"[{i}/{len(test_set)}] {item['finding_id']} ({item['file_path']}) degerlendiriliyor...")
        pred = classify_item(item, config, system_prompt, max_chars)
        results.append({
            "finding_id": item["finding_id"],
            "file_path": item["file_path"],
            "true_verdict": item["verdict"],
            "predicted_verdict": pred["verdict"],
            "confidence": pred.get("confidence"),
            "model_reasoning": pred.get("reasoning"),
            "human_reasoning": item.get("reasoning"),
            "attempts": pred.get("attempts"),
        })
        match = "✓" if pred["verdict"] == item["verdict"] else "✗"
        print(f"    gercek={item['verdict']}  model={pred['verdict']}  {match}")

        # Her dongu adiminda ara kayit (metrikler haric)
        output = {"results": results, "metrics": {}}
        atomic_save(output, args.out)

    metrics = compute_metrics(results)
    output = {"results": results, "metrics": metrics}
    atomic_save(output, args.out)

    print("\n=== SONUCLAR ===")
    for k, v in metrics.items():
        print(f"  {k}: {v}")
    print(f"\n[+] Detayli sonuclar: {args.out}")


def run_full_mode(args, config: dict):
    data = json.loads(Path(args.ground_truth).read_text(encoding="utf-8")) if args.ground_truth else None
    few_shot = data["few_shot"] if data else []
    if not few_shot:
        print("[!] UYARI: few-shot ornekleri verilmedi (--ground-truth belirtilmedi), prompt daha zayif calisacak.")

    findings = json.loads(Path(args.enriched).read_text(encoding="utf-8"))
    system_prompt = build_system_prompt(few_shot)
    base_url = f"http://{config['LOCAL_AI_IP']}:{config['LOCAL_AI_PORT']}"
    max_chars = int(config.get("AI_MAX_CHARS_TO_ANALYSE", 5000))

    results = []
    for i, item in enumerate(findings, start=1):
        label = item.get("file_path", "?")
        print(f"[{i}/{len(findings)}] {label} degerlendiriliyor...")
        pred = classify_item(item, config, system_prompt, max_chars)
        results.append({
            "file_path": item.get("file_path"),
            "matched_content": item.get("matched_content"),
            "found_by_modules": item.get("found_by_modules"),
            "corroboration_count": item.get("corroboration_count"),
            "predicted_verdict": pred["verdict"],
            "confidence": pred.get("confidence"),
            "model_reasoning": pred.get("reasoning"),
            "attempts": pred.get("attempts"),
        })
        
        # Her adimda sonuclari kaydet (Ctrl+C kesintilerine karsi)
        atomic_save(results, args.out)

    from collections import Counter
    dist = Counter(r["predicted_verdict"] for r in results)
    
    # Her durumda (0 bulgu olsa bile) dosyayi olustur
    atomic_save(results, args.out)
    
    print("\n=== OZET ===")
    for k, v in dist.items():
        print(f"  {k}: {v}")
    print(f"\n[+] Sonuclar: {args.out}")


def main():
    ap = argparse.ArgumentParser(description="LAVA - EMBA bulgularini LocalAI ile TP/FP olarak siniflandirir.")
    ap.add_argument("--mode", choices=["test", "run"], required=True)
    ap.add_argument("--config", required=True, help="config/ai_config.env dosyasi")
    ap.add_argument("--ground-truth", help="test modunda zorunlu; run modunda opsiyonel (sadece few-shot icin)")
    ap.add_argument("--enriched", help="run modunda zorunlu - enrich_context.py ciktisi")
    ap.add_argument("--out", required=True)
    ap.add_argument("--log-dir", help="EMBA log dizini (sadece MCP provider modunda kullanilir)")
    ap.add_argument("--fw-root", help="firmware extract koku (MCP modu; verilmezse --log-dir kullanilir)")
    args = ap.parse_args()

    config = load_ai_config(Path(args.config))
    provider = (config.get("AI_PROVIDER") or "local").strip().lower()

    # --- MCP (agentic) provider modu -------------------------------------
    # AI_PROVIDER = mcp_claude | mcp_antigravity | mcp
    # Local/Gemini dallarina hic dokunmadan, ucuncu bir provider dali.
    if provider.startswith("mcp"):
        agent = {
            "mcp_claude": "claude",
            "mcp_antigravity": "antigravity",
            "mcp": "claude",
        }.get(provider, "claude")

        log_dir = args.log_dir
        if not log_dir and args.enriched:
            # run_lava.sh: --out <LogDir>/lava_out/<ts>/verdicts.json
            log_dir = str(Path(args.out).resolve().parents[2])
        if not log_dir:
            ap.error("MCP provider modu icin --log-dir zorunlu")
        fw_root = args.fw_root or log_dir

        if args.mode != "run":
            ap.error("MCP provider modu sadece --mode run ile calisir")

        try:
            _to = int(config.get("AGENT_TIMEOUT_SECONDS") or 0) or None
        except (TypeError, ValueError):
            _to = None
        classify_via_mcp_agent(
            log_dir=log_dir,
            fw_root=fw_root,
            out_path=args.out,
            agent=agent,
            ground_truth_path=args.ground_truth,
            timeout_seconds=_to,
        )
        return

    if not config["LOCAL_AI_MODEL"]:
        print("[!] UYARI: LOCAL_AI_MODEL config'te bos - identify_ai_model mantigi burada yok, dogru modeli config'e yazdiginizdan emin olun.")

    if args.mode == "test":
        if not args.ground_truth:
            ap.error("--mode test icin --ground-truth zorunlu")
        run_test_mode(args, config)
    else:
        if not args.enriched:
            ap.error("--mode run icin --enriched zorunlu")
        run_full_mode(args, config)


if __name__ == "__main__":
    main()