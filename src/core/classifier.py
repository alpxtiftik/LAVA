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
import time
from pathlib import Path

import requests

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
    args = ap.parse_args()

    config = load_ai_config(Path(args.config))
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