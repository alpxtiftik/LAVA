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

import argparse
import json
import re
import time
from pathlib import Path

import requests

# ---------------------------------------------------------------------------
# Modele hatirlatma amacli sabit bilgi notu - kucuk modellerin hash format
# prefixlerini karistirmamasi icin. EMBA'nin S107/S108 ciktilarinda gordugumuz
# tum formatlar burada.
# ---------------------------------------------------------------------------
HASH_CHEATSHEET = """\
Bilinen crypt() hash format onekleri (bunlar GERCEK, calisan hash'lerdir, TP icin guclu sinyaldir):
  $1$  -> MD5-crypt
  $5$  -> SHA-256-crypt
  $6$  -> SHA-512-crypt
  $2a$/$2b$/$2y$ -> bcrypt
Bir /etc/passwd veya /etc/shadow satirinda bu formatlardan biri geciyorsa ve alan sayisi
dogruysa (user:hash:lastchg:min:max:warn:inactive:expire) bu genellikle gercek bir TP'dir."""

SYSTEM_PROMPT_TEMPLATE = """Sen bir firmware güvenlik analistisin. Görevin, EMBA firmware analiz aracının \
bulduğu "hardcoded credential/secret" adaylarını incelemek ve her birinin GERÇEK bir \
kimlik bilgisi sızıntısı mı (TP - True Positive) yoksa yanlış alarm mı (FP - False Positive) \
olduğuna karar vermektir.

{hash_cheatsheet}

Değerlendirirken şunlara dikkat et:
- Dosya yolu (config dosyası mı, binary/kütüphane mi, script mi, UI kodu mu)
- Eşleşen içeriğin GERÇEK bir değer mi yoksa bir değişken adı/tanımı/yorum/UI etiketi mi olduğu
- Kaç farklı EMBA modülünün aynı bulguyu bağımsız doğruladığı (corroboration_count) - yüksekse güçlü TP sinyali
- Verilen dosya bağlamı (context_lines) - eşleşen satırın etrafındaki kod/config

KRİTİK KURALLAR:
1. Eğer "eşleşen içerik" (matched_content) somut bir değer değil, JENERİK bir modül mesajıysa
   (örn. "flagged as password-related file" gibi - bu bir dosya sınıflandırma bayrağıdır,
   dosyanın GERÇEK içeriği DEĞİLDİR), bu TEK BAŞINA TP kanıtı sayılmaz. Bu durumda karar
   VERİLEN CONTEXT'E dayanmalı: context'te gerçek bir hash/parola DEĞERİ görüyorsan TP,
   görmüyorsan (örn. tüm satırlar 'x' veya '*' placeholder içeriyorsa, ya da context hiç
   bulunamadıysa) FP de.
2. Eğer eşleşen kod bir DEĞİŞKENDEN okuma yapan veya KOŞULLU bir provisioning/script mantığıysa
   (örn. "json_get_vars root_password_hash", "sed -i ... /etc/shadow", bir config dosyasından
   değer okuyup varsa uygulayan kod), bu KENDİSİ bir hardcoded credential DEĞİLDİR - script
   sadece başka bir kaynaktan (board.json, config) gelen değeri UYGULUYOR. Bu genellikle FP'dir,
   çünkü gerçek değer bu dosyada değil, script'in okuduğu kaynaktadır.
3. Context bağlamında "exact_match_located: false" görüyorsan, bu context'in dosyanın BAŞINDAN
   alınmış bir örnek olduğunu, eşleşen asıl satırı temsil etmediğini unutma - buna göre daha
   temkinli değerlendir, sadece dosya adına güvenip TP deme.
4. Eğer eşleşen içerik `/etc/passwd` veya `/etc/shadow` formatındaysa (örn. "root:x:0:0...")
   ancak içinde `$1$`, `$5$`, `$6$`, `$2a$` vb. ile başlayan GERÇEK bir kriptografik hash barındırmıyorsa,
   bu KESİNLİKLE bir FP'dir. 'x' veya '*' gibi karakterler sadece yer tutucudur (placeholder) ve
   hash DEĞİLDİR. Sadece gerçek, uzun hash barındıran satırlar TP'dir.

Aşağıda örnekler var. Bunlardan öğren, sonra sana verilen YENİ bulguyu değerlendir.

{few_shot_block}

ÇOK ÖNEMLİ KURALLAR:
1. "reasoning" kısmını KESİNLİKLE VE SADECE TÜRKÇE yaz (İngilizce kelimeler kullanma).
2. Cevabını SADECE aşağıdaki JSON formatında ver, başka hiçbir metin ekleme:
{{"verdict": "TP" veya "FP", "confidence": 0.0-1.0 arası sayı, "reasoning": "1-2 cümlelik kısa TÜRKÇE gerekçe"}}
"""

FEW_SHOT_ITEM_TEMPLATE = """### Örnek {n}
Dosya: {file_path}
Modül: {module}
Eşleşen içerik: {matched_content}
Doğru cevap: {{"verdict": "{verdict}", "reasoning": "{reasoning}"}}
"""

USER_PROMPT_TEMPLATE = """Şimdi bu bulguyu değerlendir:

Dosya: {file_path}
Modül: {module}
Kaç modül tarafından doğrulandı (corroboration_count): {corroboration_count}
Eşleşen içerik: {matched_content}
{context_block}
Cevabını yalnızca istenen JSON formatında ver."""


# ---------------------------------------------------------------------------
# Config okuma - EMBA'nin config/ai_config.env formatiyla aynen uyumlu
# (KEY="value" seklinde bash env satirlari)
# ---------------------------------------------------------------------------
def load_ai_config(config_path: Path) -> dict:
    config = {
        "LOCAL_AI_IP": "127.0.0.1",
        "LOCAL_AI_MODEL": "",
        "AI_MAX_CHARS_TO_ANALYSE": "5000",
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
        return f"Dosya bağlamı: mevcut değil ({status})\n"
    lines = context["context_lines"]
    idx = context.get("matched_line_index_in_context")
    exact = context.get("exact_match_located", idx is not None)
    rendered = []
    for i, ln in enumerate(lines):
        marker = ">>> " if (exact and i == idx) else "    "
        rendered.append(f"{marker}{ln}")
    block = "\n".join(rendered)
    if len(block) > max_chars:
        block = block[:max_chars] + "\n... (kırpıldı)"
    note = "" if exact else "\n[NOT: eşleşen satır tam olarak bulunamadı, bu dosyanın BAŞINDAN bir örnek - '>>>' işareti YOK, kendi kararını içeriğe bakarak ver]"
    return f"Dosya bağlamı{' (>>> = eşleşen satır)' if exact else ''}:{note}\n{block}\n"


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
def call_localai(base_url: str, model: str, system_prompt: str, user_prompt: str, timeout: int = 60) -> str | None:
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
        print(f"    [!] LocalAI çağrı hatası: {e}")
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
    return {
        "verdict": verdict,
        "confidence": parsed.get("confidence"),
        "reasoning": parsed.get("reasoning", ""),
    }


def classify_item(
    item: dict,
    base_url: str,
    model: str,
    system_prompt: str,
    max_chars: int,
    max_retries: int = 3,
) -> dict:
    user_prompt = build_user_prompt(item, max_chars)
    for attempt in range(1, max_retries + 1):
        raw = call_localai(base_url, model, system_prompt, user_prompt)
        result = parse_verdict_response(raw) if raw else None
        if result is not None:
            result["attempts"] = attempt
            return result
        print(f"    [!] Deneme {attempt}/{max_retries} başarısız, tekrar deneniyor...")
        time.sleep(2)
    return {"verdict": "ERROR", "confidence": None, "reasoning": "LocalAI'den geçerli cevap alınamadı", "attempts": max_retries}


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
    base_url = f"http://{config['LOCAL_AI_IP']}:11434"
    max_chars = int(config.get("AI_MAX_CHARS_TO_ANALYSE", 5000))

    results = []
    for i, item in enumerate(test_set, start=1):
        print(f"[{i}/{len(test_set)}] {item['finding_id']} ({item['file_path']}) değerlendiriliyor...")
        pred = classify_item(item, base_url, config["LOCAL_AI_MODEL"], system_prompt, max_chars)
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
        print(f"    gerçek={item['verdict']}  model={pred['verdict']}  {match}")

        # Her döngü adımında ara kayıt (metrikler hariç)
        output = {"results": results, "metrics": {}}
        Path(args.out).write_text(json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8")

    metrics = compute_metrics(results)
    output = {"results": results, "metrics": metrics}
    Path(args.out).write_text(json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8")

    print("\n=== SONUÇLAR ===")
    for k, v in metrics.items():
        print(f"  {k}: {v}")
    print(f"\n[+] Detaylı sonuçlar: {args.out}")


def run_full_mode(args, config: dict):
    data = json.loads(Path(args.ground_truth).read_text(encoding="utf-8")) if args.ground_truth else None
    few_shot = data["few_shot"] if data else []
    if not few_shot:
        print("[!] UYARI: few-shot örnekleri verilmedi (--ground-truth belirtilmedi), prompt daha zayıf çalışacak.")

    findings = json.loads(Path(args.enriched).read_text(encoding="utf-8"))
    system_prompt = build_system_prompt(few_shot)
    base_url = f"http://{config['LOCAL_AI_IP']}:11434"
    max_chars = int(config.get("AI_MAX_CHARS_TO_ANALYSE", 5000))

    results = []
    for i, item in enumerate(findings, start=1):
        label = item.get("file_path", "?")
        print(f"[{i}/{len(findings)}] {label} değerlendiriliyor...")
        pred = classify_item(item, base_url, config["LOCAL_AI_MODEL"], system_prompt, max_chars)
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
        
        # Her adımda sonuçları kaydet (Ctrl+C kesintilerine karşı)
        Path(args.out).write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")

    from collections import Counter
    dist = Counter(r["predicted_verdict"] for r in results)
    print("\n=== ÖZET ===")
    for k, v in dist.items():
        print(f"  {k}: {v}")
    print(f"\n[+] Sonuçlar: {args.out}")


def main():
    ap = argparse.ArgumentParser(description="LAVA - EMBA bulgularını LocalAI ile TP/FP olarak sınıflandırır.")
    ap.add_argument("--mode", choices=["test", "run"], required=True)
    ap.add_argument("--config", required=True, help="config/ai_config.env dosyası")
    ap.add_argument("--ground-truth", help="test modunda zorunlu; run modunda opsiyonel (sadece few-shot için)")
    ap.add_argument("--enriched", help="run modunda zorunlu - enrich_context.py çıktısı")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    config = load_ai_config(Path(args.config))
    if not config["LOCAL_AI_MODEL"]:
        print("[!] UYARI: LOCAL_AI_MODEL config'te boş - identify_ai_model mantığı burada yok, doğru modeli config'e yazdığınızdan emin olun.")

    if args.mode == "test":
        if not args.ground_truth:
            ap.error("--mode test için --ground-truth zorunlu")
        run_test_mode(args, config)
    else:
        if not args.enriched:
            ap.error("--mode run için --enriched zorunlu")
        run_full_mode(args, config)


if __name__ == "__main__":
    main()