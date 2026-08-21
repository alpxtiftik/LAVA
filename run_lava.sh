#!/bin/bash
# LAVA (Local AI Vulnerability Auditor) Pipeline Runner (Linux/macOS)

# Argümanları al
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -LogDir|--log-dir) LOGDIR="$2"; shift ;;
        *) echo "Bilinmeyen parametre: $1"; exit 1 ;;
    esac
    shift
done

if [ -z "$LOGDIR" ]; then
    echo "Hata: -LogDir parametresi zorunludur."
    exit 1
fi

echo "========================================="
echo "LAVA Pipeline Başlatılıyor..."
echo "========================================="

echo "[1/3] EMBA logları ayrıştırılıyor (parse)..."
python3 parser_and_enrichs/parse_emba_findings.py --log-dir "$LOGDIR" --out findings.json --merged-out merged_findings.json
if [ $? -ne 0 ]; then echo "Hata: parse_emba_findings.py başarısız oldu!"; exit 1; fi
echo "[OK] Ayrıştırma tamamlandı."

echo -e "\n[2/3] Bağlam oluşturuluyor (enrich)..."
python3 parser_and_enrichs/enrich_context.py --merged merged_findings.json --log-dir "$LOGDIR" --out enriched_findings.json
if [ $? -ne 0 ]; then echo "Hata: enrich_context.py başarısız oldu!"; exit 1; fi
echo "[OK] Bağlam dosyaları (context) başarıyla eklendi."

echo -e "\n[3/3] LLM Sınıflandırma Başlıyor (Bu adım uzun sürebilir)..."
python3 llm_classifier.py --mode run --config config/ai_config.env --ground-truth ground_truth.json --enriched enriched_findings.json --out verdicts.json
if [ $? -ne 0 ]; then echo "Hata: llm_classifier.py başarısız oldu!"; exit 1; fi
echo "[OK] Sınıflandırma tamamlandı! Sonuçlar verdicts.json dosyasına yazıldı."

echo -e "\n========================================="
echo "LAVA Tamamlandı!"
echo "Sonuçları incelemek için arayüzü başlatın: python3 start_ui.py"
echo "========================================="
