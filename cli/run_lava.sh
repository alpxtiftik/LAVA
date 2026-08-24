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

OUTDIR="$LOGDIR/lava_out"
mkdir -p "$OUTDIR"

FINDINGS_FILE="$OUTDIR/findings.json"
MERGED_FILE="$OUTDIR/merged_findings.json"
ENRICHED_FILE="$OUTDIR/enriched_findings.json"
VERDICTS_FILE="$OUTDIR/verdicts.json"
REPORT_FILE="$OUTDIR/lava_report.html"

echo "========================================="
echo "LAVA Pipeline Başlatılıyor..."
echo "========================================="

echo "[1/3] EMBA logları ayrıştırılıyor (parse)..."
python3 parser_and_enrichs/parse_emba_findings.py --log-dir "$LOGDIR" --out "$FINDINGS_FILE" --merged-out "$MERGED_FILE"
if [ $? -ne 0 ]; then echo "Hata: parse_emba_findings.py başarısız oldu!"; exit 1; fi
echo "[OK] Ayrıştırma tamamlandı."

echo -e "\n[2/3] Bağlam oluşturuluyor (enrich)..."
python3 parser_and_enrichs/enrich_context.py --merged "$MERGED_FILE" --log-dir "$LOGDIR" --out "$ENRICHED_FILE"
if [ $? -ne 0 ]; then echo "Hata: enrich_context.py başarısız oldu!"; exit 1; fi
echo "[OK] Bağlam dosyaları (context) başarıyla eklendi."

echo -e "\n[3/3] LLM Sınıflandırma Başlıyor (Bu adım uzun sürebilir)..."
python3 llm_classifier.py --mode run --config config/ai_config.env --ground-truth ground_truth.json --enriched "$ENRICHED_FILE" --out "$VERDICTS_FILE"
if [ $? -ne 0 ]; then echo "Hata: llm_classifier.py başarısız oldu!"; exit 1; fi
echo "[OK] Sınıflandırma tamamlandı! Sonuçlar $VERDICTS_FILE dosyasına yazıldı."

echo -e "\n[4/4] HTML Raporu oluşturuluyor..."
python3 cli/generate_html_report.py --verdicts "$VERDICTS_FILE" --out "$REPORT_FILE"
if [ $? -ne 0 ]; then echo "Hata: generate_html_report.py başarısız oldu!"; exit 1; fi
echo "[OK] Rapor tamamlandı! Çıktı: $REPORT_FILE"

echo -e "\n========================================="
echo "LAVA Tamamlandı!"
echo "Sonuçları incelemek için arayüzü başlatın: python3 start_ui.py"
echo "========================================="
