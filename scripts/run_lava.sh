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

PID_FILE="$OUTDIR/lava.pid"
if [ -f "$PID_FILE" ]; then
    OLD_PID=$(cat "$PID_FILE")
    if ps -p "$OLD_PID" > /dev/null 2>&1; then
        echo "Uyari: Bu klasorde onceki bir tarama devam ediyor (PID: $OLD_PID). Kapatiliyor..."
        kill -9 "$OLD_PID" 2>/dev/null
        sleep 1
    fi
fi
echo $$ > "$PID_FILE"


FINDINGS_FILE="$OUTDIR/findings.json"
MERGED_FILE="$OUTDIR/merged_findings.json"
ENRICHED_FILE="$OUTDIR/enriched_findings.json"
VERDICTS_FILE="$OUTDIR/verdicts.json"
REPORT_FILE="$OUTDIR/lava_report.html"

# Ollama arka planda calismiyorsa baslat
if ! curl -s http://localhost:11434/ > /dev/null; then
    echo "Ollama API'ye ulasilamadi. Arka planda baslatiliyor..."
    nohup ollama serve > /dev/null 2>&1 &
    sleep 3
fi

echo "========================================="
echo "LAVA Pipeline Başlatılıyor..."
echo "========================================="

echo "[1/3] EMBA logları ayrıştırılıyor (parse)..."
python3 src/core/parser.py --log-dir "$LOGDIR" --out "$FINDINGS_FILE" --merged-out "$MERGED_FILE"
if [ $? -ne 0 ]; then echo "Hata: parser.py başarısız oldu!"; exit 1; fi
echo "[OK] Ayrıştırma tamamlandı."

echo -e "\n[2/3] Bağlam oluşturuluyor (enrich)..."
python3 src/core/enricher.py --merged "$MERGED_FILE" --log-dir "$LOGDIR" --out "$ENRICHED_FILE"
if [ $? -ne 0 ]; then echo "Hata: enricher.py başarısız oldu!"; exit 1; fi
echo "[OK] Bağlam dosyaları (context) başarıyla eklendi."

echo -e "\n[3/3] LLM Sınıflandırma Başlıyor (Bu adım uzun sürebilir)..."
python3 src/core/classifier.py --mode run --config config/ai_config.env --ground-truth ground_truth.json --enriched "$ENRICHED_FILE" --out "$VERDICTS_FILE"
if [ $? -ne 0 ]; then echo "Hata: classifier.py başarısız oldu!"; exit 1; fi
echo "[OK] Sınıflandırma tamamlandı! Sonuçlar $VERDICTS_FILE dosyasına yazıldı."

echo -e "\n[4/4] HTML Raporu oluşturuluyor..."
python3 src/reporting/html_report.py --verdicts "$VERDICTS_FILE" --out "$REPORT_FILE"
if [ $? -ne 0 ]; then echo "Hata: html_report.py başarısız oldu!"; exit 1; fi
echo "[OK] Rapor tamamlandı! Çıktı: $REPORT_FILE"

echo -e "\n========================================="
echo "LAVA Tamamlandı!"
echo "Sonuçları incelemek için arayüzü başlatın: python3 start_ui.py"
echo "========================================="
