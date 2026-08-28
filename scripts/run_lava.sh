#!/bin/bash
# LAVA (Local AI Vulnerability Auditor) Pipeline Runner (Linux/macOS)

# Argümanları al
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -LogDir|--log-dir) LOGDIR="$2"; shift ;;
        -OutDir|--out-dir) BASEOUTDIR="$2"; shift ;;
        *) echo "Bilinmeyen parametre: $1"; exit 2 ;;
    esac
    shift
done

if [ -z "$LOGDIR" ]; then
    echo "Hata: -LogDir parametresi zorunludur."
    exit 2
fi

if [ -z "$BASEOUTDIR" ]; then
    BASEOUTDIR="$LOGDIR/lava_out"
fi

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTDIR="$BASEOUTDIR/$TIMESTAMP"
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

# Config dosyasindan IP ve PORT al
AI_IP="127.0.0.1"
AI_PORT="11434"
AI_PROVIDER="local"
AI_MODEL="qwen2.5-coder:7b"

# ai_config.env'den bir anahtarin degerini oku. Sadece satir-basi "KEY=" ile
# eslesir (yorum satirlarini - ornegin "# AI_PROVIDER secenekleri:" - atlar),
# ilk eslesmeyi alir, tirnak ve bosluklari kirpar. (run_lava.ps1 ile ayni mantik.)
read_env_val() {
    grep -E "^[[:space:]]*$1[[:space:]]*=" "$2" 2>/dev/null | head -n1 \
        | sed -E "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*[\"']?([^\"']*)[\"']?[[:space:]]*\$/\1/"
}

if [ -f "config/ai_config.env" ]; then
    ip_val=$(read_env_val LOCAL_AI_IP config/ai_config.env)
    port_val=$(read_env_val LOCAL_AI_PORT config/ai_config.env)
    prov_val=$(read_env_val AI_PROVIDER config/ai_config.env)
    mod_val=$(read_env_val LOCAL_AI_MODEL config/ai_config.env)
    [ -n "$ip_val" ] && AI_IP="$ip_val"
    [ -n "$port_val" ] && AI_PORT="$port_val"
    [ -n "$prov_val" ] && AI_PROVIDER="$prov_val"
    [ -n "$mod_val" ] && AI_MODEL="$mod_val"
fi

# Ollama arka planda calismiyorsa baslat (Sadece Localhost icin ve provider local ise)
if [ "$AI_PROVIDER" != "gemini" ] && [[ "$AI_PROVIDER" != mcp* ]] && ! curl -s "http://$AI_IP:$AI_PORT/" > /dev/null; then
    if [ "$AI_IP" = "127.0.0.1" ] || [ "$AI_IP" = "localhost" ]; then
        if command -v ollama &> /dev/null; then
            echo "[AI_INFO] Ollama servisi kapali, otomatik olarak arka planda baslatiliyor..."
            nohup ollama serve > /dev/null 2>&1 &
            sleep 3
            echo "[AI_INFO] Ollama servisi basariyla tetiklendi!"
        else
            echo "HATA: Sisteminizde 'ollama' kurulu degil!"
            echo "Linux (Kali) uzerinde LAVA'yi kullanabilmek icin Ollama gereklidir."
            echo "Kurmak icin su komutu calistirin: curl -fsSL https://ollama.com/install.sh | sh"
            echo "Alternatif olarak config/ai_config.env icerisinden uzak bir Ollama IP'si belirtebilirsiniz."
            exit 2
        fi
    else
        echo "UYARI: Uzak Ollama sunucusuna ($AI_IP:$AI_PORT) ulasilamadi!"
        echo "Lutfen Windows makinenizdeki Ollama'nin calistigindan ve ag baglantisina acik oldugundan (OLLAMA_HOST=0.0.0.0) emin olun."
    fi
fi

echo "========================================="
echo "LAVA Pipeline Baslatiliyor..."
if [ "$AI_PROVIDER" = "gemini" ]; then
    echo "[AI_INFO] Secilen Model: Gemini API (Cloud)"
elif [[ "$AI_PROVIDER" == mcp* ]]; then
    echo "[AI_INFO] Secilen Model: MCP agent ($AI_PROVIDER)"
else
    echo "[AI_INFO] Secilen Model: $AI_MODEL (Local AI)"
fi
echo "========================================="

if [[ "$AI_PROVIDER" == mcp* ]]; then
    echo "[1-2/3] MCP modu: parse/enrich adimlari atlaniyor (ajan ham loglari kendisi kesfeder)."
else
    echo "[1/3] EMBA loglari ayristiriliyor (parse)..."
    python3 src/core/parser.py --log-dir "$LOGDIR" --out "$FINDINGS_FILE" --merged-out "$MERGED_FILE"
    if [ $? -ne 0 ]; then echo "Hata: parser.py basarisiz oldu!"; exit 2; fi
    echo "[OK] Ayristirma tamamlandi."

    echo -e "\n[2/3] Baglam olusturuluyor (enrich)..."
    python3 src/core/enricher.py --merged "$MERGED_FILE" --log-dir "$LOGDIR" --out "$ENRICHED_FILE"
    if [ $? -ne 0 ]; then echo "Hata: enricher.py basarisiz oldu!"; exit 2; fi
    echo "[OK] Baglam dosyalari (context) basariyla eklendi."
fi

echo -e "\n[3/3] LLM Siniflandirma Basliyor (Bu adim uzun surebilir)..."
python3 src/core/classifier.py --mode run --config config/ai_config.env --ground-truth ground_truth.json --enriched "$ENRICHED_FILE" --out "$VERDICTS_FILE" --log-dir "$LOGDIR"
if [ $? -ne 0 ]; then echo "Hata: classifier.py basarisiz oldu!"; exit 2; fi
echo "[OK] Siniflandirma tamamlandi! Sonuclar $VERDICTS_FILE dosyasina yazildi."

echo -e "\n[4/4] HTML Raporu olusturuluyor..."
python3 src/reporting/html_report.py --verdicts "$VERDICTS_FILE" --out "$REPORT_FILE"
if [ $? -ne 0 ]; then echo "Hata: html_report.py basarisiz oldu!"; exit 2; fi
echo "[OK] Rapor tamamlandi! Cikti: $REPORT_FILE"

echo -e "\n========================================="
echo "LAVA Tamamlandi!"
echo "========================================="
