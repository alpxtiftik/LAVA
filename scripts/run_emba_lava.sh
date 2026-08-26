#!/usr/bin/env bash
#
# LAVA Full Pipeline Runner for Linux
# EMBA'yi calistirip ardindan LAVA AI analizini baslatir.

FirmwarePath=""
LogDir=""

while [[ "$#" -gt 0 ]]; do
    case $1 in
        -FirmwarePath|--firmware-path) FirmwarePath="$2"; shift ;;
        -LogDir|--log-dir) LogDir="$2"; shift ;;
        *) echo "Bilinmeyen parametre: $1"; exit 1 ;;
    esac
    shift
done

if [ -z "$FirmwarePath" ] || [ -z "$LogDir" ]; then
    echo "Kullanim: $0 -FirmwarePath <path> -LogDir <dir>"
    exit 1
fi

# Ollama arka planda calismiyorsa baslat
if ! curl -s http://localhost:11434/ > /dev/null; then
    echo "Ollama API'ye ulasilamadi. Arka planda baslatiliyor..."
    nohup ollama serve > /dev/null 2>&1 &
    sleep 3
fi

echo "========================================="
echo "LAVA FULL PIPELINE BASLATILIYOR (LINUX)"
echo "========================================="

# 1. Config'den EMBA_PATH oku
EMBA_PATH="/emba/emba"
if [ -f "config/ai_config.env" ]; then
    while IFS='=' read -r key value; do
        if [ "$key" == "EMBA_PATH" ]; then
            EMBA_PATH=$(echo "$value" | tr -d '"' | tr -d "'")
        fi
    done < config/ai_config.env
fi

echo "[1/2] EMBA calistiriliyor..."
echo "Firmware: $FirmwarePath"
echo "Log Dizini: $LogDir"
echo "EMBA Dizin: $EMBA_PATH"

emba_dir=$(dirname "$EMBA_PATH")
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
LAVA_ROOT="$(dirname "$SCRIPT_DIR")"
PROFILE_SRC="$LAVA_ROOT/EMBA - Scan Profile/lava.00-quick-scan.emba"

if [ -f "$PROFILE_SRC" ]; then
    echo "Hizli tarama profili bulundu, kopyalaniyor: $PROFILE_SRC"
    sudo cp "$PROFILE_SRC" "$emba_dir/scan-profiles/"
    PROFILE_ARG="-p ./scan-profiles/lava.00-quick-scan.emba"
else
    echo "Uyari: Hizli tarama profili bulunamadi, varsayilan tarama yapilacak."
    PROFILE_ARG=""
fi

# Force PTY using script to preserve EMBA's native TUI with ANSI escape codes
sudo bash -c "cd '$emba_dir' && script -q -e -c \"./emba -f '$FirmwarePath' -l '$LogDir' $PROFILE_ARG\" /dev/null"
if [ $? -ne 0 ]; then
    echo "Hata: EMBA taramasi basarisiz oldu veya EMBA bulunamadi!"
    exit 1
fi

echo "[OK] EMBA taramasi tamamlandi!"

# 3. LAVA analizini baslat
echo ""
echo "[2/2] LAVA yapay zeka analizi baslatiliyor..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
bash "$SCRIPT_DIR/run_lava.sh" -LogDir "$LogDir"

if [ $? -ne 0 ]; then
    echo "Hata: LAVA analizi basarisiz oldu!"
    exit 1
fi

echo ""
echo "========================================="
echo "FULL PIPELINE TAMAMLANDI!"
echo "========================================="
