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

# Eger root degilsek ve terminal baglantimiz yoksa (GUI'den calisiyorsa), sudo sifre soramayacagi icin uyar
if [ "$EUID" -ne 0 ] && ! tty -s; then
    echo "HATA: EMBA'nin calisabilmesi icin ROOT yetkisine ihtiyaci var!"
    echo "Arayuz uzerinden sifre girilemedigi icin islem iptal edildi."
    echo "COZUM: Lutfen arayuzu kapatin ve terminalden baslatici komutun basina 'sudo' ekleyerek calistirin:"
    echo "       sudo bash scripts/start_linux.sh"
    exit 1
fi

# 1. EMBA_PATH'i dinamik olarak bul
EMBA_PATH=""

# Aday yollari tanimla
CANDIDATE_PATHS=(
    "$(command -v emba 2>/dev/null)"
    "/emba/emba"
    "/opt/emba/emba"
    "/usr/local/emba/emba"
    "/home/$USER/emba/emba"
    "/root/emba/emba"
)

# Config dosyasini oku ve listeye ekle
if [ -f "config/ai_config.env" ]; then
    while IFS='=' read -r key value; do
        if [ "$key" == "EMBA_PATH" ]; then
            config_path=$(echo "$value" | tr -d '"' | tr -d "'")
            CANDIDATE_PATHS+=("$config_path")
        fi
    done < config/ai_config.env
fi

# Aday yollari test et
for p in "${CANDIDATE_PATHS[@]}"; do
    if [ -n "$p" ]; then
        # Eger kullanici klasor vermisse (or: /home/kali/emba), icindeki emba dosyasina bak
        if [ -d "$p" ] && [ -f "$p/emba" ]; then
            p="$p/emba"
        fi
        
        # Dosya varsa ve calistirilabilirse sec
        if [ -f "$p" ]; then
            EMBA_PATH="$p"
            break
        fi
    fi
done

if [ -z "$EMBA_PATH" ]; then
    echo "Hata: EMBA calistirilabilir dosyasi bulunamadi!"
    echo "Lutfen 'config/ai_config.env' dosyasina dogru EMBA_PATH degerini girin."
    exit 1
fi

# Calistirma izni ver (gerekirse)
if [ ! -x "$EMBA_PATH" ]; then
    echo "Uyari: $EMBA_PATH icin calistirma izni yok, veriliyor..."
    sudo chmod +x "$EMBA_PATH"
fi

if [ ! -f "$FirmwarePath" ]; then
    echo "Hata: Firmware dosyasi bulunamadi: $FirmwarePath"
    exit 1
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
    sudo mkdir -p "$emba_dir/scan-profiles/"
    sudo cp "$PROFILE_SRC" "$emba_dir/scan-profiles/"
    PROFILE_ARG="-p ./scan-profiles/lava.00-quick-scan.emba"
else
    echo "Uyari: Hizli tarama profili bulunamadi, varsayilan tarama yapilacak."
    PROFILE_ARG=""
fi

# Force PTY using script to preserve EMBA's native TUI with ANSI escape codes
# We export variables to bash -c to avoid quoting nightmares with paths
sudo TERM="xterm-256color" COLUMNS="120" LINES="30" FirmwarePath="$FirmwarePath" LogDir="$LogDir" PROFILE_ARG="$PROFILE_ARG" bash -c 'cd "$1" && script -q -e -c "./emba -f \"$FirmwarePath\" -l \"$LogDir\" $PROFILE_ARG" /dev/null' _ "$emba_dir"
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
    echo "Hata: LAVA yapay zeka analizi adiminda (run_lava.sh) hata olustu! Ayrintilar icin LAVA loglarini kontrol edin."
    exit 1
fi

echo ""
echo "========================================="
echo "FULL PIPELINE TAMAMLANDI!"
echo "========================================="
