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
        -Profile|--profile) ProfilePath="$2"; shift ;;
        *) echo "Bilinmeyen parametre: $1"; exit 2 ;;
    esac
    shift
done

if [ -z "$FirmwarePath" ] || [ -z "$LogDir" ]; then
    echo "Kullanim: $0 -FirmwarePath <path> -LogDir <dir>"
    exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
LAVA_ROOT="$(dirname "$SCRIPT_DIR")"

AI_PROVIDER="local"
if [ -f "$LAVA_ROOT/config/ai_config.env" ]; then
    prov_val=$(grep "AI_PROVIDER" "$LAVA_ROOT/config/ai_config.env" | cut -d '=' -f2 | tr -d '"' | tr -d "'")
    [ -n "$prov_val" ] && AI_PROVIDER="$prov_val"
fi

# Ollama arka planda calismiyorsa baslat
if [ "$AI_PROVIDER" != "gemini" ] && ! curl -s http://localhost:11434/ > /dev/null; then
    echo "Ollama API'ye ulasilamadi. Arka planda baslatiliyor..."
    nohup ollama serve > /dev/null 2>&1 &
    sleep 3
fi

echo "========================================="
echo "LAVA FULL PIPELINE BASLATILIYOR (LINUX)"
echo "========================================="

# Eger root degilsek ve terminal baglantimiz yoksa (GUI'den calisiyorsa), sudo sifre soramayacagi icin uyar
if [ "$EUID" -ne 0 ] && [ "$LAVA_GUI_MODE" == "1" ]; then
    echo "HATA: EMBA'nin calisabilmesi icin ROOT yetkisine ihtiyaci var!"
    echo "Arayuz uzerinden sifre girilemedigi icin islem iptal edildi."
    echo "COZUM: Lutfen arayuzu kapatin ve terminalden baslatici komutun basina 'sudo' ekleyerek calistirin:"
    echo "       sudo bash scripts/start_linux.sh"
    exit 2
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
    "/home/kali/emba/emba"
)

# Eger sudo ile calistirildiysa asil kullanicinin home dizinini de ekle
if [ -n "$SUDO_USER" ]; then
    CANDIDATE_PATHS+=("/home/$SUDO_USER/emba/emba")
fi

# Config dosyasini oku ve listeye ekle (Geriye donuk uyumluluk)
if [ -f "config/ai_config.env" ]; then
    while IFS='=' read -r key value; do
        if [ "$key" == "EMBA_PATH" ]; then
            config_path=$(echo "$value" | tr -d '"' | tr -d "'")
            CANDIDATE_PATHS=("$config_path" "${CANDIDATE_PATHS[@]}")
        fi
    done < "config/ai_config.env"
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
    echo "Lutfen EMBA'nin kurulu oldugundan emin olun. (Beklenen yerler: /opt/emba/emba, /home/kali/emba/emba vb.)"
    exit 2
fi

# Calistirma izni ver (gerekirse)
if [ ! -x "$EMBA_PATH" ]; then
    echo "Uyari: $EMBA_PATH icin calistirma izni yok, veriliyor..."
    sudo chmod +x "$EMBA_PATH"
fi

if [ ! -f "$FirmwarePath" ]; then
    echo "Hata: Firmware dosyasi bulunamadi: $FirmwarePath"
    exit 2
fi

echo "[1/2] EMBA calistiriliyor..."
echo "Firmware: $FirmwarePath"
echo "Log Dizini: $LogDir"
echo "EMBA Dizin: $EMBA_PATH"

emba_dir=$(dirname "$EMBA_PATH")
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
LAVA_ROOT="$(dirname "$SCRIPT_DIR")"
PROFILE_ARG=""
if [ -n "$ProfilePath" ] && [ -f "$ProfilePath" ]; then
    PROFILE_NAME=$(basename "$ProfilePath")
    echo "Ozel tarama profili bulundu, kopyalaniyor: $ProfilePath"
    sudo mkdir -p "$emba_dir/scan-profiles/"
    sudo cp "$ProfilePath" "$emba_dir/scan-profiles/"
    PROFILE_ARG="-p $PROFILE_NAME"
else
    echo "Bilgi: Ozel bir profil belirtilmedi, varsayilan (full) tarama yapilacak."
fi

# Run EMBA directly. Python's PTY will handle the terminal dimensions and UTF-8 base64 encoding.
cd "$emba_dir"
sudo LC_ALL="en_US.UTF-8" LANG="en_US.UTF-8" ./emba -f "$FirmwarePath" -l "$LogDir" $PROFILE_ARG
if [ $? -ne 0 ]; then
    echo "Hata: EMBA taramasi basarisiz oldu veya EMBA bulunamadi!"
    exit 2
fi

echo "[OK] EMBA taramasi tamamlandi!"

# 3. LAVA analizini baslat
echo ""
echo "[2/2] LAVA yapay zeka analizi baslatiliyor..."
cd "$LAVA_ROOT" || exit 2
bash "$SCRIPT_DIR/run_lava.sh" -LogDir "$LogDir"

if [ $? -ne 0 ]; then
    echo "Hata: LAVA yapay zeka analizi adiminda (run_lava.sh) hata olustu! Ayrintilar icin LAVA loglarini kontrol edin."
    exit 2
fi

echo ""
echo "========================================="
echo "FULL PIPELINE TAMAMLANDI!"
echo "========================================="
