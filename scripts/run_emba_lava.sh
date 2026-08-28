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
        *) echo "Bilinmeyen parametre: $1"; exit 2 ;;
    esac
    shift
done

if [ -z "$FirmwarePath" ]; then
    echo "Kullanim: $0 -FirmwarePath <path> [-LogDir <dir>]"
    exit 2
fi

if [ -z "$LogDir" ]; then
    FIRMWARE_DIR=$(dirname "$FirmwarePath")
    FIRMWARE_BASENAME=$(basename "$FirmwarePath")
    TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
    LogDir="${FIRMWARE_DIR}/lava_scan_${FIRMWARE_BASENAME}_${TIMESTAMP}"
    echo "[*] LogDir belirtilmedi, otomatik olusturuldu: $LogDir"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
LAVA_ROOT="$(dirname "$SCRIPT_DIR")"

AI_PROVIDER="local"
if [ -f "$LAVA_ROOT/config/ai_config.env" ]; then
    prov_val=$(grep "AI_PROVIDER" "$LAVA_ROOT/config/ai_config.env" | cut -d '=' -f2 | tr -d '"' | tr -d "'")
    [ -n "$prov_val" ] && AI_PROVIDER="$prov_val"
fi

# Ollama arka planda calismiyorsa baslat
if [ "$AI_PROVIDER" != "gemini" ] && [[ "$AI_PROVIDER" != mcp* ]] && ! curl -s http://localhost:11434/ > /dev/null; then
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

# Aday yollari tanimla (Guvenlik sebebiyle dinamik command -v ve home dizini taramalari kaldirildi)
CANDIDATE_PATHS=(
    "/emba/emba"
    "/opt/emba/emba"
    "/usr/local/emba/emba"
    "/root/emba/emba"
    "/home/kali/emba/emba"
	"/home/ahtiftik/emba"
)

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
        # Eger kullanici klasor vermisse (or: /opt/emba), icindeki emba dosyasina bak
        if [ -d "$p" ] && [ -f "$p/emba" ]; then
            p="$p/emba"
        fi
        
        # Dosya varsa ve calistirilabilirse sec
        if [ -x "$p" ]; then
            EMBA_PATH="$p"
            break
        fi
    fi
done

if [ -z "$EMBA_PATH" ]; then
    echo "Hata: EMBA calistirilabilir dosyasi bulunamadi veya calistirma izni (execute) yok!"
    echo "Lutfen EMBA'nin kurulu oldugundan ve '+x' iznine sahip oldugundan emin olun. (Beklenen yerler: /opt/emba/emba, /home/kali/emba/emba vb.)"
    exit 2
fi

if [ ! -f "$FirmwarePath" ]; then
    echo "Hata: Firmware dosyasi bulunamadi: $FirmwarePath"
    exit 2
fi

echo "[1/2] EMBA calistiriliyor..."
echo "Firmware: $FirmwarePath"
echo "Ana Dizin (LAVA & EMBA): $LogDir"
echo "EMBA Dizin: $EMBA_PATH"

emba_dir=$(dirname "$EMBA_PATH")
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
LAVA_ROOT="$(dirname "$SCRIPT_DIR")"
PROFILE_SRC="$LAVA_ROOT/EMBA - Scan Profile/lava.00-quick-scan.emba"

if [ -f "$PROFILE_SRC" ]; then
    echo "Hizli tarama profili bulundu, kopyalaniyor: $PROFILE_SRC"
    sudo mkdir -p "$emba_dir/scan-profiles/"
    sudo cp "$PROFILE_SRC" "$emba_dir/scan-profiles/"
    PROFILE_ARG="-p lava.00-quick-scan.emba"
else
    echo "Uyari: Hizli tarama profili bulunamadi, varsayilan tarama yapilacak."
    PROFILE_ARG=""
fi

# Dizinleri ayarla
PARENT_DIR="$LogDir"
EMBA_DIR="$PARENT_DIR/emba_logs"
LAVA_OUT_DIR="$PARENT_DIR/lava_out"

# Run EMBA directly. Python's PTY will handle the terminal dimensions and UTF-8 base64 encoding.
cd "$emba_dir"
sudo LC_ALL="en_US.UTF-8" LANG="en_US.UTF-8" ./emba -f "$FirmwarePath" -l "$EMBA_DIR" $PROFILE_ARG
if [ $? -ne 0 ]; then
    echo "Hata: EMBA taramasi basarisiz oldu veya EMBA bulunamadi!"
    exit 2
fi

echo "[OK] EMBA taramasi tamamlandi!"

# 3. LAVA analizini baslat
# EMBA log dizini root tarafindan olusturuldu, LAVA tarafindan okunabilmesi icin izinleri duzeltelim
sudo chown -R "$USER:$USER" "$PARENT_DIR" 2>/dev/null

echo ""
echo "[2/2] LAVA yapay zeka analizi baslatiliyor..."
cd "$LAVA_ROOT" || exit 2
bash "$SCRIPT_DIR/run_lava.sh" -LogDir "$EMBA_DIR" -OutDir "$LAVA_OUT_DIR"

if [ $? -ne 0 ]; then
    echo "Hata: LAVA yapay zeka analizi adiminda (run_lava.sh) hata olustu! Ayrintilar icin LAVA loglarini kontrol edin."
    exit 2
fi

echo ""
echo "========================================="
echo "FULL PIPELINE TAMAMLANDI!"
echo "========================================="
