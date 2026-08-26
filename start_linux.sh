#!/bin/bash
# LAVA Linux Baslatici (Plug-and-Play)
# Bu script, LAVA'yi Linux uzerinde hatasiz calistirmak icin sanal ortam kurar ve baslatir.

cd "$(dirname "$0")"

echo "========================================="
echo "LAVA UI Baslatiliyor (Linux)..."
echo "========================================="

# Gerekli sistem paketlerinin kurulu oldugundan emin ol
if ! command -v python3 &> /dev/null; then
    echo "Hata: python3 bulunamadi. Lutfen Python yukleyin."
    exit 1
fi

# Debian/Kali tabanli sistemler icin venv kontrolu
if command -v apt-get &> /dev/null; then
    if ! dpkg -s python3-venv &> /dev/null; then
        echo "python3-venv paketi eksik. Yukleniyor..."
        sudo apt-get update && sudo apt-get install -y python3-venv
    fi
fi

# Sanal ortam olustur
if [ ! -d ".venv" ]; then
    echo "Sanal ortam (venv) olusturuluyor..."
    python3 -m venv .venv
fi

# Sanal ortami aktif et
source .venv/bin/activate

# Bagimliliklari yukle
echo "Kutuphaneler guncelleniyor (Bu islem ilk calistirmada biraz surebilir)..."
pip install --upgrade pip > /dev/null 2>&1
pip install -r requirements.txt > /dev/null 2>&1
pip install PyQt6 PyQtWebEngine qtpy > /dev/null 2>&1

echo "[OK] LAVA arayuzu aciliyor..."
# Root olarak calistirilirsa Chromium sandbox hatasini onlemek icin flag ekle
QTWEBENGINE_CHROMIUM_FLAGS="--no-sandbox" python3 src/gui/gui_main.py
