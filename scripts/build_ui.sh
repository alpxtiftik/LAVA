#!/bin/bash
# LAVA Arayüzü Derleme (Build) Scripti (Linux/macOS)

# Scriptin bulunduğu dizinden bağımsız olarak kök dizine geç
cd "$(dirname "$0")/.."

echo "========================================="
echo "LAVA UI Masaüstü Uygulaması Derleniyor..."
echo "========================================="

echo "[1/3] Kütüphaneler kontrol ediliyor (Sanal Ortam/venv)..."

# Create a virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    python3 -m venv --system-site-packages venv
fi

# Activate the virtual environment
source venv/bin/activate

pip install -r requirements.txt
# Linux icin PyQt bagimliliklarini kur (GTK hatasini onlemek icin)
pip install PyQt6 PyQtWebEngine qtpy

echo "[2/3] PyInstaller ile derleniyor..."
pyinstaller --noconsole --onefile --add-data "src/gui/ui:ui" --name "LAVA_UI" src/gui/gui_main.py

if [ $? -ne 0 ]; then
    echo "Hata: PyInstaller derlemesi başarısız oldu!"
    exit 1
fi

echo -e "\n[3/3] Derleme tamamlandı. Geçici dosyalar temizleniyor..."
rm -rf build LAVA_UI.spec
mv dist/LAVA_UI ./LAVA_UI
rm -rf dist

echo -e "\n========================================="
echo "[OK] LAVA_UI başarıyla oluşturuldu!"
echo "Çıktı dosyası: ./LAVA_UI"
echo "Lütfen uygulamayı başlatmak için ./LAVA_UI komutunu çalıştırın."
echo "========================================="
