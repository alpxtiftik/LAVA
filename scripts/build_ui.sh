#!/bin/bash
# LAVA Arayüzü Derleme (Build) Scripti (Linux/macOS)

# Scriptin bulunduğu dizinden bağımsız olarak kök dizine geç
cd "$(dirname "$0")/.."

echo "========================================="
echo "LAVA UI Masaüstü Uygulaması Derleniyor..."
echo "========================================="

echo "[1/3] Kütüphaneler kontrol ediliyor..."
pip3 install -r requirements.txt

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
