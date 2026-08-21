#!/bin/bash
# LAVA UI Linux/macOS Derleme Betigi

echo "========================================="
echo "LAVA UI Linux/macOS Uygulaması Derleniyor..."
echo "========================================="

echo "[1/3] Kütüphaneler kontrol ediliyor..."
pip3 install -r requirements.txt

echo "[2/3] PyInstaller çalıştırılıyor (Bu işlem biraz sürebilir)..."
pyinstaller --noconfirm --onedir --windowed --add-data "ui:ui" --add-data "config:config" --name "LAVA_UI" start_ui.py

echo "[3/3] Derleme tamamlandı. Geçici dosyalar temizleniyor..."
rm -rf build/
rm -f LAVA_UI.spec

echo "========================================="
echo "[OK] LAVA_UI başarıyla oluşturuldu!"
echo "Çıktı klasörü: ./dist/LAVA_UI/LAVA_UI"
echo "Çalıştırmak için: ./dist/LAVA_UI/LAVA_UI"
echo "========================================="
