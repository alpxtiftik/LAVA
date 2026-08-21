<#
.SYNOPSIS
    LAVA Arayüzü Derleme (Build) Scripti
.DESCRIPTION
    start_ui.py ve ui/ klasörünü tek bir LAVA_UI.exe dosyasına dönüştürür.
#>

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "LAVA UI Masaüstü Uygulaması Derleniyor..." -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan

# Gerekli bağımlılıkları kontrol et
Write-Host "[1/3] Kütüphaneler kontrol ediliyor..." -ForegroundColor Yellow
pip install -r requirements.txt

Write-Host "`n[2/3] PyInstaller çalıştırılıyor (Bu işlem biraz sürebilir)..." -ForegroundColor Yellow
# PyInstaller ayarları:
# --noconsole: Arka planda siyah cmd penceresi açılmasın
# --onefile: Tek bir .exe çıktısı versin
# --add-data "ui;ui": Arayüz kodlarını (HTML/CSS/JS) pakete dahil et (Windows için ayraç noktalı virgüldür ;)
# --name "LAVA_UI": Çıktı dosyasının adı
pyinstaller --noconsole --onefile --add-data "ui;ui" --name "LAVA_UI" start_ui.py

if ($LASTEXITCODE -ne 0) {
    Write-Host "Hata: PyInstaller derlemesi başarısız oldu!" -ForegroundColor Red
    exit $LASTEXITCODE
}

Write-Host "`n[3/3] Derleme tamamlandı. Geçici dosyalar temizleniyor..." -ForegroundColor Yellow
# Gereksiz geçici dosyaları temizle
Remove-Item -Recurse -Force build
Remove-Item LAVA_UI.spec

Write-Host "`n=========================================" -ForegroundColor Cyan
Write-Host "[OK] LAVA_UI.exe başarıyla oluşturuldu!" -ForegroundColor Green
Write-Host "Çıktı klasörü: .\dist\LAVA_UI.exe" -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Cyan
