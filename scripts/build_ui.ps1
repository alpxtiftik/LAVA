<#
.SYNOPSIS
    LAVA Arayüzü Derleme (Build) Scripti
.DESCRIPTION
    gui/gui_main.py ve gui/ui/ klasörünü tek bir LAVA_UI.exe dosyasına dönüştürür.
#>

# Konsol çıktısını UTF-8 olarak ayarla (Türkçe karakterlerin bozulmaması için)
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

# Scriptin bulunduğu klasörden bağımsız olarak ana dizine geç
Set-Location "$PSScriptRoot\.."

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
# --add-data "src/gui/ui;ui": Arayüz kodlarını (HTML/CSS/JS) pakete dahil et
# --name "LAVA_UI": Çıktı dosyasının adı
pyinstaller --noconsole --onefile --add-data "src/gui/ui;ui" --name "LAVA_UI" src/gui/gui_main.py

if ($LASTEXITCODE -ne 0) {
    Write-Host "Hata: PyInstaller derlemesi başarısız oldu!" -ForegroundColor Red
    exit $LASTEXITCODE
}

Write-Host "`n[3/3] Derleme tamamlandı. Geçici dosyalar temizleniyor..." -ForegroundColor Yellow
# Gereksiz geçici dosyaları temizle
Remove-Item -Recurse -Force build
Remove-Item LAVA_UI.spec
# LAVA_UI.exe'yi ana dizine tasi
try {
    Move-Item -Force dist\LAVA_UI.exe .\LAVA_UI.exe -ErrorAction Stop
    Remove-Item -Recurse -Force dist
    
    Write-Host "`n=========================================" -ForegroundColor Cyan
    Write-Host "[OK] LAVA_UI.exe basariyla olusturuldu!" -ForegroundColor Green
    Write-Host "Cikti dosyasi: .\LAVA_UI.exe" -ForegroundColor Green
    Write-Host "Lutfen uygulamayi baslatmak icin LAVA_UI.exe'ye cift tiklayin." -ForegroundColor Green
    Write-Host "=========================================" -ForegroundColor Cyan
} catch {
    Write-Host "`n=========================================" -ForegroundColor Red
    Write-Host "[HATA] LAVA_UI.exe ana dizine tasinamadi!" -ForegroundColor Red
    Write-Host "Muhtemelen LAVA uygulamasi su anda acik." -ForegroundColor Yellow
    Write-Host "Lutfen acik olan LAVA penceresini kapatin ve dist\LAVA_UI.exe dosyasini manuel olarak disari cikartin veya script'i tekrar calistirin." -ForegroundColor Yellow
    Write-Host "=========================================" -ForegroundColor Red
    exit 1
}
