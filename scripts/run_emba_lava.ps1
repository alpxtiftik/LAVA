<#
.SYNOPSIS
    LAVA Full Pipeline Runner for Windows (WSL)
.DESCRIPTION
    Bu betik, verilen bir firmware dosyasini WSL uzerindeki EMBA araci ile tarar.
    Tarama tamamlandiktan sonra sonuclari LAVA AI analizine sokar.
.PARAMETER FirmwarePath
    Analiz edilecek firmware'in Windows uzerindeki tam yolu.
.PARAMETER LogDir
    EMBA'nin sonuclari cikaracagi Windows uzerindeki dizin (LAVA bu dizini okuyacak).
#>
param(
    [Parameter(Mandatory=$true)]
    [string]$FirmwarePath,

    [Parameter(Mandatory=$true)]
    [string]$LogDir
)

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "LAVA FULL PIPELINE BASLATILIYOR (WSL)" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan

# 1. Config'den EMBA_PATH oku
$ConfigPath = "config/ai_config.env"
$EmbaPath = "/root/emba/emba" # Varsayilan
if (Test-Path $ConfigPath) {
    foreach ($line in Get-Content $ConfigPath) {
        if ($line -match "^\s*EMBA_PATH=(.*)$") {
            $EmbaPath = $matches[1].Trim()
        }
    }
}

# 2. Path'leri WSL formatina donustur
Write-Host "[1/2] WSL uzerinde EMBA calistiriliyor..." -ForegroundColor Yellow
Write-Host "Firmware: $FirmwarePath"
Write-Host "Log Dizini: $LogDir"
Write-Host "EMBA Dizin: $EmbaPath"

$wslCmd = "fw_path=`$(wslpath -a '$FirmwarePath'); log_path=`$(wslpath -a '$LogDir'); $EmbaPath -f `$fw_path -l `$log_path"

wsl -u root -- bash -c $wslCmd
if ($LASTEXITCODE -ne 0) {
    Write-Host "Hata: EMBA taramasi basarisiz oldu veya EMBA bulunamadi!" -ForegroundColor Red
    exit $LASTEXITCODE
}

Write-Host "[OK] EMBA taramasi tamamlandi!" -ForegroundColor Green

# 3. LAVA analizini baslat
Write-Host "`n[2/2] LAVA yapay zeka analizi baslatiliyor..." -ForegroundColor Yellow
$RunLava = Join-Path -Path $PSScriptRoot -ChildPath "run_lava.ps1"
& powershell -ExecutionPolicy Bypass -File $RunLava -LogDir $LogDir

if ($LASTEXITCODE -ne 0) {
    Write-Host "Hata: LAVA analizi basarisiz oldu!" -ForegroundColor Red
    exit $LASTEXITCODE
}

Write-Host "`n=========================================" -ForegroundColor Cyan
Write-Host "FULL PIPELINE TAMAMLANDI!" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
