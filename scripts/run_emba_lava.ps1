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

# Ollama arka planda calismiyorsa baslat
try {
    $null = Invoke-RestMethod -Uri "http://localhost:11434/" -Method Get -ErrorAction Stop
} catch {
    Write-Host "Ollama API'ye ulasilamadi. Arka planda baslatiliyor..." -ForegroundColor Yellow
    Start-Process -FilePath "ollama" -ArgumentList "serve" -WindowStyle Hidden
    Start-Sleep -Seconds 3
}

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

$emba_dir = $EmbaPath.Substring(0, $EmbaPath.LastIndexOf('/'))

$ProfilePath = Join-Path -Path $PSScriptRoot -ChildPath "..\EMBA - Scan Profile\lava.00-quick-scan.emba"
$ProfileCopyCmd = ""
$ProfileArg = ""

if (Test-Path $ProfilePath) {
    Write-Host "Hizli tarama profili bulundu, kopyalaniyor..." -ForegroundColor Yellow
    $ProfileCopyCmd = "cp `"\`$(wslpath -a '$ProfilePath')`" `"$emba_dir/scan-profiles/`";"
    $ProfileArg = "-p ./scan-profiles/lava.00-quick-scan.emba"
}

# script -q -e -c ile sarmalayarak ANSI renk kodlarinin kaybolmamasini sagla
$wslCmd = "FW=`$(wslpath -a '$FirmwarePath'); LOG=`$(wslpath -a '$LogDir'); $ProfileCopyCmd cd '$emba_dir' && script -q -e -c `"./emba -f \`"\`$FW\`" -l \`"\`$LOG\`" $ProfileArg`" /dev/null"

Write-Host "CMD: $wslCmd"; wsl -u root -- bash -c $wslCmd
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
