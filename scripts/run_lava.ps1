<#
.SYNOPSIS
    LAVA (Local AI Vulnerability Auditor) Pipeline Runner
.DESCRIPTION
    EMBA'nin urettigi loglari alip parse eden, baglamla zenginlestiren ve
    son olarak yerel yapay zeka ile TP/FP analizini gerceklestiren ana betik.
.PARAMETER LogDir
    EMBA taramasinin ana log klasoru.
.EXAMPLE
    .\run_lava.ps1 -LogDir "lava_iotgoat_log"
#>
param(
    [Parameter(Mandatory=$true)]
    [string]$LogDir
)

# Konsol çıktısını UTF-8 olarak ayarla (Türkçe karakterlerin bozulmaması için)
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$OutDir = Join-Path -Path $LogDir -ChildPath "lava_out"
if (-not (Test-Path -Path $OutDir)) {
    New-Item -ItemType Directory -Path $OutDir | Out-Null
}

$PidFile = Join-Path -Path $OutDir -ChildPath "lava.pid"
if (Test-Path $PidFile) {
    $OldPid = Get-Content $PidFile
    $OldProcess = Get-Process -Id $OldPid -ErrorAction SilentlyContinue
    if ($OldProcess) {
        Write-Host "Uyari: Bu klasorde onceki bir tarama devam ediyor (PID: $OldPid). Kapatiliyor..." -ForegroundColor Yellow
        taskkill /F /T /PID $OldPid 2>$null
        Start-Sleep -Seconds 1
    }
}
$PID | Out-File -FilePath $PidFile -Encoding UTF8


$FindingsFile = Join-Path -Path $OutDir -ChildPath "findings.json"
$MergedFile = Join-Path -Path $OutDir -ChildPath "merged_findings.json"
$EnrichedFile = Join-Path -Path $OutDir -ChildPath "enriched_findings.json"
$VerdictsFile = Join-Path -Path $OutDir -ChildPath "verdicts.json"
$ReportFile = Join-Path -Path $OutDir -ChildPath "lava_report.html"

# Config dosyasindan IP ve PORT al
$AiIp = "127.0.0.1"
$AiPort = "11434"
$AiProvider = "local"
$ConfigPath = Join-Path -Path (Get-Location) -ChildPath "config\ai_config.env"
if (Test-Path $ConfigPath) {
    foreach ($line in Get-Content $ConfigPath) {
        if ($line -match "^\s*LOCAL_AI_IP\s*=\s*`"?([^`"\s]+)`"?") { $AiIp = $matches[1] }
        if ($line -match "^\s*LOCAL_AI_PORT\s*=\s*`"?([^`"\s]+)`"?") { $AiPort = $matches[1] }
        if ($line -match "^\s*AI_PROVIDER\s*=\s*`"?([^`"\s]+)`"?") { $AiProvider = $matches[1] }
    }
}

# Ollama arka planda calismiyorsa baslat (Sadece Localhost icin)
if ($AiProvider -ne "gemini") {
    try {
        $null = Invoke-RestMethod -Uri "http://${AiIp}:${AiPort}/" -Method Get -ErrorAction Stop
    } catch {
        if ($AiIp -eq "127.0.0.1" -or $AiIp -eq "localhost") {
            Write-Host "Ollama API'ye ulasilamadi (${AiIp}:${AiPort}). Arka planda baslatiliyor..." -ForegroundColor Yellow
            Start-Process -FilePath "ollama" -ArgumentList "serve" -WindowStyle Hidden -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 3
        } else {
            Write-Host "UYARI: Uzak Ollama sunucusuna (${AiIp}:${AiPort}) ulasilamadi!" -ForegroundColor Red
            Write-Host "Lutfen o makinedeki Ollama'nin calistigindan ve ag baglantisina acik oldugundan (OLLAMA_HOST=0.0.0.0) emin olun." -ForegroundColor Yellow
        }
    }
}

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "LAVA Pipeline Baslatiliyor..." -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan

# 1. Parse
Write-Host "[1/3] EMBA loglari ayristiriliyor (parse)..." -ForegroundColor Yellow
py src/core/parser.py --log-dir "$LogDir" --out "$FindingsFile" --merged-out "$MergedFile"
if ($LASTEXITCODE -ne 0) { Write-Host "Hata: parser.py basarisiz oldu!" -ForegroundColor Red; exit $LASTEXITCODE }
Write-Host "[OK] Ayristirma tamamlandi." -ForegroundColor Green

# 2. Enrich
Write-Host "`n[2/3] Baglam olusturuluyor (enrich)..." -ForegroundColor Yellow
py src/core/enricher.py --merged "$MergedFile" --log-dir "$LogDir" --out "$EnrichedFile"
if ($LASTEXITCODE -ne 0) { Write-Host "Hata: enricher.py basarisiz oldu!" -ForegroundColor Red; exit $LASTEXITCODE }
Write-Host "[OK] Baglam dosyalari (context) basariyla eklendi." -ForegroundColor Green

# 3. Classify (AI)
Write-Host "`n[3/3] LLM Siniflandirma Basliyor (Bu adim uzun surebilir)..." -ForegroundColor Yellow
py src/core/classifier.py --mode run --config config/ai_config.env --ground-truth ground_truth.json --enriched "$EnrichedFile" --out "$VerdictsFile"
if ($LASTEXITCODE -ne 0) { Write-Host "Hata: classifier.py basarisiz oldu!" -ForegroundColor Red; exit $LASTEXITCODE }
Write-Host "[OK] Siniflandirma tamamlandi! Sonuclar $VerdictsFile dosyasina yazildi." -ForegroundColor Green

# 4. Generate HTML Report
Write-Host "`n[4/4] HTML Raporu olusturuluyor..." -ForegroundColor Yellow
py src/reporting/html_report.py --verdicts "$VerdictsFile" --out "$ReportFile"
if ($LASTEXITCODE -ne 0) { Write-Host "Hata: html_report.py basarisiz oldu!" -ForegroundColor Red; exit $LASTEXITCODE }
Write-Host "[OK] Rapor tamamlandi! Cikti: $ReportFile" -ForegroundColor Green

Write-Host "`n=========================================" -ForegroundColor Cyan
Write-Host "LAVA Tamamlandi!" -ForegroundColor Cyan
Write-Host "Sonuclari incelemek icin arayuzu baslatin: LAVA_UI.exe" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
