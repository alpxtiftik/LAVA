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

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "LAVA Pipeline Baslatiliyor..." -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan

# 1. Parse
Write-Host "[1/3] EMBA loglari ayristiriliyor (parse)..." -ForegroundColor Yellow
py parser_and_enrichs/parse_emba_findings.py --log-dir $LogDir --out findings.json --merged-out merged_findings.json
if ($LASTEXITCODE -ne 0) { Write-Host "Hata: parse_emba_findings.py basarisiz oldu!" -ForegroundColor Red; exit $LASTEXITCODE }
Write-Host "[OK] Ayristirma tamamlandi." -ForegroundColor Green

# 2. Enrich
Write-Host "`n[2/3] Baglam olusturuluyor (enrich)..." -ForegroundColor Yellow
py parser_and_enrichs/enrich_context.py --merged merged_findings.json --log-dir $LogDir --out enriched_findings.json
if ($LASTEXITCODE -ne 0) { Write-Host "Hata: enrich_context.py basarisiz oldu!" -ForegroundColor Red; exit $LASTEXITCODE }
Write-Host "[OK] Baglam dosyalari (context) basariyla eklendi." -ForegroundColor Green

# 3. Classify (AI)
Write-Host "`n[3/3] LLM Siniflandirma Basliyor (Bu adim uzun surebilir)..." -ForegroundColor Yellow
py llm_classifier.py --mode run --config config/ai_config.env --ground-truth ground_truth.json --enriched enriched_findings.json --out verdicts.json
if ($LASTEXITCODE -ne 0) { Write-Host "Hata: llm_classifier.py basarisiz oldu!" -ForegroundColor Red; exit $LASTEXITCODE }
Write-Host "[OK] Siniflandirma tamamlandi! Sonuclar verdicts.json dosyasina yazildi." -ForegroundColor Green

Write-Host "`n=========================================" -ForegroundColor Cyan
Write-Host "LAVA Tamamlandi!" -ForegroundColor Cyan
Write-Host "Sonuclari incelemek icin arayuzu baslatin: py start_ui.py" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
