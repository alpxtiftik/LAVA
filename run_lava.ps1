<#
.SYNOPSIS
    LAVA (Local AI Vulnerability Assessor) Pipeline Runner
.DESCRIPTION
    EMBA'nın ürettiği logları alıp parse eden, bağlamla zenginleştiren ve
    son olarak yerel yapay zeka ile TP/FP analizini gerçekleştiren ana betik.
.PARAMETER LogDir
    EMBA taramasının ana log klasörü.
.EXAMPLE
    .\run_lava.ps1 -LogDir "lava_iotgoat_log"
#>
param(
    [Parameter(Mandatory=$true)]
    [string]$LogDir
)

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "LAVA Pipeline Başlatılıyor..." -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan

# 1. Parse
Write-Host "[1/3] EMBA logları ayrıştırılıyor (parse)..." -ForegroundColor Yellow
py parse_emba_findings.py --log-dir $LogDir --out findings.json --merged-out merged_findings.json
if ($LASTEXITCODE -ne 0) { Write-Host "Hata: parse_emba_findings.py başarısız oldu!" -ForegroundColor Red; exit $LASTEXITCODE }
Write-Host "[OK] Ayrıştırma tamamlandı." -ForegroundColor Green

# 2. Enrich
Write-Host "`n[2/3] Bağlam oluşturuluyor (enrich)..." -ForegroundColor Yellow
py enrich_context.py --findings merged_findings.json --log-dir $LogDir --out enriched_findings.json
if ($LASTEXITCODE -ne 0) { Write-Host "Hata: enrich_context.py başarısız oldu!" -ForegroundColor Red; exit $LASTEXITCODE }
Write-Host "[OK] Bağlam dosyaları (context) başarıyla eklendi." -ForegroundColor Green

# 3. Classify (AI)
Write-Host "`n[3/3] LLM Sınıflandırma Başlıyor (Bu adım uzun sürebilir)..." -ForegroundColor Yellow
py llm_classifier.py --mode run --config config/ai_config.env --enriched enriched_findings.json --out verdicts.json
if ($LASTEXITCODE -ne 0) { Write-Host "Hata: llm_classifier.py başarısız oldu!" -ForegroundColor Red; exit $LASTEXITCODE }
Write-Host "[OK] Sınıflandırma tamamlandı! Sonuçlar verdicts.json dosyasına yazıldı." -ForegroundColor Green

Write-Host "`n=========================================" -ForegroundColor Cyan
Write-Host "LAVA Tamamlandı!" -ForegroundColor Cyan
Write-Host "Sonuçları incelemek için arayüzü başlatın: py start_ui.py" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
