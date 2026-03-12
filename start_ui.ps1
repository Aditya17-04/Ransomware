# start_ui.ps1
# ─────────────────────────────────────────────────────────────────────────────
# Launches the AI-RIDS Flask API bridge + React dev server side by side.
#
# Usage:
#   cd C:\EDI_SEM_2\Ransomware
#   .\start_ui.ps1
# ─────────────────────────────────────────────────────────────────────────────

$root = $PSScriptRoot

Write-Host "`n[AI-RIDS] Starting services...`n" -ForegroundColor Cyan

# ── 1. Flask API server ───────────────────────────────────────────────────────
Write-Host "[1/2] Starting Flask API server on http://localhost:5000" -ForegroundColor Yellow
$flaskJob = Start-Job -ScriptBlock {
    param($dir)
    Set-Location $dir
    python api_server.py
} -ArgumentList $root

# ── 2. React dev server ───────────────────────────────────────────────────────
Write-Host "[2/2] Starting React dev server on http://localhost:3000`n" -ForegroundColor Yellow

$uiPath = Join-Path $root "ui"

# Install npm deps if node_modules absent
if (-not (Test-Path (Join-Path $uiPath "node_modules"))) {
    Write-Host "  Installing npm packages (first run)..." -ForegroundColor DarkCyan
    Push-Location $uiPath
    npm install
    Pop-Location
}

try {
    Push-Location $uiPath
    npm run dev
} finally {
    Pop-Location
    Write-Host "`n[AI-RIDS] Stopping Flask job..." -ForegroundColor DarkGray
    Stop-Job  $flaskJob
    Remove-Job $flaskJob
}
