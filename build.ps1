# Privacy Messenger — Build Script (Phase 3)
# Erstellt eine portable Windows .exe ohne Installation

Write-Host "🔐 Privacy Messenger — Build" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan

$ProjectDir = $PSScriptRoot

# 1. Check electron-builder
Write-Host "`n[1/3] Checking electron-builder..." -ForegroundColor Yellow
$eb = Get-Command "electron-builder" -ErrorAction SilentlyContinue
if (-not $eb) {
    Write-Host "  Installing electron-builder..." -ForegroundColor Gray
    npm install --save-dev electron-builder --prefix $ProjectDir
}

# 2. Ensure icon exists (create placeholder if missing)
$iconDir = Join-Path $ProjectDir "assets"
New-Item -ItemType Directory -Force -Path $iconDir | Out-Null

$icoPath = Join-Path $iconDir "icon.ico"
if (-not (Test-Path $icoPath)) {
    Write-Host "  No icon.ico found — skipping icon (app will use default)" -ForegroundColor Gray
    # Remove icon reference from package.json build config temporarily
}

# 3. Build
Write-Host "`n[2/3] Building portable .exe..." -ForegroundColor Yellow
Set-Location $ProjectDir

$env:CSC_IDENTITY_AUTO_DISCOVERY = "false"  # skip code signing

npx electron-builder --win portable --x64 2>&1 | ForEach-Object {
    if ($_ -match "error|Error") { Write-Host "  $_" -ForegroundColor Red }
    elseif ($_ -match "•") { Write-Host "  $_" -ForegroundColor Green }
    else { Write-Host "  $_" -ForegroundColor Gray }
}

# 4. Result
Write-Host "`n[3/3] Done!" -ForegroundColor Green
$distPath = Join-Path $ProjectDir "dist"
if (Test-Path $distPath) {
    $exes = Get-ChildItem $distPath -Filter "*.exe" -Recurse
    foreach ($exe in $exes) {
        $sizeMB = [math]::Round($exe.Length / 1MB, 1)
        Write-Host "  ✅ $($exe.Name)  ($sizeMB MB)" -ForegroundColor Green
        Write-Host "  📁 $($exe.FullName)" -ForegroundColor Cyan
    }
} else {
    Write-Host "  ❌ Build fehlgeschlagen — dist/ nicht gefunden" -ForegroundColor Red
}
