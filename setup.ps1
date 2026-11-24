#!/usr/bin/env pwsh
<#
.SYNOPSIS
  Bastion One-Click Environment Setup Script (Windows PowerShell)
  Installs TruffleHog, BLA (bla-agents), Cloudflare Security Audit Skill,
  and prepares Bastion's FastAPI backend and Next.js frontend.
#>

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "==> Bastion Local-First DevSecOps Setup (Windows)" -ForegroundColor Cyan

# 1. TruffleHog
$LocalBin = Join-Path $env:USERPROFILE ".local\bin"
New-Item -ItemType Directory -Force -Path $LocalBin | Out-Null
$TruffleExe = Join-Path $LocalBin "trufflehog.exe"

if (-not (Get-Command trufflehog -ErrorAction SilentlyContinue) -and -not (Test-Path $TruffleExe)) {
    Write-Host "[1/5] Installing TruffleHog latest Windows amd64 release..."
    $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/trufflesecurity/trufflehog/releases/latest" -Headers @{"User-Agent"="Bastion-Setup"}
    $asset = $rel.assets | Where-Object { $_.name -match "windows_amd64\.tar\.gz$" } | Select-Object -First 1
    if (-not $asset) { throw "Could not locate TruffleHog windows_amd64 archive in latest release." }
    $tmpTar = Join-Path $env:TEMP $asset.name
    $tmpDir = Join-Path $env:TEMP "bastion_trufflehog_extract"
    if (Test-Path $tmpDir) { Remove-Item -Recurse -Force $tmpDir }
    New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null
    curl.exe -fsSL $asset.browser_download_url -o $tmpTar
    tar -xzf $tmpTar -C $tmpDir
    Copy-Item -Force (Join-Path $tmpDir "trufflehog.exe") $TruffleExe
    Remove-Item -Force $tmpTar
    Remove-Item -Recurse -Force $tmpDir
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($userPath -notlike "*$LocalBin*") {
        [Environment]::SetEnvironmentVariable("Path", "$userPath;$LocalBin", "User")
    }
    $env:Path = "$env:Path;$LocalBin"
}
Write-Host "    TruffleHog ready: $(& $TruffleExe --version 2>&1)"

# 2. BLA (qybaihe/bla)
Write-Host "[2/5] Installing BLA (bla-agents) globally via npm..."
& npm.cmd install -g bla-agents
Write-Host "    BLA ready: $(& bla.cmd --version 2>&1)"

# 3. Cloudflare Security Audit Skill
Write-Host "[3/5] Installing Cloudflare Security Audit Skill..."
$VendorSkill = Join-Path $Root "vendor\security-audit-skill"
if (-not (Test-Path $VendorSkill)) {
    New-Item -ItemType Directory -Force -Path (Join-Path $Root "vendor") | Out-Null
    git clone --depth 1 https://github.com/cloudflare/security-audit-skill.git $VendorSkill
}
& npx.cmd --yes skills add https://github.com/cloudflare/security-audit-skill --skill security-audit -y

# 4. Python Backend & Bastion CLI
Write-Host "[4/5] Configuring FastAPI backend virtual environment..."
$BackendDir = Join-Path $Root "backend"
$VenvPython = Join-Path $BackendDir ".venv\Scripts\python.exe"
if (-not (Test-Path $VenvPython)) {
    python -m venv --system-site-packages (Join-Path $BackendDir ".venv")
}
& (Join-Path $BackendDir ".venv\Scripts\pip.exe") install --default-timeout=120 --prefer-binary -r (Join-Path $BackendDir "requirements.txt")
& (Join-Path $BackendDir ".venv\Scripts\pip.exe") install --no-deps -e $BackendDir

# 5. Next.js Frontend
Write-Host "[5/5] Installing Next.js frontend dependencies..."
Push-Location (Join-Path $Root "frontend")
& npm.cmd install --no-audit --no-fund
Pop-Location

Write-Host ""
Write-Host "Setup complete. Start Bastion:" -ForegroundColor Green
Write-Host "  Backend : cd backend && .\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --port 8000"
Write-Host "  Frontend: cd frontend && npm.cmd run dev"
Write-Host "  CLI     : .\backend\.venv\Scripts\bastion.exe doctor"
