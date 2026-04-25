# Verity Setup Script for Windows
# Run in PowerShell as Administrator if Docker is not yet installed.
# Usage: Right-click -> "Run with PowerShell"  OR  powershell -ExecutionPolicy Bypass -File setup.ps1

$ComposeUrl = "https://raw.githubusercontent.com/saurabh4269/verity/main/docker-compose.yml"
$UiUrl      = "http://localhost"
$ApiUrl     = "http://localhost:8000"

function Write-Header {
    Write-Host ""
    Write-Host "╔══════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║        Verity — SBOM Validator       ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Info    { param($msg) Write-Host "[Verity] $msg" -ForegroundColor Cyan }
function Write-Success { param($msg) Write-Host "[Verity] $msg" -ForegroundColor Green }
function Write-Warn    { param($msg) Write-Host "[Verity] $msg" -ForegroundColor Yellow }
function Write-Err     { param($msg) Write-Host "[Verity] ERROR: $msg" -ForegroundColor Red; exit 1 }

Write-Header

# ── 1. Check Docker ────────────────────────────────────────────────────────────
Write-Info "Checking for Docker..."

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Warn "Docker is not installed."
    Write-Host ""
    Write-Host "Please install Docker Desktop for Windows:" -ForegroundColor Yellow
    Write-Host "  https://www.docker.com/products/docker-desktop/" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "After installing:" -ForegroundColor Yellow
    Write-Host "  1. Open Docker Desktop and wait for it to start (whale icon in taskbar)" -ForegroundColor White
    Write-Host "  2. Re-run this script" -ForegroundColor White
    Write-Host ""
    Read-Host "Press Enter to open the download page..."
    Start-Process "https://www.docker.com/products/docker-desktop/"
    exit 0
}

# ── 2. Check Docker is running ─────────────────────────────────────────────────
Write-Info "Checking Docker daemon..."
$dockerRunning = $false

for ($i = 0; $i -lt 15; $i++) {
    try {
        docker info 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) { $dockerRunning = $true; break }
    } catch {}

    if ($i -eq 0) {
        Write-Warn "Docker Desktop is not running. Attempting to start it..."
        $desktopPath = "$env:ProgramFiles\Docker\Docker\Docker Desktop.exe"
        if (Test-Path $desktopPath) {
            Start-Process $desktopPath
            Write-Info "Waiting for Docker Desktop to start (up to 60 seconds)..."
        }
    }
    Start-Sleep -Seconds 4
}

if (-not $dockerRunning) {
    Write-Err "Docker daemon is not responding. Please open Docker Desktop manually, wait for it to start, and re-run this script."
}

Write-Success "Docker is running."

# ── 3. Check Docker Compose ────────────────────────────────────────────────────
try {
    docker compose version 2>&1 | Out-Null
} catch {
    Write-Err "Docker Compose plugin not found. Please update Docker Desktop: https://www.docker.com/products/docker-desktop/"
}

# ── 4. Pull and start Verity ───────────────────────────────────────────────────
Write-Info "Starting Verity (pulling images on first run — this may take a few minutes)..."
docker compose -f $ComposeUrl up -d

if ($LASTEXITCODE -ne 0) {
    Write-Err "Failed to start Verity. Check the output above for details."
}

# ── 5. Wait for backend health ─────────────────────────────────────────────────
Write-Info "Waiting for Verity to be ready..."
$ready = $false

for ($i = 0; $i -lt 30; $i++) {
    try {
        $resp = Invoke-WebRequest -Uri "$ApiUrl/health" -UseBasicParsing -TimeoutSec 3 -ErrorAction SilentlyContinue
        if ($resp.StatusCode -eq 200) { $ready = $true; break }
    } catch {}
    Start-Sleep -Seconds 3
}

if (-not $ready) {
    Write-Warn "Verity is taking longer than expected. Check status with: docker compose logs"
} else {
    Write-Host ""
    Write-Success "Verity is up and running!"
    Write-Host ""
    Write-Host "  Web UI:   $UiUrl"   -ForegroundColor Cyan
    Write-Host "  API:      $ApiUrl"  -ForegroundColor Cyan
    Write-Host "  API Docs: $ApiUrl/docs" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  To stop:   docker compose -f $ComposeUrl down"
    Write-Host "  To update: docker compose -f $ComposeUrl pull; docker compose -f $ComposeUrl up -d"
    Write-Host ""
    Start-Process $UiUrl
}
