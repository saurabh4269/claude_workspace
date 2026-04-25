#!/usr/bin/env bash
set -euo pipefail

COMPOSE_URL="https://raw.githubusercontent.com/saurabh4269/verity/main/docker-compose.yml"
UI_URL="http://localhost"
API_URL="http://localhost:8000"

# ── Colours ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}${BOLD}[Verity]${RESET} $*"; }
success() { echo -e "${GREEN}${BOLD}[Verity]${RESET} $*"; }
warn()    { echo -e "${YELLOW}${BOLD}[Verity]${RESET} $*"; }
error()   { echo -e "${RED}${BOLD}[Verity]${RESET} $*" >&2; exit 1; }

echo ""
echo -e "${BOLD}╔══════════════════════════════════════╗${RESET}"
echo -e "${BOLD}║        Verity — SBOM Validator       ║${RESET}"
echo -e "${BOLD}╚══════════════════════════════════════╝${RESET}"
echo ""

# ── 1. Detect OS ───────────────────────────────────────────────────────────────
OS="$(uname -s)"
info "Detected OS: $OS"

# ── 2. Check / install Docker ──────────────────────────────────────────────────
if ! command -v docker &>/dev/null; then
    warn "Docker is not installed."

    if [[ "$OS" == "Linux" ]]; then
        info "Installing Docker automatically..."
        curl -fsSL https://get.docker.com | sh
        # Add current user to docker group so they don't need sudo
        sudo usermod -aG docker "$USER" 2>/dev/null || true
        warn "Docker installed. You may need to log out and back in for group changes to take effect."
        warn "If the next step fails, run: newgrp docker"
    elif [[ "$OS" == "Darwin" ]]; then
        echo ""
        error "Please install Docker Desktop for Mac first:
  https://www.docker.com/products/docker-desktop/
  After installing, open Docker Desktop, wait for it to start, then re-run this script."
    else
        error "Unsupported OS. Install Docker manually from https://docs.docker.com/get-docker/ and re-run this script."
    fi
fi

# ── 3. Check Docker is running ─────────────────────────────────────────────────
info "Checking Docker daemon..."
if ! docker info &>/dev/null; then
    if [[ "$OS" == "Darwin" ]]; then
        warn "Docker Desktop is not running. Attempting to start it..."
        open -a Docker
        info "Waiting for Docker to start (this can take up to 30 seconds)..."
        for i in $(seq 1 30); do
            docker info &>/dev/null && break
            sleep 2
        done
    fi

    if ! docker info &>/dev/null; then
        error "Docker daemon is not running. Please start Docker Desktop and re-run this script."
    fi
fi
success "Docker is running."

# ── 4. Check Docker Compose ────────────────────────────────────────────────────
if ! docker compose version &>/dev/null; then
    error "Docker Compose plugin not found. Please update Docker Desktop or install the Compose plugin:
  https://docs.docker.com/compose/install/"
fi

# ── 5. Pull and start Verity ───────────────────────────────────────────────────
info "Starting Verity (pulling images on first run — this may take a few minutes)..."
docker compose -f "$COMPOSE_URL" up -d

# ── 6. Wait for backend health ─────────────────────────────────────────────────
info "Waiting for Verity to be ready..."
for i in $(seq 1 30); do
    if curl -sf "$API_URL/health" &>/dev/null; then
        break
    fi
    sleep 3
done

if ! curl -sf "$API_URL/health" &>/dev/null; then
    warn "Verity is taking longer than expected. Check status with: docker compose logs"
else
    echo ""
    success "Verity is up and running!"
    echo ""
    echo -e "  ${BOLD}Web UI:${RESET}  ${CYAN}$UI_URL${RESET}"
    echo -e "  ${BOLD}API:${RESET}     ${CYAN}$API_URL${RESET}"
    echo -e "  ${BOLD}API Docs:${RESET} ${CYAN}$API_URL/docs${RESET}"
    echo ""
    echo -e "  To stop:   ${BOLD}docker compose -f $COMPOSE_URL down${RESET}"
    echo -e "  To update: ${BOLD}docker compose -f $COMPOSE_URL pull && docker compose -f $COMPOSE_URL up -d${RESET}"
    echo ""
fi
