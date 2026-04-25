#!/usr/bin/env bash
set -euo pipefail

IMAGE="ghcr.io/saurabh4269/verity:latest"
CONTAINER="verity"
PORT=8080

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
        sudo usermod -aG docker "$USER" 2>/dev/null || true
        warn "Docker installed. You may need to log out and back in for group changes to take effect."
        warn "If the next step fails, run: newgrp docker"
    elif [[ "$OS" == "Darwin" ]]; then
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
        info "Waiting for Docker to start (this can take up to 60 seconds)..."
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

# ── 4. Find a free port ────────────────────────────────────────────────────────
find_free_port() {
    local port=$1
    while lsof -iTCP:"$port" -sTCP:LISTEN &>/dev/null 2>&1 || \
          ss -tlnp "sport = :$port" 2>/dev/null | grep -q LISTEN; do
        warn "Port $port is in use, trying $((port+1))..."
        port=$((port+1))
    done
    echo "$port"
}
PORT=$(find_free_port $PORT)
info "Using port $PORT."

# ── 5. Clean up existing Verity container if present ──────────────────────────
if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER}$"; then
    warn "Existing Verity container found. Removing it..."
    docker stop "$CONTAINER" 2>/dev/null || true
    docker rm "$CONTAINER" 2>/dev/null || true
fi

# ── 6. Pull and start Verity ───────────────────────────────────────────────────
info "Starting Verity (pulling image on first run — this may take a few minutes)..."
docker run -d --name "$CONTAINER" -p "${PORT}:8080" -v verity-data:/app/data \
    --restart unless-stopped \
    -e HOST_PORT="${PORT}" \
    "$IMAGE"

# ── 7. Wait for health ────────────────────────────────────────────────────────
info "Waiting for Verity to be ready..."
for i in $(seq 1 30); do
    if curl -sf "http://localhost:${PORT}/health" &>/dev/null; then
        break
    fi
    sleep 3
done

if ! curl -sf "http://localhost:${PORT}/health" &>/dev/null; then
    warn "Verity is taking longer than expected. Check status with: docker logs $CONTAINER"
else
    echo ""
    success "Verity is up and running!"
    echo ""
    echo -e "  ${BOLD}Web UI:${RESET}   ${CYAN}http://localhost:${PORT}${RESET}"
    echo -e "  ${BOLD}API Docs:${RESET} ${CYAN}http://localhost:${PORT}/docs${RESET}"
    echo ""
    echo -e "  To stop:   ${BOLD}docker stop $CONTAINER${RESET}"
    echo -e "  To update: ${BOLD}docker pull $IMAGE && docker stop $CONTAINER && docker rm $CONTAINER && docker run -d --name $CONTAINER -p ${PORT}:8080 -v verity-data:/app/data $IMAGE${RESET}"
    echo ""
fi
