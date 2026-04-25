#!/bin/sh
set -e

PORT="${HOST_PORT:-8080}"

printf '\n'
printf '╔══════════════════════════════════════╗\n'
printf '║       Verity — SBOM Validator        ║\n'
printf '╚══════════════════════════════════════╝\n'
printf '\n'
printf '  Web UI:   http://localhost:%s\n' "$PORT"
printf '  API Docs: http://localhost:%s/docs\n' "$PORT"
printf '\n'
printf '  To stop: docker stop verity\n'
printf '\n'

exec /usr/bin/supervisord -c /etc/supervisor/supervisord.conf
