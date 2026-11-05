#!/usr/bin/env bash
# One-command installer for a fresh VPS (Ubuntu/Debian/others with curl). Run inside the project folder:
#   DOMAIN=panel.example.com ADMIN_PASS='a-strong-password' bash install.sh      (or run without variables and answer the questions)
set -euo pipefail
cd "$(dirname "$0")"
say(){ printf '\n\033[1m%s\033[0m\n' "$*"; }
if [ "$(id -u)" -ne 0 ] && ! command -v sudo >/dev/null 2>&1; then echo "Run as root (or install sudo)."; exit 1; fi
SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo"
if ! command -v docker >/dev/null 2>&1; then say "Installing Docker..."; curl -fsSL https://get.docker.com | $SUDO sh; fi
if docker compose version >/dev/null 2>&1; then DC="docker compose"; elif command -v docker-compose >/dev/null 2>&1; then DC="docker-compose"; else echo "docker compose plugin not found"; exit 1; fi
if [ ! -f .env ]; then
  DOMAIN="${DOMAIN:-}"; ADMIN_PASS="${ADMIN_PASS:-}"
  [ -n "$DOMAIN" ] || read -rp "Domain (its A record must already point to this server): " DOMAIN
  if ! printf '%s' "$DOMAIN" | grep -Eq '^[A-Za-z0-9]([A-Za-z0-9.-]{1,251})[A-Za-z0-9]$'; then echo "Invalid domain"; exit 1; fi
  if [ -z "$ADMIN_PASS" ]; then read -rsp "Admin password (min 8 characters): " ADMIN_PASS; echo; fi
  if [ "${#ADMIN_PASS}" -lt 8 ]; then echo "Password too short"; exit 1; fi
  case "$ADMIN_PASS" in *\$*|*\"*|*\`*|*\\*) echo "Please avoid \$ \" \` \\ in the password"; exit 1;; esac
  printf 'DOMAIN=%s\nADMIN_PASS=%s\nTRUST_CF=%s\n' "$DOMAIN" "$ADMIN_PASS" "${TRUST_CF:-0}" > .env
  chmod 600 .env
fi
if command -v ufw >/dev/null 2>&1 && $SUDO ufw status 2>/dev/null | grep -q "Status: active"; then $SUDO ufw allow 80/tcp >/dev/null; $SUDO ufw allow 443/tcp >/dev/null; fi
say "Building and starting..."
$SUDO $DC up -d --build
. ./.env
say "Done. Open https://$DOMAIN  (first start can take a minute while the certificate is issued)"
