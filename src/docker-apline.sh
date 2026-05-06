#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "Run as root (try: sudo $0)" >&2
  exit 1
fi

ALPINE_VER="$(cut -d. -f1,2 /etc/alpine-release 2>/dev/null || true)"

enable_community_repo() {
  local repo_file="/etc/apk/repositories"

  if [[ ! -f "$repo_file" ]]; then
    echo "Missing $repo_file" >&2
    exit 1
  fi

  if grep -Eq '^[[:space:]]*#.*\/community' "$repo_file"; then
    sed -i -E 's|^[[:space:]]*#([[:space:]]*https?://.*/alpine/.*/community.*)|\1|' \
      "$repo_file"
  fi

  if ! grep -Eq '^[[:space:]]*https?://.*/alpine/.*/community' "$repo_file"; then
    if [[ -n "$ALPINE_VER" ]]; then
      echo "https://dl-cdn.alpinelinux.org/alpine/v${ALPINE_VER}/community" \
        >>"$repo_file"
    else
      echo "Could not detect Alpine version to add community repo." >&2
      exit 1
    fi
  fi
}

echo "Enabling community repository (needed for docker compose on many Alpine installs)..."
enable_community_repo

echo "Updating apk index..."
apk update

echo "Installing Docker + Docker Compose (v2 plugin)..."
apk add --no-cache docker docker-cli-compose

echo "Enabling Docker to start on boot (OpenRC)..."
rc-update add docker default

echo "Starting Docker now..."
service docker start

echo "Docker installed:"
docker version

echo "Docker Compose installed:"
docker compose version

cat <<'EOF'

Optional: allow your user to run docker without sudo
  addgroup -S docker || true
  adduser "$(whoami)" docker
Then log out and log back in.

EOF
