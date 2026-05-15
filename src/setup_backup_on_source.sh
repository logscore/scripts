#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "Run this as root." >&2
  exit 1
fi

if [ ! -r /etc/os-release ]; then
  echo "Cannot detect distro." >&2
  exit 1
fi

. /etc/os-release

install_acl() {
  if command -v setfacl >/dev/null 2>&1; then
    return
  fi

  case "${ID:-}" in
    alpine)
      apk add --no-cache acl
      ;;
    debian | ubuntu)
      apt-get update
      apt-get install -y acl
      ;;
    *)
      echo "Unsupported distro: ${ID:-unknown}" >&2
      exit 1
      ;;
  esac
}

create_user() {
  user="$1"

  if id "$user" >/dev/null 2>&1; then
    return
  fi

  case "${ID:-}" in
    alpine)
      adduser -D "$user"
      ;;
    debian | ubuntu)
      adduser --disabled-password --gecos "" "$user"
      ;;
    *)
      echo "Unsupported distro: ${ID:-unknown}" >&2
      exit 1
      ;;
  esac
}

get_home_dir() {
  user="$1"
  awk -F: -v u="$user" '$1 == u { print $6 }' /etc/passwd
}

grant_parent_traverse() {
  user="$1"
  path="$2"

  old_ifs=$IFS
  IFS='/'
  set -- $path
  IFS=$old_ifs

  current=""
  for part in "$@"; do
    [ -n "$part" ] || continue
    current="$current/$part"
    if [ "$current" != "$path" ]; then
      setfacl -m "u:$user:--x" "$current"
    fi
  done
}

printf "Backup username [backup]: "
read -r BACKUP_USER
BACKUP_USER=${BACKUP_USER:-backup}

printf "Absolute directory to back up: "
read -r TARGET_PATH

if [ -z "$TARGET_PATH" ]; then
  echo "Path is required." >&2
  exit 1
fi

case "$TARGET_PATH" in
  /*) ;;
  *)
    echo "Use an absolute path." >&2
    exit 1
    ;;
esac

if [ "$TARGET_PATH" != "/" ]; then
  TARGET_PATH=${TARGET_PATH%/}
fi

if [ ! -d "$TARGET_PATH" ]; then
  echo "Directory does not exist: $TARGET_PATH" >&2
  exit 1
fi

printf "Paste SSH public key: "
read -r PUBKEY

if [ -z "$PUBKEY" ]; then
  echo "Public key is required." >&2
  exit 1
fi

install_acl
create_user "$BACKUP_USER"

HOME_DIR=$(get_home_dir "$BACKUP_USER")
if [ -z "$HOME_DIR" ]; then
  echo "Could not determine home dir for $BACKUP_USER" >&2
  exit 1
fi

SSH_DIR="$HOME_DIR/.ssh"
AUTH_KEYS="$SSH_DIR/authorized_keys"

mkdir -p "$SSH_DIR"
touch "$AUTH_KEYS"
chmod 700 "$SSH_DIR"
chmod 600 "$AUTH_KEYS"
chown -R "$BACKUP_USER:$BACKUP_USER" "$SSH_DIR"

if ! grep -Fqx -- "$PUBKEY" "$AUTH_KEYS"; then
  printf "%s\n" "$PUBKEY" >> "$AUTH_KEYS"
fi

chown "$BACKUP_USER:$BACKUP_USER" "$AUTH_KEYS"

grant_parent_traverse "$BACKUP_USER" "$TARGET_PATH"
setfacl -R -m "u:$BACKUP_USER:rX" "$TARGET_PATH"
find "$TARGET_PATH" -type d -exec setfacl -m "d:u:$BACKUP_USER:rX" {} \;

echo
echo "Done."
echo "User: $BACKUP_USER"
echo "Path: $TARGET_PATH"
echo
echo "Test locally:"
echo "  su - $BACKUP_USER -c 'find $TARGET_PATH -maxdepth 2 | head'"
echo
echo "Backrest source example:"
echo "  sftp:$BACKUP_USER@host:$TARGET_PATH"
