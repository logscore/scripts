#!/bin/sh
set -eu

usage() {
  echo "Usage: $0 <backup-user> <source-path> <public-key-file>"
  exit 1
}

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "Must run as root"
    exit 1
  fi
}

install_acl_tools() {
  if command -v setfacl >/dev/null 2>&1; then
    return
  fi

  if command -v apk >/dev/null 2>&1; then
    apk add --no-cache acl
    return
  fi

  if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    apt-get install -y acl
    return
  fi

  echo "Could not install ACL tools. Unsupported system."
  exit 1
}

create_user_if_missing() {
  user="$1"

  if id "$user" >/dev/null 2>&1; then
    return
  fi

  if command -v adduser >/dev/null 2>&1; then
    if command -v apk >/dev/null 2>&1; then
      adduser -D "$user"
      return
    fi

    adduser --disabled-password --gecos "" "$user"
    return
  fi

  if command -v useradd >/dev/null 2>&1; then
    useradd -m -s /bin/sh "$user"
    return
  fi

  echo "Could not create user. Unsupported system."
  exit 1
}

setup_ssh_key() {
  user="$1"
  pubkey_file="$2"

  home_dir=$(getent passwd "$user" | cut -d: -f6)
  ssh_dir="$home_dir/.ssh"
  auth_keys="$ssh_dir/authorized_keys"

  mkdir -p "$ssh_dir"
  chmod 700 "$ssh_dir"
  touch "$auth_keys"
  chmod 600 "$auth_keys"
  chown -R "$user:$user" "$ssh_dir"

  pubkey=$(cat "$pubkey_file")
  if ! grep -Fqx "$pubkey" "$auth_keys"; then
    echo "$pubkey" >> "$auth_keys"
  fi

  chown "$user:$user" "$auth_keys"
}

grant_parent_traverse() {
  user="$1"
  target="$2"

  current="/"
  old_ifs="$IFS"
  IFS="/"

  for part in $target; do
    [ -n "$part" ] || continue
    current="${current%/}/$part"

    if [ "$current" != "$target" ]; then
      setfacl -m "u:$user:--x" "$current"
    fi
  done

  IFS="$old_ifs"
}

grant_readonly_acl() {
  user="$1"
  target="$2"

  setfacl -R -m "u:$user:rX" "$target"
  setfacl -dR -m "u:$user:rX" "$target"
}

main() {
  [ "$#" -eq 3 ] || usage

  require_root

  backup_user="$1"
  source_path="$2"
  public_key_file="$3"

  if [ ! -d "$source_path" ]; then
    echo "Source path does not exist or is not a directory: $source_path"
    exit 1
  fi

  if [ ! -f "$public_key_file" ]; then
    echo "Public key file does not exist: $public_key_file"
    exit 1
  fi

  install_acl_tools
  create_user_if_missing "$backup_user"
  setup_ssh_key "$backup_user" "$public_key_file"
  grant_parent_traverse "$backup_user" "$source_path"
  grant_readonly_acl "$backup_user" "$source_path"

  echo "Done."
  echo "User: $backup_user"
  echo "Source: $source_path"
  echo "Test:"
  echo "  su -s /bin/sh $backup_user -c 'find \"$source_path\" | head'"
}

main "$@"
