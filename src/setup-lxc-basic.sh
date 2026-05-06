#!/bin/bash
set -euo pipefail

# --- Create user? ---
read -rp "Create a new user? (Y/n): " CREATE_USER
case "${CREATE_USER:-y}" in
  [Nn]*) CREATE_USER="no" ;;
  *) CREATE_USER="yes" ;;
esac

if [[ "$CREATE_USER" == "yes" ]]; then
  read -rp "New username: " USERNAME
  if [[ -z "$USERNAME" ]]; then echo "Error: username required." >&2; exit 1; fi

  read -rsp "New password: " PASSWORD
  echo
  if [[ -z "$PASSWORD" ]]; then echo "Error: password required." >&2; exit 1; fi

  # Loop until SSH key is provided
  while true; do
    read -rp "Your SSH public key: " PUBKEY
    if [[ -n "$PUBKEY" ]]; then
      break
    fi
    echo "[*] SSH key is required (password auth is disabled). Try again."
  done

  echo "[*] Creating user $USERNAME..."
  useradd -m -s /bin/bash "$USERNAME"
  echo "$USERNAME:$PASSWORD" | chpasswd
  usermod -aG sudo "$USERNAME"

  mkdir -p "/home/$USERNAME/.ssh"
  chmod 700 "/home/$USERNAME/.ssh"
  echo "$PUBKEY" > "/home/$USERNAME/.ssh/authorized_keys"
  chown -R "$USERNAME:$USERNAME" "/home/$USERNAME/.ssh"
  chmod 600 "/home/$USERNAME/.ssh/authorized_keys"
else
  echo "[*] Skipping user creation."
fi

# --- Root login option ---
read -rp "Disable root login entirely? (y/N): " DISABLE_ROOT
case "${DISABLE_ROOT:-n}" in
  [Yy]*) ROOT_SETTING="no" ;;
  *) ROOT_SETTING="prohibit-password" ;;
esac

# --- Backup & write sshd_config ---
echo "[*] Writing sshd_config..."
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%Y%m%d%H%M%S)

cat > /etc/ssh/sshd_config << EOF
# === PVE SSH Config ===

# Network
Port 22
AddressFamily any
ListenAddress 0.0.0.0
ListenAddress ::

# Authentication
PermitRootLogin $ROOT_SETTING
MaxAuthTries 3
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes

# Session
X11Forwarding no
PrintMotd no
AcceptEnv LANG LC_*

# Subsystem
Subsystem sftp /usr/lib/openssh/sftp-server

# Security hardening
ClientAliveInterval 300
ClientAliveCountMax 2
AllowAgentForwarding no
AllowTcpForwarding no

# Logging
LogLevel VERBOSE
SyslogFacility AUTH
EOF

echo "[*] Validating config..."
sshd -t

echo "[*] Restarting sshd..."
systemctl restart sshd

echo ""
if [[ "$CREATE_USER" == "yes" ]]; then
  echo "Done. User: $USERNAME | Root login: $ROOT_SETTING"
else
  echo "Done. No new user created. Root login: $ROOT_SETTING"
fi
echo "Old config backed up."
