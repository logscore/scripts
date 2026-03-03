#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# LXC Container Hardening Script
# Run as root inside the container
# Supports: Debian, Ubuntu, Alpine
# ============================================================

if [[ $EUID -ne 0 ]]; then
  echo "Run as root."
  exit 1
fi

# --- Detect distro ---
DISTRO="unknown"
if [ -f /etc/os-release ]; then
  . /etc/os-release
  case "$ID" in
    ubuntu | debian) DISTRO="debian" ;;
    alpine) DISTRO="alpine" ;;
  esac
fi

if [[ "$DISTRO" == "unknown" ]]; then
  echo "Unsupported distro."
  exit 1
fi

echo "Detected distro: $DISTRO"
echo "Starting hardening..."

# ============================================================
# 1. FILESYSTEM MOUNT HARDENING
# ============================================================
# Adds noexec, nosuid, nodev to /tmp and /dev/shm.
#
# WHAT IT DOES:
#   noexec  - prevents executing binaries from these paths
#   nosuid  - ignores setuid/setgid bits on binaries
#   nodev   - prevents creation of device files
#
# IMPACT:
#   You cannot run scripts or binaries directly from /tmp or
#   /dev/shm. Some poorly written installers or build tools
#   that execute from /tmp will break. You can temporarily
#   remount if needed: mount -o remount,exec /tmp
# ============================================================

echo "[1/10] Hardening filesystem mounts..."

FSTAB_ENTRIES=(
  "tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev,size=256m 0 0"
  "tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev,size=128m 0 0"
)

for entry in "${FSTAB_ENTRIES[@]}"; do
  mount_point=$(echo "$entry" | awk '{print $2}')
  grep -q "$mount_point" /etc/fstab 2>/dev/null && \
    sed -i "\|$mount_point|d" /etc/fstab
  echo "$entry" >> /etc/fstab
done

mount -o remount,noexec,nosuid,nodev /tmp 2>/dev/null || true
mount -o remount,noexec,nosuid,nodev /dev/shm 2>/dev/null || true

# ============================================================
# 2. SYSCTL HARDENING
# ============================================================
# Kernel-level network and memory protections.
#
# WHAT IT DOES:
#   - Disables IP forwarding (container is not a router)
#   - Ignores ICMP redirects (prevents MITM route poisoning)
#   - Enables SYN cookies (mitigates SYN flood attacks)
#   - Disables source routing (prevents IP spoofing tricks)
#   - Enables reverse path filtering (drops spoofed packets)
#   - Restricts kernel pointer leaks in /proc
#   - Restricts dmesg access to root
#   - Randomizes VA space layout (ASLR)
#
# IMPACT:
#   If the container needs to act as a router or forward
#   traffic (e.g., VPN gateway), ip_forward must stay on.
#   Otherwise, no practical impact for normal services.
# ============================================================

echo "[2/10] Applying sysctl hardening..."

cat > /etc/sysctl.d/99-hardening.conf << 'EOF'
# Network
net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0

# Kernel
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 2

# Filesystem
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0
EOF

sysctl --system > /dev/null 2>&1 || true

# ============================================================
# 3. DISABLE CORE DUMPS
# ============================================================
# WHAT IT DOES:
#   Prevents processes from writing memory dumps to disk when
#   they crash. Core dumps can contain secrets, passwords,
#   encryption keys from process memory.
#
# IMPACT:
#   Debugging crashes becomes harder. If you need to debug a
#   specific process, temporarily re-enable with ulimit.
# ============================================================

echo "[3/10] Disabling core dumps..."

cat > /etc/security/limits.d/99-no-core.conf << 'EOF'
* hard core 0
* soft core 0
EOF

mkdir -p /etc/systemd/coredump.conf.d 2>/dev/null || true
cat > /etc/systemd/coredump.conf.d/disable.conf 2>/dev/null << 'EOF' || true
[Coredump]
Storage=none
ProcessSizeMax=0
EOF

# ============================================================
# 4. REMOVE SETUID/SETGID BINARIES
# ============================================================
# WHAT IT DOES:
#   Finds binaries with the setuid or setgid bit and removes
#   those bits. These binaries run with elevated privileges
#   regardless of who executes them. Common privilege
#   escalation vector.
#
# IMPACT:
#   Commands like ping, su, mount, umount will lose their
#   elevated privileges. Root can still do everything.
#   We preserve sudo and passwd in a whitelist. If you need
#   specific ones back: chmod u+s /path/to/binary
# ============================================================

echo "[4/10] Stripping setuid/setgid bits..."

SUID_WHITELIST=(
  "/usr/bin/sudo"
  "/usr/bin/passwd"
)

while IFS= read -r -d '' file; do
  skip=false
  for allowed in "${SUID_WHITELIST[@]}"; do
    [[ "$file" == "$allowed" ]] && skip=true && break
  done
  if ! $skip; then
    chmod ug-s "$file" 2>/dev/null || true
  fi
done < <(find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -print0 2>/dev/null)

# ============================================================
# 5. CREATE NON-ROOT USER WITH SSH KEY
# ============================================================
# WHAT IT DOES:
#   Creates a new user with sudo privileges and sets up
#   SSH key-based authentication for them. Sets a password
#   for sudo access. This is the account you'll use to log
#   in going forward since root SSH login gets disabled in
#   the next step.
#
# IMPACT:
#   You will SSH in as this user, then sudo for root tasks.
#   Direct root login via SSH will no longer work. The
#   password is only used for sudo, not SSH.
# ============================================================

echo "[5/10] Creating non-root user..."

read -rp "Enter username for new non-root user: " NEW_USER

if [[ -z "$NEW_USER" ]]; then
  echo "No username provided. Exiting."
  exit 1
fi

if id "$NEW_USER" &>/dev/null; then
  echo "User '$NEW_USER' already exists. Skipping creation."
else
  if [[ "$DISTRO" == "debian" ]]; then
    adduser --disabled-password --gecos "" "$NEW_USER"
    usermod -aG sudo "$NEW_USER"
  elif [[ "$DISTRO" == "alpine" ]]; then
    adduser -D "$NEW_USER"
    addgroup "$NEW_USER" wheel 2>/dev/null || true
    apk add sudo > /dev/null 2>&1 || true
    sed -i 's/^# %wheel ALL=(ALL:ALL) ALL/%wheel ALL=(ALL:ALL) ALL/' \
      /etc/sudoers 2>/dev/null || true
  fi
  echo "User '$NEW_USER' created."
fi

echo ""
echo "Set a password for '$NEW_USER' (used for sudo):"
passwd "$NEW_USER"

echo ""
echo "Paste the SSH public key for '$NEW_USER'."
echo "(Single line, starts with ssh-rsa, ssh-ed25519, etc.)"
read -rp "> " SSH_PUB_KEY

if [[ -z "$SSH_PUB_KEY" ]]; then
  echo "No key provided. Exiting."
  echo "You MUST provide a key since password auth will be disabled."
  exit 1
fi

USER_HOME=$(eval echo "~$NEW_USER")
SSH_DIR="$USER_HOME/.ssh"
mkdir -p "$SSH_DIR"
echo "$SSH_PUB_KEY" > "$SSH_DIR/authorized_keys"
chmod 700 "$SSH_DIR"
chmod 600 "$SSH_DIR/authorized_keys"
chown -R "$NEW_USER":"$NEW_USER" "$SSH_DIR"

echo "SSH key installed for '$NEW_USER'."

# ============================================================
# 6. HARDEN SSH (if installed)
# ============================================================
# WHAT IT DOES:
#   Locks down the SSH daemon config if SSH is present.
#   - Disables root login
#   - Disables password auth (key-only)
#   - Disables X11 forwarding
#   - Restricts to SSHv2
#   - Reduces auth timeout and max attempts
#   - Only allows the user created in step 5
#
# IMPACT:
#   Only the user created above can SSH in, and only with
#   their key. No root login, no passwords for SSH. If you
#   need to add more users later, update AllowUsers in
#   /etc/ssh/sshd_config.d/99-hardening.conf
# ============================================================

echo "[6/10] Hardening SSH (if present)..."

SSHD_CONFIG="/etc/ssh/sshd_config"
if [ -f "$SSHD_CONFIG" ]; then
  cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak"

  cat > /etc/ssh/sshd_config.d/99-hardening.conf << EOF
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
MaxAuthTries 3
LoginGraceTime 20
ClientAliveInterval 300
ClientAliveCountMax 2
PermitEmptyPasswords no
Protocol 2
AllowUsers $NEW_USER
EOF

  if [[ "$DISTRO" == "debian" ]]; then
    systemctl restart sshd 2>/dev/null || true
  elif [[ "$DISTRO" == "alpine" ]]; then
    rc-service sshd restart 2>/dev/null || true
  fi
fi

# ============================================================
# 7. AUTOMATIC SECURITY UPDATES
# ============================================================
# WHAT IT DOES:
#   Installs and enables unattended security updates on
#   Debian/Ubuntu. On Alpine, installs a daily cron job to
#   run apk upgrade.
#
# IMPACT:
#   Packages will update automatically. In rare cases a bad
#   update can break something. The tradeoff is worth it for
#   security patches. Review /var/log/unattended-upgrades/
#   or cron logs if something breaks after an auto-update.
# ============================================================

echo "[7/10] Configuring automatic security updates..."

if [[ "$DISTRO" == "debian" ]]; then
  DEBIAN_FRONTEND=noninteractive apt-get install -y \
    unattended-upgrades apt-listchanges > /dev/null 2>&1

  cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
};
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF

  cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

elif [[ "$DISTRO" == "alpine" ]]; then
  cat > /etc/periodic/daily/auto-upgrade << 'SCRIPT'
#!/bin/sh
apk update && apk upgrade --no-cache >> /var/log/apk-upgrade.log 2>&1
SCRIPT
  chmod +x /etc/periodic/daily/auto-upgrade
fi

# ============================================================
# 8. REMOVE UNNECESSARY PACKAGES AND SERVICES
# ============================================================
# WHAT IT DOES:
#   Removes common attack surface packages that have no
#   business being in a server container: telnet, ftp, rsh,
#   rlogin, etc.
#
# IMPACT:
#   If you actually need any of these tools, install them
#   back individually. You almost certainly don't.
# ============================================================

echo "[8/10] Removing unnecessary packages..."

if [[ "$DISTRO" == "debian" ]]; then
  REMOVE_PKGS="telnet rsh-client rsh-redone-client xinetd tftp"
  for pkg in $REMOVE_PKGS; do
    apt-get purge -y "$pkg" > /dev/null 2>&1 || true
  done
  apt-get autoremove -y > /dev/null 2>&1 || true

elif [[ "$DISTRO" == "alpine" ]]; then
  REMOVE_PKGS="telnet tftp-hpa"
  for pkg in $REMOVE_PKGS; do
    apk del "$pkg" > /dev/null 2>&1 || true
  done
fi

# ============================================================
# 9. USER AND LOGIN HARDENING
# ============================================================
# WHAT IT DOES:
#   - Sets strong default umask (027) so new files are not
#     world-readable by default
#   - Restricts su to the sudo/wheel group only
#   - Locks down cron to root only
#   - Sets password aging policies
#   - Locks system accounts to nologin shells
#
# IMPACT:
#   New files created by users will have permissions 750 for
#   dirs and 640 for files by default. Non-root users can't
#   use su unless they're in the sudo/wheel group. Only root
#   can create cron jobs.
# ============================================================

echo "[9/10] Hardening user and login settings..."

# Set default umask
sed -i 's/^UMASK.*/UMASK 027/' /etc/login.defs 2>/dev/null || true

# Restrict su
if [[ "$DISTRO" == "debian" ]]; then
  if [ -f /etc/pam.d/su ]; then
    sed -i '/pam_wheel.so/s/^#//' /etc/pam.d/su
  fi
fi

# Restrict cron
if [ -d /etc ]; then
  echo "root" > /etc/cron.allow 2>/dev/null || true
  rm -f /etc/cron.deny 2>/dev/null || true
fi

# Password policies (Debian/Ubuntu)
if [[ "$DISTRO" == "debian" ]]; then
  sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs
  sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 7/' /etc/login.defs
  sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 14/' /etc/login.defs
fi

# Lock system accounts that shouldn't have login shells
while IFS=: read -r user _ uid _ _ _ shell; do
  if [[ "$uid" -lt 1000 && "$uid" -ne 0 \
    && "$shell" != "/usr/sbin/nologin" \
    && "$shell" != "/bin/false" \
    && "$shell" != "/sbin/nologin" ]]; then
    usermod -s /usr/sbin/nologin "$user" 2>/dev/null || \
      usermod -s /sbin/nologin "$user" 2>/dev/null || true
  fi
done < /etc/passwd

# ============================================================
# 10. RESTRICT /proc (hidepid)
# ============================================================
# WHAT IT DOES:
#   Sets hidepid=2 on /proc so non-root users can only see
#   their own processes. Prevents users from seeing what
#   other users/services are running, which leaks info about
#   what software is installed and running.
#
# IMPACT:
#   Normal for single-user/root-only containers. If you have
#   multiple non-root users who need to see all processes
#   (monitoring tools), either run them as root or set
#   hidepid=1 instead.
# ============================================================

echo "[10/10] Restricting /proc visibility..."

if ! grep -q "hidepid" /etc/fstab 2>/dev/null; then
  echo "proc /proc proc defaults,hidepid=2,gid=0 0 0" >> /etc/fstab
fi
mount -o remount,hidepid=2 /proc 2>/dev/null || true

# ============================================================
# DONE
# ============================================================

echo ""
echo "========================================="
echo " Hardening complete."
echo "========================================="
echo ""
echo "IMPORTANT reminders:"
echo " - SSH user: $NEW_USER (root login disabled)"
echo " - SSH is key-only. Password is for sudo only."
echo " - Test SSH access BEFORE closing your current session."
echo " - Firewall should be configured on the Proxmox host"
echo "   via /etc/pve/firewall/<CTID>.fw or the web UI."
echo " - /tmp is noexec. Temporarily remount if an"
echo "   installer needs it: mount -o remount,exec /tmp"
echo " - Review sysctl settings if this container needs"
echo "   to forward traffic (VPN, proxy, etc.)."
echo " - Reboot the container to ensure all changes"
echo "   persist correctly."
echo ""
