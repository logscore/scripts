#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# Linux Hardening Script
# Run as root on the target system
# Supports: Debian, Ubuntu, Alpine, Fedora, RHEL, CentOS,
#           Rocky, Alma, Arch, Manjaro, openSUSE, SLES
# Works on: bare metal, VMs, LXC containers, Docker
#
# Flow: Configure → Review → Execute
#   Phase 1: Collect all interactive input (no system changes)
#   Phase 2: Display summary and confirm
#   Phase 3: Execute hardening (no prompts)
# ============================================================

if [[ $EUID -ne 0 ]]; then
  echo "Run as root."
  exit 1
fi

# --- Detect distro ---
DISTRO="unknown"
if [ -f /etc/os-release ]; then
  # shellcheck source=/dev/null
  . /etc/os-release
  case "$ID" in
    ubuntu|debian) DISTRO="debian" ;;
    alpine) DISTRO="alpine" ;;
    fedora|centos|rhel|rocky|alma) DISTRO="rhel" ;;
    arch|endeavouros|manjaro) DISTRO="arch" ;;
    opensuse*|sles) DISTRO="suse" ;;
  esac
fi

if [[ "$DISTRO" == "unknown" ]]; then
  echo "Unsupported distro."
  exit 1
fi

# --- Detect runtime environment ---
RUNTIME_ENV="bare-metal"
if [ -f /.dockerenv ] || grep -q 'docker\|containerd' /proc/1/cgroup 2>/dev/null; then
  RUNTIME_ENV="docker"
elif [ -d /dev/lxd ] || grep -q 'lxc' /proc/1/cgroup 2>/dev/null; then
  RUNTIME_ENV="lxc"
elif command -v systemd-detect-virt &>/dev/null; then
  virt=$(systemd-detect-virt 2>/dev/null || true)
  case "$virt" in
    none|"") RUNTIME_ENV="bare-metal" ;;
    lxc*) RUNTIME_ENV="lxc" ;;
    docker) RUNTIME_ENV="docker" ;;
    *) RUNTIME_ENV="vm" ;;
  esac
fi

echo "Detected distro: $DISTRO"
echo "Runtime environment: $RUNTIME_ENV"

# --- Helper functions ---
pkg_install() {
  case "$DISTRO" in
    debian) DEBIAN_FRONTEND=noninteractive apt-get install -y "$@" > /dev/null 2>&1 ;;
    alpine) apk add "$@" > /dev/null 2>&1 ;;
    rhel) dnf install -y "$@" > /dev/null 2>&1 || yum install -y "$@" > /dev/null 2>&1 ;;
    arch) pacman -S --noconfirm "$@" > /dev/null 2>&1 ;;
    suse) zypper install -y "$@" > /dev/null 2>&1 ;;
  esac
}

pkg_remove() {
  case "$DISTRO" in
    debian) apt-get purge -y "$@" > /dev/null 2>&1 || true ;;
    alpine) apk del "$@" > /dev/null 2>&1 || true ;;
    rhel) dnf remove -y "$@" > /dev/null 2>&1 || yum remove -y "$@" > /dev/null 2>&1 || true ;;
    arch) pacman -Rns --noconfirm "$@" > /dev/null 2>&1 || true ;;
    suse) zypper remove -y "$@" > /dev/null 2>&1 || true ;;
  esac
}

svc_restart() {
  if command -v systemctl &>/dev/null; then
    systemctl restart "$1" 2>/dev/null && return 0
  fi
  if command -v rc-service &>/dev/null; then
    rc-service "$1" restart 2>/dev/null && return 0
  fi
  return 1
}

svc_enable() {
  if command -v systemctl &>/dev/null; then
    systemctl enable "$1" 2>/dev/null && return 0
  fi
  if command -v rc-update &>/dev/null; then
    rc-update add "$1" default 2>/dev/null && return 0
  fi
  return 1
}

collect_password() {
  local user="$1"
  while true; do
    read -rsp "    New password for $user: " pass1; echo >&2
    read -rsp "    Confirm password: " pass2; echo >&2
    if [[ "$pass1" == "$pass2" ]]; then
      echo "$pass1"
      return 0
    fi
    echo "    Passwords don't match. Try again." >&2
  done
}

# --- Configuration variables ---
declare -A USER_ACTIONS
declare -A USER_PASSWORDS
CFG_NEW_USER=""
CFG_NEW_USER_PASS=""
CFG_SSH_PUB_KEY=""
CFG_INSTALL_FW=""
CFG_EXTRA_PORTS=""

# ============================================================
# PHASE 1: CONFIGURATION
# ============================================================
# All interactive input is collected here. No system changes.
# ============================================================

echo ""
echo "========================================="
echo " Phase 1: Configuration"
echo "========================================="

# --- User management ---
echo ""
echo "Current human users (UID >= 1000) and root:"
echo "----------------------------------------------------------------------"
printf "%-16s %-6s %-30s %-20s %s\n" "USERNAME" "UID" "GROUPS" "SHELL" "HOME"
echo "----------------------------------------------------------------------"

mapfile -t USER_ENTRIES < <(awk -F: '($3 >= 1000 || $3 == 0)' /etc/passwd)

for line in "${USER_ENTRIES[@]}"; do
  IFS=: read -r user _ uid _ _ home shell <<< "$line"
  groups_list=$(id -nG "$user" 2>/dev/null | tr ' ' ',')
  printf "%-16s %-6s %-30s %-20s %s\n" "$user" "$uid" "$groups_list" "$shell" "$home"
done

echo ""
echo "For each user: (s)kip / (d)elete / (p)assword change / (l)ock"
echo "Default: skip"
echo ""

for line in "${USER_ENTRIES[@]}"; do
  IFS=: read -r user _ uid _ _ _ _ <<< "$line"
  read -rp "  $user: [s/d/p/l] " action
  action=${action:-s}
  case "$action" in
    d)
      if [[ "$user" == "root" ]]; then
        echo "    Cannot delete root. Setting to skip."
        action="s"
      fi
      ;;
    p)
      USER_PASSWORDS[$user]=$(collect_password "$user")
      ;;
    l|s) ;;
    *)
      echo "    Invalid action. Defaulting to skip."
      action="s"
      ;;
  esac
  USER_ACTIONS[$user]="$action"
done

# --- New user creation ---
echo ""
read -rp "Enter username for new non-root user: " CFG_NEW_USER

if [[ -z "$CFG_NEW_USER" ]]; then
  echo "No username provided. Exiting."
  exit 1
fi

if id "$CFG_NEW_USER" &>/dev/null; then
  echo "  User '$CFG_NEW_USER' already exists. Password will be updated."
else
  echo "  User '$CFG_NEW_USER' will be created."
fi

echo ""
echo "Set a password for '$CFG_NEW_USER' (used for sudo):"
CFG_NEW_USER_PASS=$(collect_password "$CFG_NEW_USER")

echo ""
echo "Paste the SSH public key for '$CFG_NEW_USER'."
echo "(Single line, starts with ssh-rsa, ssh-ed25519, etc.)"
read -rp "> " CFG_SSH_PUB_KEY

if [[ -z "$CFG_SSH_PUB_KEY" ]]; then
  echo "No key provided. Exiting."
  echo "You MUST provide a key since password auth will be disabled."
  exit 1
fi

# --- Firewall configuration ---
echo ""
FIREWALL=""
FW_DEFAULT=""

if command -v ufw &>/dev/null; then
  FIREWALL="ufw"
elif command -v firewall-cmd &>/dev/null; then
  FIREWALL="firewalld"
elif command -v nft &>/dev/null; then
  FIREWALL="nftables"
elif command -v iptables &>/dev/null; then
  FIREWALL="iptables"
fi

if [[ -z "$FIREWALL" ]]; then
  echo "  No firewall detected."
  case "$DISTRO" in
    debian) FW_DEFAULT="ufw" ;;
    rhel|arch|suse) FW_DEFAULT="firewalld" ;;
    alpine) FW_DEFAULT="iptables" ;;
  esac
  read -rp "  Install $FW_DEFAULT? [Y/n] " CFG_INSTALL_FW
  CFG_INSTALL_FW=${CFG_INSTALL_FW:-Y}
  if [[ "$CFG_INSTALL_FW" =~ ^[Yy]$ ]]; then
    FIREWALL="$FW_DEFAULT"
  fi
else
  echo "  Firewall detected: $FIREWALL"
fi

if [[ -n "$FIREWALL" ]]; then
  read -rp "  Additional TCP ports to allow (comma-separated, e.g. 80,443) [none]: " CFG_EXTRA_PORTS
  CFG_EXTRA_PORTS=${CFG_EXTRA_PORTS:-}
fi

# --- Read-only detection for summary ---
HAS_SSH=false
[ -f /etc/ssh/sshd_config ] && HAS_SSH=true

# ============================================================
# PHASE 2: REVIEW + CONFIRM
# ============================================================

echo ""
echo "========================================="
echo " Hardening Configuration Review"
echo "========================================="
echo ""
echo " System:  $DISTRO | $RUNTIME_ENV"
if $HAS_SSH; then
  echo " SSH:     present"
else
  echo " SSH:     not detected"
fi

echo ""
echo " User Management:"
for line in "${USER_ENTRIES[@]}"; do
  IFS=: read -r user _ _ _ _ _ _ <<< "$line"
  case "${USER_ACTIONS[$user]}" in
    s) echo "   $user → skip" ;;
    d) echo "   $user → delete (home removed)" ;;
    p) echo "   $user → password change" ;;
    l) echo "   $user → lock" ;;
  esac
done

echo ""
echo " New User:  $CFG_NEW_USER"
if id "$CFG_NEW_USER" &>/dev/null; then
  echo "   Status:  already exists (password will be updated)"
else
  echo "   Status:  will be created"
fi
echo "   SSH key: ${CFG_SSH_PUB_KEY:0:40}..."
if $HAS_SSH; then
  echo "   SSH:     key-only, AllowUsers $CFG_NEW_USER"
fi

echo ""
if [[ -n "$FIREWALL" ]]; then
  fw_ports="SSH"
  [[ -n "$CFG_EXTRA_PORTS" ]] && fw_ports="SSH + $CFG_EXTRA_PORTS"
  echo " Firewall:  $FIREWALL → deny incoming, allow $fw_ports"
else
  echo " Firewall:  none (skipped)"
fi

echo ""
echo " Auto-applied (no config needed):"
echo "   [1]  Filesystem mount hardening (/tmp, /dev/shm)"
echo "   [2]  Sysctl kernel hardening"
echo "   [3]  Core dump disable"
echo "   [4]  Setuid/setgid bit removal"
echo "   [8]  Automatic security updates"
echo "   [9]  Unnecessary package removal"
echo "   [10] User/login hardening (umask, cron, password aging)"
echo "   [12] /proc hidepid restriction"

if [[ "$RUNTIME_ENV" == "docker" || "$RUNTIME_ENV" == "lxc" ]]; then
  echo ""
  echo " Container notes:"
  echo "   - fstab writes will be skipped"
  echo "   - some sysctls may be read-only"
  echo "   - /proc hidepid will be skipped"
fi

echo ""
echo "========================================="
read -rp " Proceed with hardening? [y/N] " confirm
echo "========================================="

if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
  echo "Aborted."
  exit 0
fi

# ============================================================
# PHASE 3: EXECUTION
# ============================================================
# All 12 hardening steps. No interactive prompts.
# ============================================================

echo ""
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

echo "[1/12] Hardening filesystem mounts..."

FSTAB_ENTRIES=(
  "tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev,size=256m 0 0"
  "tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev,size=128m 0 0"
)

if [[ "$RUNTIME_ENV" == "docker" || "$RUNTIME_ENV" == "lxc" ]]; then
  echo "  Container detected — skipping fstab modifications."
  echo "  Attempting remount only..."
else
  for entry in "${FSTAB_ENTRIES[@]}"; do
    mount_point=$(echo "$entry" | awk '{print $2}')
    grep -q "$mount_point" /etc/fstab 2>/dev/null && \
      sed -i "\|$mount_point|d" /etc/fstab
    echo "$entry" >> /etc/fstab
  done
fi

mount -o remount,noexec,nosuid,nodev /tmp 2>/dev/null || true
mount -o remount,noexec,nosuid,nodev /dev/shm 2>/dev/null || true

# ============================================================
# 2. SYSCTL HARDENING
# ============================================================
# Kernel-level network and memory protections.
#
# WHAT IT DOES:
#   - Disables IP forwarding (not a router)
#   - Ignores ICMP redirects (prevents MITM route poisoning)
#   - Enables SYN cookies (mitigates SYN flood attacks)
#   - Disables source routing (prevents IP spoofing tricks)
#   - Enables reverse path filtering (drops spoofed packets)
#   - Restricts kernel pointer leaks in /proc
#   - Restricts dmesg access to root
#   - Randomizes VA space layout (ASLR)
#
# IMPACT:
#   If the system needs to act as a router or forward traffic
#   (e.g., VPN gateway), ip_forward must stay on. Otherwise,
#   no practical impact for normal services.
# ============================================================

echo "[2/12] Applying sysctl hardening..."

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

if [[ "$RUNTIME_ENV" == "docker" || "$RUNTIME_ENV" == "lxc" ]]; then
  echo "  Container detected — applying sysctls individually..."
  while IFS= read -r line; do
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    [[ -z "${line// /}" ]] && continue
    key=$(echo "$line" | awk -F= '{print $1}' | tr -d ' ')
    if ! sysctl -w "$line" > /dev/null 2>&1; then
      echo "  Warning: $key is read-only in this container"
    fi
  done < /etc/sysctl.d/99-hardening.conf
else
  sysctl --system > /dev/null 2>&1 || true
fi

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

echo "[3/12] Disabling core dumps..."

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

echo "[4/12] Stripping setuid/setgid bits..."

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
# 5. USER MANAGEMENT
# ============================================================
# Applies the user actions collected in Phase 1.
# Uses chpasswd for password changes (non-interactive).
# ============================================================

echo "[5/12] Applying user management changes..."

for line in "${USER_ENTRIES[@]}"; do
  IFS=: read -r user _ _ _ _ _ _ <<< "$line"
  case "${USER_ACTIONS[$user]}" in
    d)
      userdel -r "$user" 2>/dev/null || userdel "$user" 2>/dev/null || true
      echo "  Deleted $user."
      ;;
    p)
      echo "$user:${USER_PASSWORDS[$user]}" | chpasswd
      echo "  Password changed for $user."
      ;;
    l)
      usermod -L "$user" 2>/dev/null || true
      echo "  Locked $user."
      ;;
    *)
      echo "  Skipped $user."
      ;;
  esac
done

# ============================================================
# 6. CREATE NON-ROOT USER WITH SSH KEY
# ============================================================
# Creates the user collected in Phase 1 with sudo privileges
# and installs the SSH public key. Uses chpasswd for the
# password (non-interactive).
# ============================================================

echo "[6/12] Creating non-root user..."

if id "$CFG_NEW_USER" &>/dev/null; then
  echo "  User '$CFG_NEW_USER' already exists. Skipping creation."
else
  case "$DISTRO" in
    debian)
      adduser --disabled-password --gecos "" "$CFG_NEW_USER"
      usermod -aG sudo "$CFG_NEW_USER"
      ;;
    alpine)
      adduser -D "$CFG_NEW_USER"
      addgroup "$CFG_NEW_USER" wheel 2>/dev/null || true
      pkg_install sudo
      sed -i 's/^# %wheel ALL=(ALL:ALL) ALL/%wheel ALL=(ALL:ALL) ALL/' \
        /etc/sudoers 2>/dev/null || true
      ;;
    rhel)
      useradd -m "$CFG_NEW_USER"
      usermod -aG wheel "$CFG_NEW_USER"
      ;;
    arch)
      useradd -m -G wheel "$CFG_NEW_USER"
      pkg_install sudo
      sed -i 's/^# %wheel ALL=(ALL:ALL) ALL/%wheel ALL=(ALL:ALL) ALL/' \
        /etc/sudoers 2>/dev/null || true
      ;;
    suse)
      useradd -m "$CFG_NEW_USER"
      usermod -aG wheel "$CFG_NEW_USER"
      sed -i 's/^# %wheel ALL=(ALL:ALL) ALL/%wheel ALL=(ALL:ALL) ALL/' \
        /etc/sudoers 2>/dev/null || true
      ;;
  esac
  echo "  User '$CFG_NEW_USER' created."
fi

echo "$CFG_NEW_USER:$CFG_NEW_USER_PASS" | chpasswd
echo "  Password set for '$CFG_NEW_USER'."

USER_HOME=$(awk -F: -v user="$CFG_NEW_USER" '$1 == user {print $6}' /etc/passwd)
SSH_DIR="$USER_HOME/.ssh"
mkdir -p "$SSH_DIR"
echo "$CFG_SSH_PUB_KEY" > "$SSH_DIR/authorized_keys"
chmod 700 "$SSH_DIR"
chmod 600 "$SSH_DIR/authorized_keys"
chown -R "$CFG_NEW_USER":"$CFG_NEW_USER" "$SSH_DIR"
echo "  SSH key installed for '$CFG_NEW_USER'."

# ============================================================
# 7. HARDEN SSH (if installed)
# ============================================================
# Locks down the SSH daemon config if SSH is present.
#   - Disables root login
#   - Disables password auth (key-only)
#   - Disables X11 forwarding
#   - Restricts to SSHv2
#   - Reduces auth timeout and max attempts
#   - Only allows the user created in step 6
# ============================================================

echo "[7/12] Hardening SSH (if present)..."

SSHD_CONFIG="/etc/ssh/sshd_config"
if [ -f "$SSHD_CONFIG" ]; then
  cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak"

  if ! grep -q 'Include /etc/ssh/sshd_config.d/' "$SSHD_CONFIG" 2>/dev/null; then
    sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' "$SSHD_CONFIG" 2>/dev/null || \
      echo "Include /etc/ssh/sshd_config.d/*.conf" >> "$SSHD_CONFIG"
  fi
  mkdir -p /etc/ssh/sshd_config.d

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
AllowUsers $CFG_NEW_USER
EOF

  if [[ "$DISTRO" == "debian" ]]; then
    svc_restart ssh || svc_restart sshd || true
  else
    svc_restart sshd || true
  fi
fi

# ============================================================
# 8. AUTOMATIC SECURITY UPDATES
# ============================================================
# Installs and enables automatic security updates for the
# detected distro.
# ============================================================

echo "[8/12] Configuring automatic security updates..."

case "$DISTRO" in
  debian)
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
    ;;

  alpine)
    cat > /etc/periodic/daily/auto-upgrade << 'SCRIPT'
#!/bin/sh
apk update && apk upgrade --no-cache >> /var/log/apk-upgrade.log 2>&1
SCRIPT
    chmod +x /etc/periodic/daily/auto-upgrade
    ;;

  rhel)
    pkg_install dnf-automatic
    if [ -f /etc/dnf/automatic.conf ]; then
      sed -i 's/^apply_updates.*/apply_updates = yes/' /etc/dnf/automatic.conf
    fi
    systemctl enable --now dnf-automatic.timer 2>/dev/null || true
    ;;

  arch)
    cat > /etc/systemd/system/pacman-update.service << 'EOF'
[Unit]
Description=Pacman system update

[Service]
Type=oneshot
ExecStart=/usr/bin/pacman -Syu --noconfirm
EOF

    cat > /etc/systemd/system/pacman-update.timer << 'EOF'
[Unit]
Description=Daily pacman update

[Timer]
OnCalendar=daily
Persistent=true
RandomizedDelaySec=3600

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload 2>/dev/null || true
    systemctl enable --now pacman-update.timer 2>/dev/null || true
    ;;

  suse)
    cat > /etc/cron.daily/zypper-security-update << 'SCRIPT'
#!/bin/sh
zypper --non-interactive patch --category security >> /var/log/zypper-update.log 2>&1
SCRIPT
    chmod +x /etc/cron.daily/zypper-security-update
    ;;
esac

# ============================================================
# 9. REMOVE UNNECESSARY PACKAGES AND SERVICES
# ============================================================
# Removes common attack surface packages: telnet, ftp, rsh,
# rlogin, etc.
# ============================================================

echo "[9/12] Removing unnecessary packages..."

case "$DISTRO" in
  debian)
    for pkg in telnet rsh-client rsh-redone-client xinetd tftp; do
      pkg_remove "$pkg"
    done
    apt-get autoremove -y > /dev/null 2>&1 || true
    ;;
  alpine)
    for pkg in telnet tftp-hpa; do
      pkg_remove "$pkg"
    done
    ;;
  rhel)
    for pkg in telnet tftp rsh xinetd; do
      pkg_remove "$pkg"
    done
    dnf autoremove -y > /dev/null 2>&1 || true
    ;;
  arch)
    for pkg in inetutils tftp-hpa xinetd; do
      pkg_remove "$pkg"
    done
    ;;
  suse)
    for pkg in telnet tftp xinetd rsh; do
      pkg_remove "$pkg"
    done
    ;;
esac

# ============================================================
# 10. USER AND LOGIN HARDENING
# ============================================================
# - Sets strong default umask (027)
# - Restricts su to the sudo/wheel group only
# - Locks down cron to root only
# - Sets password aging policies
# - Locks system accounts to nologin shells
# ============================================================

echo "[10/12] Hardening user and login settings..."

sed -i 's/^UMASK.*/UMASK 027/' /etc/login.defs 2>/dev/null || true

if [ -f /etc/pam.d/su ]; then
  sed -i '/pam_wheel.so/s/^#//' /etc/pam.d/su
fi
if [[ "$DISTRO" == "arch" ]] && [ -f /etc/pam.d/su-l ]; then
  sed -i '/pam_wheel.so/s/^#//' /etc/pam.d/su-l
fi

if [ -d /etc ]; then
  echo "root" > /etc/cron.allow 2>/dev/null || true
  rm -f /etc/cron.deny 2>/dev/null || true
fi

if [ -f /etc/login.defs ]; then
  sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs
  sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 7/' /etc/login.defs
  sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 14/' /etc/login.defs
fi

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
# 11. FIREWALL CONFIGURATION
# ============================================================
# Uses the firewall and port config collected in Phase 1.
# Installs the firewall if needed, then configures:
#   - Default-deny incoming, allow outgoing
#   - Always allow SSH (port 22)
#   - Additional TCP ports from config
# ============================================================

echo "[11/12] Configuring firewall..."

FIREWALL_STATUS="none installed"

if [[ -n "$CFG_INSTALL_FW" && "$CFG_INSTALL_FW" =~ ^[Yy]$ ]]; then
  pkg_install "$FIREWALL"
fi

if [[ -n "$FIREWALL" ]]; then
  echo "  Using firewall: $FIREWALL"

  case "$FIREWALL" in
    ufw)
      ufw --force reset > /dev/null 2>&1
      ufw default deny incoming > /dev/null 2>&1
      ufw default allow outgoing > /dev/null 2>&1
      ufw allow 22/tcp > /dev/null 2>&1
      if [[ -n "$CFG_EXTRA_PORTS" ]]; then
        IFS=',' read -ra ports <<< "$CFG_EXTRA_PORTS"
        for port in "${ports[@]}"; do
          port=$(echo "$port" | tr -d ' ')
          ufw allow "$port/tcp" > /dev/null 2>&1
        done
      fi
      ufw --force enable > /dev/null 2>&1
      ;;

    firewalld)
      systemctl start firewalld 2>/dev/null || true
      svc_enable firewalld || true
      firewall-cmd --set-default-zone=drop 2>/dev/null || true
      firewall-cmd --permanent --add-service=ssh 2>/dev/null || true
      if [[ -n "$CFG_EXTRA_PORTS" ]]; then
        IFS=',' read -ra ports <<< "$CFG_EXTRA_PORTS"
        for port in "${ports[@]}"; do
          port=$(echo "$port" | tr -d ' ')
          firewall-cmd --permanent --add-port="${port}/tcp" 2>/dev/null || true
        done
      fi
      firewall-cmd --reload 2>/dev/null || true
      ;;

    nftables)
      if [[ -n "$CFG_EXTRA_PORTS" ]]; then
        clean_ports=$(echo "$CFG_EXTRA_PORTS" | tr -d ' ')
        NFT_PORTS="tcp dport { 22, ${clean_ports//,/, } } accept"
      else
        NFT_PORTS="tcp dport 22 accept"
      fi
      cat > /etc/nftables.conf << NFTEOF
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        iif lo accept
        ct state established,related accept
        ${NFT_PORTS}
    }
    chain forward {
        type filter hook forward priority 0; policy drop;
    }
    chain output {
        type filter hook output priority 0; policy accept;
    }
}
NFTEOF
      svc_enable nftables || true
      svc_restart nftables || true
      ;;

    iptables)
      iptables -F
      iptables -P INPUT DROP
      iptables -P FORWARD DROP
      iptables -P OUTPUT ACCEPT
      iptables -A INPUT -i lo -j ACCEPT
      iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
      iptables -A INPUT -p tcp --dport 22 -j ACCEPT
      if [[ -n "$CFG_EXTRA_PORTS" ]]; then
        IFS=',' read -ra ports <<< "$CFG_EXTRA_PORTS"
        for port in "${ports[@]}"; do
          port=$(echo "$port" | tr -d ' ')
          iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
        done
      fi
      if command -v iptables-save &>/dev/null; then
        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
      fi
      ;;
  esac
  FIREWALL_STATUS="$FIREWALL configured (SSH + ${CFG_EXTRA_PORTS:-none})"
fi

# ============================================================
# 12. RESTRICT /proc (hidepid)
# ============================================================
# Sets hidepid=2 on /proc so non-root users can only see
# their own processes.
# ============================================================

echo "[12/12] Restricting /proc visibility..."

if [[ "$RUNTIME_ENV" == "docker" || "$RUNTIME_ENV" == "lxc" ]]; then
  echo "  Container detected — skipping /proc hidepid (not supported)."
else
  if ! grep -q "hidepid" /etc/fstab 2>/dev/null; then
    echo "proc /proc proc defaults,hidepid=2,gid=0 0 0" >> /etc/fstab
  fi
  mount -o remount,hidepid=2 /proc 2>/dev/null || true
fi

# ============================================================
# DONE
# ============================================================

echo ""
echo "========================================="
echo " Hardening complete."
echo "========================================="
echo ""
echo " Runtime: $RUNTIME_ENV | Distro: $DISTRO"
echo " Firewall: $FIREWALL_STATUS"
echo ""
echo "IMPORTANT reminders:"
echo " - SSH user: $CFG_NEW_USER (root login disabled)"
echo " - SSH is key-only. Password is for sudo only."
echo " - Test SSH access BEFORE closing your current session."
echo " - /tmp is noexec. Temporarily remount if an"
echo "   installer needs it: mount -o remount,exec /tmp"
echo " - Review sysctl settings if this system needs"
echo "   to forward traffic (VPN, proxy, etc.)."
if [[ "$RUNTIME_ENV" == "docker" || "$RUNTIME_ENV" == "lxc" ]]; then
  echo " - Container mode: some sysctls may be read-only"
  echo " - Container mode: fstab changes were skipped"
  echo " - Container mode: /proc hidepid was skipped"
fi
echo " - Reboot to ensure all changes persist correctly."
echo ""
