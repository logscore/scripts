#!/bin/bash
set -euo pipefail

read -rp "Subnet to advertise (e.g. 192.168.86.0/24): " SUBNET

if [[ -z "$SUBNET" ]]; then
  echo "Error: Subnet is required." >&2
  exit 1
fi

echo "[*] Enabling IP forwarding..."
mkdir -p /etc/sysctl.d
printf 'net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
' \
  | sudo tee /etc/sysctl.d/99-tailscale.conf > /dev/null
sudo sysctl -p /etc/sysctl.d/99-tailscale.conf

echo "[*] Advertising exit node and subnet route: $SUBNET"
sudo tailscale set --advertise-exit-node --advertise-routes="$SUBNET"

echo ""
echo "Done. Approve the route in your Tailscale admin console."
