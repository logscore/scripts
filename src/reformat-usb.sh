#!/bin/bash
set -euo pipefail

echo "================ Available Drives ================"
lsblk -f
echo "=================================================="

# Ask which drive to reformat
read -rp "Enter the drive you want to reformat (e.g., sdb): " DRIVE

# Safety: ensure input is not empty
if [[ -z "$DRIVE" ]]; then
  echo "No drive specified. Exiting."
  exit 1
fi

DEVICE="/dev/$DRIVE"

# Guard rails: refuse to touch the main system drive
SYSTEM_DRIVES=$(lsblk -ndo NAME,TYPE | awk '$2=="disk"{print $1}' | grep -E '^(nvme0n1|sda)$' || true)

for SYS in $SYSTEM_DRIVES; do
  if [[ "$DRIVE" == "$SYS" ]]; then
    echo ""
    echo "************************************************************"
    echo "WARNING: $DEVICE looks like your system drive!"
    echo "If you continue, you may accidentally wipe all your files"
    echo "from your main computer."
    echo "Only proceed if you are ABSOLUTELY sure you want to do this."
    echo "************************************************************"
    echo ""
  fi
done

echo "You selected: $DEVICE"
read -rp "Are you absolutely sure you want to erase and reformat $DEVICE? (yes/no): " CONFIRM
if [[ "$CONFIRM" != "yes" ]]; then
  echo "Aborted."
  exit 1
fi

# Ask for filesystem type
echo "Choose a filesystem format:"
echo "1) FAT32 (recommended, works everywhere)"
echo "2) exFAT (good for files >4GB, modern systems)"
echo "3) ext4 (Linux only)"
read -rp "Enter choice [1-3]: " FMT_CHOICE

case "$FMT_CHOICE" in
1)
  FSTYPE="vfat"
  FORMAT_CMD="mkfs.vfat -F32"
  ;;
2)
  FSTYPE="exfat"
  FORMAT_CMD="mkfs.exfat"
  ;;
3)
  FSTYPE="ext4"
  FORMAT_CMD="mkfs.ext4"
  ;;
*)
  echo "Invalid choice. Exiting."
  exit 1
  ;;
esac

echo "Unmounting any mounted partitions on $DEVICE..."
sudo umount "${DEVICE}"* || true

echo "Wiping partition table on $DEVICE..."
sudo wipefs -a "$DEVICE"

echo "Creating new partition table on $DEVICE..."
sudo parted -s "$DEVICE" mklabel msdos

echo "Creating a single partition on $DEVICE..."
sudo parted -s -a optimal "$DEVICE" mkpart primary 0% 100%

PARTITION="${DEVICE}1"

echo "Formatting $PARTITION as $FSTYPE..."
sudo $FORMAT_CMD "$PARTITION"

echo "================================================="
echo "Done! $PARTITION has been reformatted as $FSTYPE."
echo "Unplug and replug the drive to use it."
echo "================================================="
echo ""
