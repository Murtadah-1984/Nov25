#!/usr/bin/env bash
#
# set-static-ip-interactive.sh
# Description: Interactively set hostname and static IP address on Ubuntu (Netplan-based)
# Compatible with: Ubuntu 20.04, 22.04, 24.04 (Focal, Jammy, Noble)
#

set -euo pipefail

# === ROOT CHECK ===
if [[ $EUID -ne 0 ]]; then
    echo "❌ Please run as root: sudo $0"
    exit 1
fi

# === INTRO ===
echo "============================================"
echo "   🧠 Ubuntu Hostname and Static IP Config   "
echo "============================================"

# === PROMPTS ===
read -rp "Enter new hostname: " HOSTNAME
read -rp "Enter network interface name (e.g. eth0, ens33): " INTERFACE
read -rp "Enter static IP address (e.g. 192.168.1.100): " STATIC_IP
read -rp "Enter subnet mask (CIDR format, e.g. 24 for 255.255.255.0): " NETMASK
read -rp "Enter default gateway (e.g. 192.168.1.1): " GATEWAY
read -rp "Enter DNS servers (comma separated, e.g. 8.8.8.8,1.1.1.1): " DNS_SERVERS

# === VALIDATION ===
if [[ -z "$HOSTNAME" || -z "$INTERFACE" || -z "$STATIC_IP" || -z "$NETMASK" || -z "$GATEWAY" ]]; then
    echo "❌ All fields are required."
    exit 1
fi

# === SHOW SUMMARY ===
echo ""
echo "🧾 Configuration summary:"
echo "-------------------------"
echo "Hostname  : $HOSTNAME"
echo "Interface : $INTERFACE"
echo "IP Address: $STATIC_IP/$NETMASK"
echo "Gateway   : $GATEWAY"
echo "DNS       : $DNS_SERVERS"
echo "-------------------------"
read -rp "Proceed with these settings? (y/n): " CONFIRM

if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
    echo "❌ Operation cancelled."
    exit 0
fi

# === SET HOSTNAME ===
echo "🖥️ Setting hostname..."
hostnamectl set-hostname "$HOSTNAME"
echo "$HOSTNAME" > /etc/hostname

if ! grep -q "$HOSTNAME" /etc/hosts; then
    echo "127.0.1.1 $HOSTNAME" >> /etc/hosts
fi

# === CONFIGURE NETPLAN ===
NETPLAN_FILE="/etc/netplan/01-netcfg.yaml"

if [[ -f "$NETPLAN_FILE" ]]; then
    cp "$NETPLAN_FILE" "${NETPLAN_FILE}.bak.$(date +%s)"
    echo "📦 Backup saved: ${NETPLAN_FILE}.bak.$(date +%s)"
fi

echo "🌐 Writing new Netplan configuration..."

cat > "$NETPLAN_FILE" <<EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    $INTERFACE:
      dhcp4: no
      addresses:
        - ${STATIC_IP}/${NETMASK}
      gateway4: ${GATEWAY}
      nameservers:
        addresses: [${DNS_SERVERS}]
EOF

# === APPLY CONFIG ===
echo "🚀 Applying network configuration..."
netplan apply || netplan try

# === Set Timezone ===
echo "🕒 Setting timezone to Asia/Baghdad..."
timedatectl set-timezone Asia/Baghdad

echo "Timezone set to: $(timedatectl show -p Timezone --value)"

echo ""
echo "✅ Done!"
echo "--------------------------------------------"
echo "Hostname  : $(hostname)"
ip -4 addr show "$INTERFACE" | grep "inet " || echo "No IP assigned yet."
echo "--------------------------------------------"
echo "📝 Note: A backup of the old Netplan file was created."
