#!/usr/bin/env bash
#
# make-static-ip.sh
# Automatically set the current DHCP IP as static on Ubuntu (Netplan-based)
# Compatible: Ubuntu 20.04, 22.04, 24.04 (Focal, Jammy, Noble)
#

set -euo pipefail

# === Root check ===
if [[ $EUID -ne 0 ]]; then
    echo "❌ Please run as root: sudo $0"
    exit 1
fi

echo "============================================"
echo "  🌐 Ubuntu Auto Static IP Configuration     "
echo "============================================"

# === Detect primary interface ===
INTERFACE=$(ip route | awk '/default/ {print $5; exit}')
if [[ -z "$INTERFACE" ]]; then
    echo "❌ Could not detect default network interface."
    exit 1
fi

# === Get current network info ===
CURRENT_IP=$(ip -4 addr show "$INTERFACE" | awk '/inet / {print $2}' | head -n1)
GATEWAY=$(ip route | awk '/default/ {print $3; exit}')
DNS_SERVERS=$(grep -E '^nameserver' /etc/resolv.conf | awk '{print $2}' | paste -sd, -)

# === Parse IP and netmask ===
IP_ADDR=${CURRENT_IP%%/*}
NETMASK=${CURRENT_IP##*/}

echo "Detected configuration:"
echo "--------------------------------------------"
echo "Interface : $INTERFACE"
echo "Current IP: $IP_ADDR/$NETMASK"
echo "Gateway   : $GATEWAY"
echo "DNS       : $DNS_SERVERS"
echo "--------------------------------------------"

# === Ask for hostname ===
read -rp "Enter new hostname (leave blank to skip): " HOSTNAME

if [[ -n "$HOSTNAME" ]]; then
    echo "🖥️ Setting hostname to '$HOSTNAME'..."
    hostnamectl set-hostname "$HOSTNAME"
    echo "$HOSTNAME" > /etc/hostname
    if ! grep -q "$HOSTNAME" /etc/hosts; then
        echo "127.0.1.1 $HOSTNAME" >> /etc/hosts
    fi
fi

# === Confirm before applying ===
echo ""
read -rp "Convert this configuration to static? (y/n): " CONFIRM
if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
    echo "❌ Operation cancelled."
    exit 0
fi

# === Write Netplan config ===
NETPLAN_FILE="/etc/netplan/01-netcfg.yaml"
BACKUP="${NETPLAN_FILE}.bak.$(date +%s)"

if [[ -f "$NETPLAN_FILE" ]]; then
    cp "$NETPLAN_FILE" "$BACKUP"
    echo "📦 Backup created: $BACKUP"
fi

echo "✍️ Writing static config to $NETPLAN_FILE..."
cat > "$NETPLAN_FILE" <<EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    $INTERFACE:
      dhcp4: no
      addresses:
        - ${IP_ADDR}/${NETMASK}
      gateway4: ${GATEWAY}
      nameservers:
        addresses: [${DNS_SERVERS}]
EOF

# === Apply config ===
echo "🚀 Applying new Netplan configuration..."
netplan apply || netplan try


# === Set Timezone ===
echo "🕒 Setting timezone to Asia/Baghdad..."
timedatectl set-timezone Asia/Baghdad
echo "Timezone set to: $(timedatectl show -p Timezone --value)"



# === Show final result ===
echo ""
echo "✅ Done!"
echo "--------------------------------------------"
[[ -n "$HOSTNAME" ]] && echo "Hostname : $(hostname)"
echo "Interface: $INTERFACE"
ip -4 addr show "$INTERFACE" | awk '/inet / {print "IP Addr  : " $2}'
echo "Gateway  : $GATEWAY"
echo "DNS      : $DNS_SERVERS"
echo "--------------------------------------------"
echo "📝 Previous Netplan config backed up at: $BACKUP"
