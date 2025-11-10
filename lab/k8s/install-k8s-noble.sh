#!/usr/bin/env bash
#
# install-k8s-noble.sh
# Kubernetes + Docker installation for Ubuntu 24.04 (Noble Numbat)
# Compatible: Ubuntu 24.04 server
#

set -euo pipefail

# === Colors ===
YELLOW='\033[1;33m'
GREEN='\033[1;32m'
NC='\033[0m'

echo -e "${YELLOW}🚀 Starting Kubernetes Installation on Ubuntu 24.04 (Noble)...${NC}"

# === 1. Update system ===
echo -e "${YELLOW}🔧 Updating system packages...${NC}"
apt update -y && apt upgrade -y

# === 2. Disable swap (required for K8s) ===
echo -e "${YELLOW}🧠 Disabling swap...${NC}"
swapoff -a
sed -i '/ swap / s/^/#/' /etc/fstab

# === 3. Enable kernel modules ===
echo -e "${YELLOW}🧩 Loading kernel modules...${NC}"
cat <<EOF | tee /etc/modules-load.d/k8s.conf
overlay
br_netfilter
EOF

modprobe overlay
modprobe br_netfilter

# === 4. Configure sysctl parameters ===
echo -e "${YELLOW}⚙️ Configuring sysctl...${NC}"
cat <<EOF | tee /etc/sysctl.d/99-kubernetes-cri.conf
net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward                 = 1
EOF

sysctl --system

# === 5. Install dependencies ===
echo -e "${YELLOW}📦 Installing dependencies...${NC}"
apt install -y apt-transport-https ca-certificates curl gpg lsb-release software-properties-common

# === 6. Install Docker Engine (container runtime) ===
echo -e "${YELLOW}🐳 Installing Docker Engine...${NC}"
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
  | tee /etc/apt/sources.list.d/docker.list > /dev/null

apt update -y
apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# === 7. Configure containerd for K8s ===
echo -e "${YELLOW}⚙️ Configuring containerd...${NC}"
mkdir -p /etc/containerd
containerd config default | tee /etc/containerd/config.toml >/dev/null
sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml
systemctl restart containerd
systemctl enable containerd

# === 8. Add Kubernetes repository ===
echo -e "${YELLOW}🧭 Adding Kubernetes apt repository...${NC}"
curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.30/deb/Release.key | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.30/deb/ /" | tee /etc/apt/sources.list.d/kubernetes.list

apt update -y

# === 9. Install Kubernetes tools ===
echo -e "${YELLOW}📦 Installing kubeadm, kubelet, kubectl...${NC}"
apt install -y kubelet kubeadm kubectl
apt-mark hold kubelet kubeadm kubectl

systemctl enable kubelet

# === 10. Optional hostname setup ===
read -rp "Enter hostname for this node (leave blank to skip): " HOSTNAME
if [[ -n "$HOSTNAME" ]]; then
  hostnamectl set-hostname "$HOSTNAME"
fi

# === 11. Set timezone (optional) ===
echo -e "${YELLOW}🕒 Setting timezone to Asia/Baghdad...${NC}"
timedatectl set-timezone Asia/Baghdad

# === 12. Ask if this node should initialize the cluster ===
read -rp "Do you want to initialize a new Kubernetes cluster on this node? (y/n): " INIT
if [[ "$INIT" =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}🌐 Initializing Kubernetes cluster...${NC}"
    kubeadm init --pod-network-cidr=10.244.0.0/16

    mkdir -p $HOME/.kube
    cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
    chown $(id -u):$(id -g) $HOME/.kube/config

    echo -e "${YELLOW}🧩 Applying Flannel CNI...${NC}"
    kubectl apply -f https://raw.githubusercontent.com/flannel-io/flannel/master/Documentation/kube-flannel.yml
    echo -e "${GREEN}✅ Cluster initialized successfully!${NC}"
    kubeadm token create --print-join-command > /root/join-command.sh
    echo -e "${GREEN}➡ Join command saved to /root/join-command.sh${NC}"
else
    echo -e "${YELLOW}📋 To join a cluster, use the join command from your control plane node.${NC}"
fi

echo -e "${GREEN}🎉 Kubernetes installation complete!${NC}"
