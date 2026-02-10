#!/usr/bin/env bash
set -euo pipefail

#############################################
# CONFIG
#############################################
WG_IF="wg0"
WG_PORT_UDP="51820"
UDP2RAW_PORT_TCP="443"
WG_NET_CIDR="10.66.66.0/24"
WG_SERVER_IP="10.66.66.1/24"
ALLOWED_LAN_CIDR="192.168.56.0/24"

UDP2RAW_PASS='Mongolia2026$'
CLIENT_DNS="1.1.1.1"

GO_BIN_NAME="wg_GUI_udp2raw_MTU"
GO_INSTALL_DIR="/opt/OCNARF/sec-tool/wg"
GO_INSTALL_PATH="${GO_INSTALL_DIR}/${GO_BIN_NAME}"

DODGEVPN_LISTEN=":80"
DODGEVPN_SERVICE_NAME="DodgeVPN.service"
#############################################

need_root() { [[ $EUID -eq 0 ]] || { echo "[!] Run as root" >&2; exit 1; }; }
need_root

say() { echo "$@" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

#############################################
# NIC MENU
#############################################
nic_table() {
  for n in /sys/class/net/*; do
    nic="$(basename "$n")"
    [[ "$nic" == "lo" ]] && continue
    [[ "$nic" =~ ^wg[0-9]+$ ]] && continue

    state="$(cat "/sys/class/net/${nic}/operstate" 2>/dev/null || echo unknown)"
    case "$state" in
      up) state="UP" ;;
      down|dormant) state="DOWN" ;;
      *) state="UNKNOWN" ;;
    esac

    ip4="$(ip -4 -o addr show dev "$nic" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1)"
    [[ -z "$ip4" ]] && ip4="-"

    echo "${nic}|${ip4}|${state}"
  done
}

prompt_nic_menu() {
  local title="$1"
  local rows=()
  local names=()

  say
  say "=============================================="
  say "$title"
  say "=============================================="

  while IFS= read -r line; do rows+=("$line"); done < <(nic_table)

  for i in "${!rows[@]}"; do
    IFS='|' read -r nic ip st <<<"${rows[$i]}"
    names+=("$nic")
    printf "%d) %-12s %-15s %s\n" $((i+1)) "$nic" "$ip" "$st" >&2
  done

  say
  while true; do
    read -r -p "Select option [1-${#names[@]}]: " sel </dev/tty
    [[ "$sel" =~ ^[0-9]+$ ]] && (( sel>=1 && sel<=${#names[@]} )) && {
      echo "${names[$((sel-1))]}"
      return
    }
    say "[!] Invalid selection."
  done
}

#############################################
# START
#############################################
say "[+] Updating apt + installing packages..."
apt-get update -y
apt-get install -y wireguard qrencode iptables-persistent git build-essential linux-headers-$(uname -r) curl

WAN_NIC="$(prompt_nic_menu "Select WAN interface (internet-facing)")"
LAN_NIC="$(prompt_nic_menu "Select LAN interface (where ${ALLOWED_LAN_CIDR} exists)")"

say "[+] WAN NIC: $WAN_NIC"
say "[+] LAN NIC: $LAN_NIC"

#############################################
# PUBLIC IP (CONFIRMATION REQUIRED)
#############################################
GUESSED_IP="$(curl -4 -s --max-time 5 https://api.ipify.org || true)"

say
if [[ -n "$GUESSED_IP" ]]; then
  say "Detected public IP: ${GUESSED_IP}"
  read -r -p "Is this correct? [Y/n]: " ans </dev/tty
  ans="${ans:-Y}"
  if [[ "$ans" =~ ^[Yy]$ ]]; then
    WAN_PUB_IP="$GUESSED_IP"
  fi
fi

if [[ -z "${WAN_PUB_IP:-}" ]]; then
  while true; do
    read -r -p "Enter server PUBLIC IP or DNS name: " WAN_PUB_IP </dev/tty
    WAN_PUB_IP="${WAN_PUB_IP// /}"
    [[ -n "$WAN_PUB_IP" ]] && break
  done
fi

say "[+] endpoint-public-ip set to: $WAN_PUB_IP"

#############################################
# SYSCTL
#############################################
say "[+] Enabling IP forwarding..."
cat >/etc/sysctl.d/99-wireguard.conf <<EOF
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
EOF
sysctl --system >/dev/null

#############################################
# WIREGUARD
#############################################
say "[+] Creating WireGuard keys..."
install -d -m 700 /etc/wireguard
umask 077
[[ ! -f /etc/wireguard/${WG_IF}.key ]] && {
  wg genkey | tee /etc/wireguard/${WG_IF}.key >/dev/null
  wg pubkey < /etc/wireguard/${WG_IF}.key > /etc/wireguard/${WG_IF}.pub
}

SERVER_PRIV="$(cat /etc/wireguard/${WG_IF}.key)"
SERVER_PUB="$(cat /etc/wireguard/${WG_IF}.pub)"

say "[+] Writing WireGuard config..."
cat >/etc/wireguard/${WG_IF}.conf <<EOF
[Interface]
Address = ${WG_SERVER_IP}
ListenPort = ${WG_PORT_UDP}
PrivateKey = ${SERVER_PRIV}

PostUp   = iptables -t nat -A POSTROUTING -s ${WG_NET_CIDR} -o ${WAN_NIC} -j MASQUERADE
PostDown = iptables -t nat -D POSTROUTING -s ${WG_NET_CIDR} -o ${WAN_NIC} -j MASQUERADE
EOF
chmod 600 /etc/wireguard/${WG_IF}.conf

#############################################
# FIREWALL
#############################################
say "[+] Configuring firewall..."
iptables -A INPUT -i lo -p udp --dport ${WG_PORT_UDP} -j ACCEPT 2>/dev/null || true
iptables -A INPUT ! -i lo -p udp --dport ${WG_PORT_UDP} -j DROP 2>/dev/null || true
iptables -A INPUT -i ${WAN_NIC} -p tcp --dport ${UDP2RAW_PORT_TCP} -j ACCEPT 2>/dev/null || true
netfilter-persistent save >/dev/null

#############################################
# UDP2RAW
#############################################
say "[+] Installing udp2raw..."
git clone --depth 1 https://github.com/wangyu-/udp2raw /tmp/udp2raw
cd /tmp/udp2raw && make dynamic
install -m 755 udp2raw_dynamic /usr/local/bin/udp2raw

cat >/etc/systemd/system/udp2raw-wg.service <<EOF
[Unit]
Description=udp2raw FakeTCP wrapper
After=network-online.target

[Service]
ExecStart=/usr/local/bin/udp2raw -s -l0.0.0.0:${UDP2RAW_PORT_TCP} -r 127.0.0.1:${WG_PORT_UDP} -a -k "${UDP2RAW_PASS}" --raw-mode faketcp
Restart=always

[Install]
WantedBy=multi-user.target
EOF

#############################################
# INSTALL GO BINARY
#############################################
BIN_SRC="${SCRIPT_DIR}/${GO_BIN_NAME}"
[[ ! -f "$BIN_SRC" ]] && { say "[!] Missing ${GO_BIN_NAME} next to installer."; exit 1; }

install -d -m 755 "${GO_INSTALL_DIR}"
install -m 755 "$BIN_SRC" "${GO_INSTALL_PATH}"

#############################################
# DODGEVPN SERVICE
#############################################
cat >/etc/systemd/system/${DODGEVPN_SERVICE_NAME} <<EOF
[Unit]
Description=DodgeVPN WebUI
After=wg-quick@${WG_IF}.service udp2raw-wg.service

[Service]
ExecStart=${GO_INSTALL_PATH} -listen ${DODGEVPN_LISTEN} -wg-if ${WG_IF} -wg-net ${WG_NET_CIDR} -allowed-lan ${ALLOWED_LAN_CIDR} -udp2raw-tcp-port ${UDP2RAW_PORT_TCP} -udp2raw-local-port ${WG_PORT_UDP} -endpoint-public-ip ${WAN_PUB_IP}
Restart=always

[Install]
WantedBy=multi-user.target
EOF

#############################################
# START SERVICES
#############################################
systemctl daemon-reexec
systemctl daemon-reload
systemctl enable --now wg-quick@${WG_IF}
systemctl enable --now udp2raw-wg
systemctl enable --now ${DODGEVPN_SERVICE_NAME}

#############################################
# DONE
#############################################
say
say "=============================================="
say "[OK] DodgeVPN installed"
say "WireGuard pubkey: $SERVER_PUB"
say "WebUI: http://${WAN_PUB_IP}/"
say "Service: ${DODGEVPN_SERVICE_NAME}"
say "=============================================="

