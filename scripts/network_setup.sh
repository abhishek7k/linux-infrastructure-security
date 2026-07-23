#!/usr/bin/env bash
#
# network_setup.sh - Configure private network access control rules (iptables/UFW)
# Usage: sudo ./network_setup.sh --node [server|attacker]
#

# --- Visual Styling & Logging ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() { echo -e "${BLUE}[*] $1${NC}"; }
log_success() { echo -e "${GREEN}[+] $1${NC}"; }
log_warn() { echo -e "${YELLOW}[!] $1${NC}"; }
log_err() { echo -e "${RED}[-] ERROR: $1${NC}"; exit 1; }

# --- Root Check ---
if [[ $EUID -ne 0 ]]; then
   log_err "This script must be run as root (sudo)."
fi

NODE_TYPE=""
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --node) NODE_TYPE="$2"; shift ;;
        *) log_err "Unknown parameter passed: $1" ;;
    esac
    shift
done

if [[ "$NODE_TYPE" != "server" && "$NODE_TYPE" != "attacker" ]]; then
    log_err "You must specify --node as either 'server' or 'attacker'."
fi

# Define IP allocation
SERVER_IP="192.168.56.20"
ATTACKER_IP="192.168.56.10"
SUBNET="192.168.56.0/24"

# ------------------------------------------------------------
# Server Configuration (Arch Linux Node)
# ------------------------------------------------------------
configure_server() {
    log_info "Configuring network access controls on Server (Arch Node)..."
    
    # 1. Flush existing rules
    iptables -F
    iptables -X
    
    # 2. Set default policies (Deny All incoming, allow outgoing)
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT

    # 3. Allow Loopback interface
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT

    # 4. Allow already established and related connections
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # 5. Network Access Control: Allow SSH (Port 2222) ONLY from Kali Attacker IP
    iptables -A INPUT -p tcp -s "$ATTACKER_IP" --dport 2222 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
    log_success "Access Control Rule: Allowed incoming TCP/2222 (SSH) from $ATTACKER_IP"

    # 6. ICMP (Ping) Control: Allow ICMP echo-requests ONLY from Kali Attacker IP
    iptables -A INPUT -p icmp --icmp-type echo-request -s "$ATTACKER_IP" -j ACCEPT
    log_success "Access Control Rule: Allowed ICMP Ping only from $ATTACKER_IP"
    
    # 7. Log and Drop rule for auditing firewall violations
    iptables -A INPUT -p tcp -j LOG --log-prefix "FW_TCP_BLOCKED: " --log-level 4
    iptables -A INPUT -p udp -j LOG --log-prefix "FW_UDP_BLOCKED: " --log-level 4
    iptables -A INPUT -p icmp -j LOG --log-prefix "FW_ICMP_BLOCKED: " --log-level 4
    
    log_success "Host-based packet filter configured successfully."
    log_info "Current active iptables rules on Server:"
    iptables -L -n -v
}

# ------------------------------------------------------------
# Attacker Configuration (Kali Linux Node)
# ------------------------------------------------------------
configure_attacker() {
    log_info "Configuring Attacker Network Diagnostics (Kali Node)..."
    
    # Enable routing tools and test utilities (standard check)
    log_info "Testing basic network reachability to server ($SERVER_IP)..."
    if ping -c 3 -W 2 "$SERVER_IP" &>/dev/null; then
        log_success "Host $SERVER_IP is REACHABLE."
    else
        log_warn "Host $SERVER_IP is UNREACHABLE. Check Vagrant hostonly network settings."
    fi

    # Create diagnostic command helpers for the Kali node
    cat << 'EOF' > /usr/local/bin/sec-scan
#!/usr/bin/env bash
SERVER_IP="192.168.56.20"
echo "[*] Launching network audit scans against Server ($SERVER_IP)..."
echo "[+] Checking port 2222 (Hardened SSH)..."
nc -z -w 2 "$SERVER_IP" 2222 && echo "    --> Port 2222 is OPEN" || echo "    --> Port 2222 is CLOSED"

echo "[+] Checking port 22 (Default SSH)..."
nc -z -w 2 "$SERVER_IP" 22 && echo "    --> Port 22 is OPEN" || echo "    --> Port 22 is CLOSED"

echo "[+] Checking port 80 (HTTP Server)..."
nc -z -w 2 "$SERVER_IP" 80 && echo "    --> Port 80 is OPEN" || echo "    --> Port 80 is CLOSED"
EOF
    chmod +x /usr/local/bin/sec-scan
    log_success "Created network diagnostics utility 'sec-scan' on Kali."
}

# Run configuration based on node type
if [[ "$NODE_TYPE" == "server" ]]; then
    configure_server
else
    configure_attacker
fi
