#!/bin/bash
#
# https://github.com/shivajichaprana/openvpn-manager
# Enhanced with security hardening, logging, error handling, and more.

set -euo pipefail

# ─── Constants ───────────────────────────────────────────────────────────────
readonly LOG_FILE="/var/log/openvpn-manager.log"
readonly VERSION="1.0.0"
readonly OVPN_SERVER_DIR="/etc/openvpn/server"
readonly CLIENTS_DB="$OVPN_SERVER_DIR/clients.db"
readonly EASYRSA_DIR="$OVPN_SERVER_DIR/easy-rsa"
readonly SERVER_CONF="$OVPN_SERVER_DIR/server.conf"
readonly OVPN_DIR="$HOME"
readonly SVC="openvpn-server@server.service"
readonly EASY_RSA_URL='https://github.com/OpenVPN/easy-rsa/releases/download/v3.2.1/EasyRSA-3.2.1.tgz'
readonly EASY_RSA_SHA256='ec0fdca46c07afef341e0e0eeb2bf0cfe74a11322b77163e5d764d28cb4eec89'
readonly VPN_SUBNET="10.8.0.0"
readonly VPN_SUBNET_CIDR="10.8.0.0/24"
readonly VPN_SUBNET6="fddd:1194:1194:1194::/64"
readonly SECONDS_PER_DAY=86400
readonly MGMT_PORT=7505

# ─── Argument handling ───────────────────────────────────────────────────────
for _arg in "$@"; do
    case "$_arg" in
        --version|-v) echo "openvpn-manager v$VERSION"; exit 0 ;;
        --help|-h)
            echo "Usage: bash openvpn-manager.sh [--version] [--help]"
            echo "  Run without arguments to launch the interactive menu."
            exit 0 ;;
    esac
done

# ─── Colors ──────────────────────────────────────────────────────────────────
readonly RED='\033[0;31m'; readonly GREEN='\033[0;32m'; readonly YELLOW='\033[1;33m'; readonly CYAN='\033[0;36m'; readonly NC='\033[0m'

# ─── Helpers ─────────────────────────────────────────────────────────────────
log() { printf -v _log_ts '%(%Y-%m-%d %H:%M:%S)T' -1; echo "[$_log_ts] $*" >> "$LOG_FILE"; }
info() { printf "%b\n" "${CYAN}$*${NC}"; log "INFO: $*"; }
ok() { printf "%b\n" "${GREEN}✔ $*${NC}"; log "OK: $*"; }
warn() { printf "%b\n" "${YELLOW}⚠ $*${NC}" >&2; log "WARN: $*"; }
err() { printf "%b\n" "${RED}✘ $*${NC}" >&2; log "ERROR: $*"; exit 1; }
run() { "$@" || err "Failed: $*"; }
pause() { read -n1 -rsp $'Press any key...\n'; }
# Prompt "[y/N]" and return 0 only on y/Y
confirm() {
    local _msg="$1" _reply
    read -rp "$_msg [y/N]: " _reply
    until [[ "$_reply" =~ ^[yYnN]*$ ]]; do
        echo "$_reply: invalid."; read -rp "$_msg [y/N]: " _reply
    done
    [[ "$_reply" =~ ^[yY]$ ]]
}
# Escape sed address/replacement metacharacters in $1
sed_escape() { printf '%s' "$1" | sed 's/[\/&]/\\&/g'; }
# Append 'push "dhcp-option DNS <addr>"' lines to SERVER_CONF for each arg
push_dns() { local _s; for _s in "$@"; do printf 'push "dhcp-option DNS %s"\n' "$_s" >> "$SERVER_CONF"; done; }
# Sanity-check SERVER_CONF has required directives before a restart
test_server_config() {
    [[ -s "$SERVER_CONF" ]] || err "Server config is missing or empty: $SERVER_CONF"
    local _d; for _d in port proto dev ca cert key; do
        grep -q "^$_d " "$SERVER_CONF" || warn "server.conf may be missing directive: $_d"
    done
}
reload_service() {
    if ! systemctl reload "$SVC" 2>/dev/null; then
        warn "reload failed, restarting..."
        systemctl restart "$SVC" 2>/dev/null || { warn "Service restart also failed. Check: systemctl status $SVC"; log "ERROR: service restart failed"; }
    fi
}
get_clients() {
    [[ -f "$EASYRSA_DIR/pki/index.txt" ]] || return 0
    awk -F'/CN=' '/^V/{split($2,a,"/"); if(a[1]!="server") print a[1]}' "$EASYRSA_DIR/pki/index.txt"
}
crl_update() {
    ( cd "$EASYRSA_DIR" && EASYRSA_CRL_DAYS=3650 run ./easyrsa gen-crl )
    cp "$EASYRSA_DIR/pki/crl.pem" "$OVPN_SERVER_DIR/crl.pem"
    chown nobody:"$group_name" "$OVPN_SERVER_DIR/crl.pem"
    chmod 640 "$OVPN_SERVER_DIR/crl.pem"
}
sanitize_name() { local s="${1//[^[:alnum:][:space:]_-]/ }"; s="${s#"${s%%[![:space:]]*}"}" ; s="${s%"${s##*[![:space:]]}"}" ; echo "${s//[[:space:]]/_}"; }
read_days() {
    local _v
    read -rp "Validity in days [365, max 3650]: " _v
    if [[ -z "$_v" || ! "$_v" =~ ^[0-9]+$ ]]; then _v=365; fi
    if [[ "$_v" -gt 3650 ]]; then _v=3650; fi
    printf '%s' "$_v"
}

download_easyrsa() {
    local dest="$1"
    local easyrsa_tmp; easyrsa_tmp=$(mktemp)
    trap 'rm -f "$easyrsa_tmp"' RETURN
    { wget -qO "$easyrsa_tmp" "$EASY_RSA_URL" 2>/dev/null || curl -sL -o "$easyrsa_tmp" "$EASY_RSA_URL"; } || err "EasyRSA download failed."
    echo "${EASY_RSA_SHA256}  ${easyrsa_tmp}" | sha256sum -c - || err "EasyRSA checksum mismatch."
    tar xz -C "$dest" --strip-components 1 -f "$easyrsa_tmp"
}
_selinux_enforcing=""
selinux_port() {
    local action="$1" port="$2" proto="$3"
    if [[ -z "$_selinux_enforcing" ]]; then
        if [[ "$(getenforce 2>/dev/null)" == "Enforcing" ]]; then
            _selinux_enforcing=1
        else
            _selinux_enforcing=0
        fi
    fi
    if [[ "$_selinux_enforcing" == 1 && "$port" != "1194" ]]; then
        semanage port -"$action" -t openvpn_port_t -p "$proto" "$port"
    fi
}
pick_client() {
    local prompt="${1:-Client}"
    mapfile -t _clients < <(get_clients)
    local n=${#_clients[@]}
    if [[ $n -eq 0 ]]; then echo; echo "No existing clients!"; pause; return 1; fi
    echo; for i in "${!_clients[@]}"; do printf "  %s) %s\n" "$((i+1))" "${_clients[$i]}"; done
    echo "   0) Back"
    local num
    read -rp "$prompt: " num
    [[ "$num" == "0" ]] && return 1
    until [[ "$num" =~ ^[0-9]+$ && "$num" -ge 1 && "$num" -le "$n" ]]; do
        echo "$num: invalid."; read -rp "$prompt (0 to go back): " num
        [[ "$num" == "0" ]] && return 1
    done
    PICKED_CLIENT="${_clients[$((num-1))]}"
}

get_connected() { awk -F',' '/^CLIENT_LIST/{print $2}' "$OVPN_SERVER_DIR/openvpn-status.log" 2>/dev/null; }
get_revoked() { awk -F'/CN=' '/^R/{split($2,a,"/"); print a[1]}' "$EASYRSA_DIR/pki/index.txt" 2>/dev/null; }
list_db_clients() {
    # Use awk strftime to format all dates in one pass — no subprocess per row
    [[ -f "$CLIENTS_DB" ]] || return 0
    awk -F'|' '{i++; printf "%-4s %-20s %-12s %s\n", i")", $1, $2, ($3!=""?strftime("%Y-%m-%d",$3+0):"N/A")}' "$CLIENTS_DB"
}
get_ipv4_list() {
    ip -4 -o addr | awk '{
        gsub(/\/.*$/,"",$4)
        if ($4 !~ /^(127\.|0\.0\.0\.0|169\.254\.|224\.|255\.)/) print $4
    }'
}
get_ipv6_list() { ip -6 -o addr | awk '$4~/^[23]/{gsub(/\/.*$/,"",$4); print $4}'; }

# ─── Pre-flight checks ───────────────────────────────────────────────────────
read -t 0 -N 999999 || true

if [[ "$(readlink /proc/$$/exe 2>/dev/null)" == *"dash"* ]]; then
    err 'Run with "bash", not "sh".'
fi

_kr=$(uname -r)
if [[ "${_kr%%.*}" -eq 2 ]]; then
    err "Old kernel incompatible with this installer."
fi

if [[ "$PATH" != *sbin* ]]; then
    err "\$PATH does not include sbin. Use 'su -' instead of 'su'."
fi

if [[ "$EUID" -ne 0 ]]; then err "Run with superuser privileges."; fi

if [[ ! -e /dev/net/tun ]] || ! ( exec 7<>/dev/net/tun ) 2>/dev/null; then
    err "TUN device not available. Enable TUN before running."
fi

# ─── OS Detection ────────────────────────────────────────────────────────────
# shellcheck source=/dev/null
. /etc/os-release 2>/dev/null || true
case "${ID:-}" in
    ubuntu)
        os="ubuntu"; os_version="${VERSION_ID//./}"; group_name="nogroup" ;;
    debian)
        os="debian"; os_version=$(< /etc/debian_version); os_version="${os_version%%.*}"; group_name="nogroup" ;;
    rocky|almalinux)
        os="rocky"; os_version=${VERSION_ID%%.*}; group_name="nobody" ;;
    fedora)
        os="fedora"; os_version=${VERSION_ID%%.*}; group_name="nobody" ;;
    alpine)
        os="alpine"; _v="${VERSION_ID//./}"; os_version="${_v:0:4}"; group_name="nobody" ;;
    opensuse*|sles)
        os="opensuse"; os_version=${VERSION_ID%%.*}; group_name="nobody" ;;
    amzn)
        os="amzn"; os_version=${VERSION_ID%%.*}; group_name="nobody" ;;
    *)
        err "Unsupported distribution. Supported: Ubuntu, Debian, Rocky, AlmaLinux, Fedora, Alpine, openSUSE, Amazon Linux." ;;
esac

if [[ "$os" == "ubuntu" && "$os_version" -lt 2004 ]]; then err "Ubuntu 20.04+ required."; fi
if [[ "$os" == "debian" && "$os_version" -lt 11 ]]; then err "Debian 11+ required."; fi

# ─── Architecture check ──────────────────────────────────────────────────────
arch=$(uname -m)
if [[ ! "$arch" =~ ^(x86_64|aarch64|armv7l)$ ]]; then warn "Untested architecture: $arch"; fi

# ─── Client generation ───────────────────────────────────────────────────────
new_client() {
    local client="$1"
    local expiry_days="${2:-365}"
    local passphrase="${3:-}"
    if [[ "$expiry_days" -lt 1 ]]; then warn "Expiry must be at least 1 day. Setting to 1."; expiry_days=1; fi
    if [[ "$expiry_days" -gt 3650 ]]; then warn "Expiry capped at 3650 days."; expiry_days=3650; fi
    if [[ -e "$EASYRSA_DIR/pki/issued/${client}.crt" ]]; then err "Client '$client' already exists."; fi

    ( cd "$EASYRSA_DIR" && EASYRSA_CERT_EXPIRE="$expiry_days" run ./easyrsa build-client-full "$client" nopass )

    local key_block
    if [[ -n "$passphrase" ]]; then
        key_block=$(
            passfile=$(mktemp)
            trap 'rm -f "$passfile"' EXIT
            echo "$passphrase" > "$passfile"
            openssl ec -in "$EASYRSA_DIR/pki/private/${client}.key" \
                -aes256 -passout "file:$passfile" 2>/dev/null || \
            openssl rsa -in "$EASYRSA_DIR/pki/private/${client}.key" \
                -aes256 -passout "file:$passfile" 2>/dev/null
        )
    else
        key_block=$(< "$EASYRSA_DIR/pki/private/${client}.key")
    fi

    local now _today; printf -v now '%(%s)T' -1
    printf -v _today '%(%Y-%m-%d)T' -1
    echo "${client}|${_today}|$(( now + expiry_days * SECONDS_PER_DAY ))" >> "$CLIENTS_DB"
    log "Client created: $client (expires in ${expiry_days} days)"

    {
        cat "$OVPN_SERVER_DIR/client-common.txt"
        echo "<ca>"; cat "$EASYRSA_DIR/pki/ca.crt"; echo "</ca>"
        echo "<cert>"
        awk '/BEGIN CERTIFICATE/,0' "$EASYRSA_DIR/pki/issued/${client}.crt"
        echo "</cert>"
        echo "<key>"; echo "$key_block"; echo "</key>"
        echo "<tls-crypt>"
        awk '/BEGIN OpenVPN Static key/,0' "$OVPN_SERVER_DIR/tc.key"
        echo "</tls-crypt>"
    } > "$OVPN_DIR/${client}.ovpn"

    chmod 600 "$OVPN_DIR/${client}.ovpn"

    if command -v qrencode &>/dev/null; then
        qrencode -t ansiutf8 < "$OVPN_DIR/${client}.ovpn"
        ok "QR code generated above for mobile import."
    fi

    ok "Client config: $OVPN_DIR/${client}.ovpn"
}

check_expired_clients() {
    if [[ ! -f "$CLIENTS_DB" ]]; then return; fi
    local now soon
    printf -v now '%(%s)T' -1
    soon=$(( now + 7 * SECONDS_PER_DAY ))
    awk -F'|' -v now="$now" -v soon="$soon" \
        '$3!="" && now>$3{print "EXPIRED:"$1} $3!="" && soon>$3 && now<=$3{print "SOON:"$1}' \
        "$CLIENTS_DB" | while IFS=: read -r _t _n; do
            if [[ "$_t" == "EXPIRED" ]]; then
                warn "Client '$_n' certificate has expired. Consider revoking."
            else
                warn "Client '$_n' certificate expires within 7 days."
            fi
        done
}

show_status() {
    info "=== OpenVPN Server Status ==="
    systemctl status "$SVC" --no-pager -l || true
    local uptime
    uptime=$(systemctl show "$SVC" --property=ActiveEnterTimestamp --value 2>/dev/null || true)
    if [[ -n "$uptime" ]]; then echo "Active since: $uptime"; fi
    echo
    info "=== Server Configuration ==="
    if [[ -f "$SERVER_CONF" ]]; then
        local s_port s_proto s_cipher s_dns s_ver _pki
        # Single awk pass over SERVER_CONF extracts port, proto, cipher, and DNS servers
        IFS='|' read -r s_port s_proto s_cipher s_dns < <(
            awk '/^port /{p=$2} /^proto /{r=$2} /^cipher /{c=$2}
                 /dhcp-option DNS/{d=(d?d",":"")$NF}
                 END{printf "%s|%s|%s|%s\n",p,r,c,d}' "$SERVER_CONF"
        )
        s_ver=$(openvpn --version 2>/dev/null | awk 'NR==1{print $2; exit}') || s_ver="unknown"
        _pki=$(du -sh "$EASYRSA_DIR/pki" 2>/dev/null | awk '{print $1}') || _pki="N/A"
        echo "  Port    : ${s_port:-unknown}"
        echo "  Protocol: ${s_proto:-unknown}"
        echo "  Cipher  : ${s_cipher:-unknown}"
        echo "  DNS     : ${s_dns:-system}"
        echo "  Version : $s_ver"
        echo "  PKI size: $_pki"
    else
        echo "  Config not found."
    fi
    echo
    info "=== Connected Clients ==="
    if [[ -f "$OVPN_SERVER_DIR/openvpn-status.log" ]]; then
        awk -F',' '/^CLIENT_LIST/{n++; printf "  %-20s %-18s in=%-10s out=%s\n",$2,$3,$6,$7} END{print "Connected: "(n+0)" client(s)"}' \
            "$OVPN_SERVER_DIR/openvpn-status.log"
    else
        echo "No status log found."
    fi
    echo
    info "=== Registered Clients ==="
    if [[ -f "$CLIENTS_DB" && -s "$CLIENTS_DB" ]]; then
        printf "%-4s %-20s %-12s %s\n" "#" "NAME" "CREATED" "EXPIRES"
        list_db_clients
    else
        echo "No clients registered."
    fi
    check_expired_clients
}

# ─── Revoke helper ───────────────────────────────────────────────────────────
do_revoke() {
    local client="$1"
    if [[ ! -f "$EASYRSA_DIR/pki/issued/${client}.crt" ]]; then
        warn "Certificate not found for '$client'; skipping revocation."
        return 1
    fi
    run "$EASYRSA_DIR/easyrsa" --batch revoke "$client"
    crl_update
    rm -f "$OVPN_DIR/${client}.ovpn"
    sed -i "/^$(sed_escape "$client")|/d" "$CLIENTS_DB" 2>/dev/null || warn "Could not remove $client from DB."
    ok "$client revoked!"
    log "Client revoked: $client"
}

# ─── Fresh Installation ───────────────────────────────────────────────────────
if [[ ! -e "$SERVER_CONF" ]]; then
    clear
    info 'Welcome to the OpenVPN road warrior installer!'

    # IPv4 selection
    mapfile -t ipv4_list < <(get_ipv4_list)
    if [[ "${#ipv4_list[@]}" -eq 1 ]]; then
        ip="${ipv4_list[0]}"
    else
        echo; echo "Which IPv4 address should be used?"
        for i in "${!ipv4_list[@]}"; do printf "  %s) %s\n" "$((i+1))" "${ipv4_list[$i]}"; done
        read -rp "IPv4 address [1]: " ip_number
        until [[ -z "$ip_number" || "$ip_number" =~ ^[0-9]+$ && "$ip_number" -le "${#ipv4_list[@]}" ]]; do
            echo "$ip_number: invalid selection."
            read -rp "IPv4 address [1]: " ip_number
        done
        [[ -z "$ip_number" ]] && ip_number="1"
        ip="${ipv4_list[$((ip_number-1))]}"
    fi

    # NAT detection
    public_ip=""
    if [[ "$ip" =~ ^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168) ]]; then
        echo; echo "Server is behind NAT. What is the public IPv4 address or hostname?"
        get_public_ip=$(wget -T10 -t1 -4qO- "http://ip1.dynupdate.no-ip.com/" 2>/dev/null || curl -m10 -4Ls "http://ip1.dynupdate.no-ip.com/" || true)
        get_public_ip="${get_public_ip%%$'\n'*}"
        read -rp "Public IPv4 / hostname [$get_public_ip]: " public_ip
        until [[ -n "$get_public_ip" || -n "$public_ip" ]]; do
            echo "Invalid input."
            read -rp "Public IPv4 / hostname: " public_ip
        done
        [[ -z "$public_ip" ]] && public_ip="$get_public_ip"
    fi

    # IPv6 selection
    ip6=""
    mapfile -t ipv6_list < <(get_ipv6_list)
    if [[ "${#ipv6_list[@]}" -eq 1 ]]; then
        ip6="${ipv6_list[0]}"
    elif [[ "${#ipv6_list[@]}" -gt 1 ]]; then
        echo; echo "Which IPv6 address should be used?"
        for i in "${!ipv6_list[@]}"; do printf "  %s) %s\n" "$((i+1))" "${ipv6_list[$i]}"; done
        read -rp "IPv6 address [1]: " ip6_number
        until [[ -z "$ip6_number" || "$ip6_number" =~ ^[0-9]+$ && "$ip6_number" -le "${#ipv6_list[@]}" ]]; do
            echo "$ip6_number: invalid selection."
            read -rp "IPv6 address [1]: " ip6_number
        done
        [[ -z "$ip6_number" ]] && ip6_number="1"
        ip6="${ipv6_list[$((ip6_number-1))]}"
    fi

    # Protocol
    echo; echo "Which protocol should OpenVPN use?"
    echo "   1) UDP (recommended)"; echo "   2) TCP"
    read -rp "Protocol [1]: " protocol
    until [[ -z "$protocol" || "$protocol" =~ ^[12]$ ]]; do
        echo "$protocol: invalid selection."
        read -rp "Protocol [1]: " protocol
    done
    case "$protocol" in
        1|"") protocol=udp ;;
        2)    protocol=tcp ;;
    esac

    # Port
    echo; echo "What port should OpenVPN listen on?"
    read -rp "Port [1194]: " port
    until [[ -z "$port" || "$port" =~ ^[0-9]+$ && "$port" -ge 1 && "$port" -le 65535 ]]; do
        echo "$port: invalid port."
        read -rp "Port [1194]: " port
    done
    [[ -z "$port" ]] && port="1194"

    # Check port availability
    if ss -tulnp 2>/dev/null | grep -qF ":${port} "; then
        warn "Port $port appears to be in use. Proceeding anyway."
    fi

    # DNS
    echo; echo "Select a DNS server for clients:"
    echo "   1) Current system resolvers"
    echo "   2) Google (8.8.8.8)"
    echo "   3) Cloudflare (1.1.1.1)"
    echo "   4) OpenDNS"
    echo "   5) Quad9"
    echo "   6) AdGuard"
    read -rp "DNS server [1]: " dns
    until [[ -z "$dns" || "$dns" =~ ^[1-6]$ ]]; do
        echo "$dns: invalid selection."
        read -rp "DNS server [1]: " dns
    done
    [[ -z "$dns" ]] && dns=1

    # Client cert expiry
    echo; cert_days=$(read_days)

    # Client name
    echo; echo "Enter a name for the first client:"
    read -rp "Name [client]: " unsanitized_client
    client=$(sanitize_name "$unsanitized_client")
    [[ -z "$client" ]] && client="client"

    echo; info "OpenVPN installation is ready to begin."
    echo "  IP      : ${public_ip:-$ip}"
    echo "  Protocol: $protocol"
    echo "  Port    : $port"
    echo "  DNS     : $dns"
    echo "  Client  : $client (${cert_days} days)"
    echo

    # Firewall check
    firewall=""
    if ! systemctl is-active --quiet firewalld.service && ! hash iptables 2>/dev/null; then
        if [[ "$os" == "fedora" || "$os" == "rocky" ]]; then
            firewall="firewalld"
            warn "firewalld will be installed to manage routing tables."
        elif [[ "$os" == "debian" || "$os" == "ubuntu" ]]; then
            firewall="iptables"
        fi
    fi

    pause

    # Container: disable LimitNPROC
    if systemd-detect-virt -cq 2>/dev/null; then
        mkdir -p "/etc/systemd/system/$SVC.d/"
        printf "[Service]\nLimitNPROC=infinity\n" > "/etc/systemd/system/$SVC.d/disable-limitnproc.conf"
    fi

    # Install packages + all dependencies
    info "Installing packages..."
    if [[ "$os" == "debian" || "$os" == "ubuntu" ]]; then
        run apt-get update -qq
        run apt-get install -y \
            openvpn openssl ca-certificates \
            wget curl tar iproute2 \
            iptables iptables-persistent \
            qrencode logrotate \
            ${firewall:-}
    elif [[ "$os" == "rocky" || "$os" == "fedora" ]]; then
        run dnf install -y epel-release 2>/dev/null || true
        run dnf install -y \
            openvpn openssl ca-certificates \
            wget curl tar iproute \
            iptables iptables-services \
            policycoreutils-python-utils \
            qrencode logrotate \
            ${firewall:-}
    elif [[ "$os" == "amzn" && "$os_version" == "2023" ]]; then
        run dnf install -y \
            openvpn openssl ca-certificates \
            wget curl tar iproute \
            iptables iptables-services \
            qrencode logrotate \
            ${firewall:-}
    elif [[ "$os" == "amzn" ]]; then
        run amazon-linux-extras enable epel
        run yum install -y epel-release
        run yum install -y \
            openvpn openssl ca-certificates \
            wget curl tar iproute \
            iptables iptables-services \
            qrencode logrotate \
            ${firewall:-}
    elif [[ "$os" == "opensuse" ]]; then
        run zypper install -y \
            openvpn openssl ca-certificates \
            wget curl tar iproute2 \
            iptables qrencode logrotate
    elif [[ "$os" == "alpine" ]]; then
        run apk add --no-cache \
            openvpn openssl ca-certificates \
            wget curl tar iproute2 \
            iptables ip6tables \
            qrencode logrotate
    fi

    if [[ "${firewall:-}" == "firewalld" ]]; then run systemctl enable --now firewalld.service; fi

    # Setup easy-rsa
    info "Setting up PKI with ECC keys..."
    mkdir -p "$EASYRSA_DIR"
    download_easyrsa "$EASYRSA_DIR"
    chown -R root:root "$EASYRSA_DIR"

    # Use EC (prime256v1) instead of RSA for stronger, faster keys
    cat > "$EASYRSA_DIR/vars" <<'EOF'
set_var EASYRSA_ALGO ec
set_var EASYRSA_CURVE prime256v1
set_var EASYRSA_CA_EXPIRE 3650
set_var EASYRSA_CERT_EXPIRE 365
set_var EASYRSA_DIGEST sha512
EOF

    # Run all PKI init steps in a subshell so the cd does not affect the main script cwd
    ( cd "$EASYRSA_DIR"
      run ./easyrsa init-pki
      run ./easyrsa --batch build-ca nopass
      EASYRSA_CERT_EXPIRE=3650 run ./easyrsa build-server-full server nopass
      EASYRSA_CRL_DAYS=3650 run ./easyrsa gen-crl
      cp pki/ca.crt pki/issued/server.crt pki/private/server.key pki/crl.pem "$OVPN_SERVER_DIR"
    )
    chown root:"$group_name" "$OVPN_SERVER_DIR"
    chmod 750 "$OVPN_SERVER_DIR"/
    chown nobody:"$group_name" "$OVPN_SERVER_DIR/crl.pem"
    chmod 640 "$OVPN_SERVER_DIR/crl.pem"

    # tls-crypt key (shared static key for HMAC firewall)
    run openvpn --genkey secret "$OVPN_SERVER_DIR/tc.key"

    # Management socket password — umask 077 ensures 0600 before any data is written
    ( umask 077; openssl rand -hex 16 > "$OVPN_SERVER_DIR/mgmt.pwd" )

    # Hardened server.conf (AES-256-GCM, TLS 1.2+, no compression)
    info "Writing hardened server.conf..."
    cat > "$SERVER_CONF" <<EOF
local $ip
port $port
proto $protocol
dev tun
ca ca.crt
cert server.crt
key server.key
dh none
auth SHA512
cipher AES-256-GCM
data-ciphers AES-256-GCM:AES-128-GCM
tls-crypt tc.key
tls-version-min 1.2
tls-cipher TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384
topology subnet
server $VPN_SUBNET 255.255.255.0
ifconfig-pool-persist ipp.txt
keepalive 10 120
user nobody
group $group_name
persist-key
persist-tun
status openvpn-status.log
log-append /var/log/openvpn.log
verb 3
crl-verify crl.pem
management 127.0.0.1 $MGMT_PORT $OVPN_SERVER_DIR/mgmt.pwd
# Disable compression to prevent VORACLE attack
compress migrate
EOF

    # IPv6
    if [[ -z "${ip6:-}" ]]; then
        echo 'push "redirect-gateway def1 bypass-dhcp"' >> "$SERVER_CONF"
    else
        echo "server-ipv6 $VPN_SUBNET6" >> "$SERVER_CONF"
        echo 'push "redirect-gateway def1 ipv6 bypass-dhcp"' >> "$SERVER_CONF"
    fi

    # DNS push
    case "$dns" in
        1|"")
            resolv_conf="/etc/resolv.conf"
            [[ "$(< /etc/resolv.conf)" == *'nameserver 127.0.0.53'* ]] && resolv_conf="/run/systemd/resolve/resolv.conf"
            awk '/^nameserver/{if($2~/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) print "push \"dhcp-option DNS "$2"\""}' \
                "$resolv_conf" >> "$SERVER_CONF" ;;
        2) push_dns 8.8.8.8 8.8.4.4 ;;
        3) push_dns 1.1.1.1 1.0.0.1 ;;
        4) push_dns 208.67.222.222 208.67.220.220 ;;
        5) push_dns 9.9.9.9 149.112.112.112 ;;
        6) push_dns 94.140.14.14 94.140.15.15 ;;
    esac

    if [[ "$protocol" == "udp" ]]; then echo "explicit-exit-notify" >> "$SERVER_CONF"; fi

    # Performance tuning
    cat >> "$SERVER_CONF" <<'EOF'
sndbuf 393216
rcvbuf 393216
push "sndbuf 393216"
push "rcvbuf 393216"
fast-io
EOF

    # IP forwarding
    echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/30-openvpn-forward.conf
    echo 1 > /proc/sys/net/ipv4/ip_forward
    if [[ -n "${ip6:-}" ]]; then
        echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.d/30-openvpn-forward.conf
        echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
    fi

    # Firewall rules
    if systemctl is-active --quiet firewalld.service; then
        firewall-cmd --add-port="$port"/"$protocol"
        firewall-cmd --zone=trusted --add-source="$VPN_SUBNET_CIDR"
        firewall-cmd --permanent --add-port="$port"/"$protocol"
        firewall-cmd --permanent --zone=trusted --add-source="$VPN_SUBNET_CIDR"
        firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s "$VPN_SUBNET_CIDR" ! -d "$VPN_SUBNET_CIDR" -j SNAT --to "$ip"
        firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s "$VPN_SUBNET_CIDR" ! -d "$VPN_SUBNET_CIDR" -j SNAT --to "$ip"
        if [[ -n "${ip6:-}" ]]; then
            firewall-cmd --zone=trusted --add-source="$VPN_SUBNET6"
            firewall-cmd --permanent --zone=trusted --add-source="$VPN_SUBNET6"
            firewall-cmd --direct --add-rule ipv6 nat POSTROUTING 0 -s "$VPN_SUBNET6" ! -d "$VPN_SUBNET6" -j SNAT --to "$ip6"
            firewall-cmd --permanent --direct --add-rule ipv6 nat POSTROUTING 0 -s "$VPN_SUBNET6" ! -d "$VPN_SUBNET6" -j SNAT --to "$ip6"
        fi
    else
        iptables_path=$(command -v iptables)
        ip6tables_path=$(command -v ip6tables)
        if [[ $(systemd-detect-virt 2>/dev/null) == "openvz" ]] && [[ "$(readlink -f "$(command -v iptables)")" == *nft* ]] && hash iptables-legacy 2>/dev/null; then
            iptables_path=$(command -v iptables-legacy)
            ip6tables_path=$(command -v ip6tables-legacy)
        fi
        cat > /etc/systemd/system/openvpn-iptables.service <<EOF
[Unit]
Before=network.target
[Service]
Type=oneshot
ExecStart=$iptables_path -t nat -A POSTROUTING -s $VPN_SUBNET_CIDR ! -d $VPN_SUBNET_CIDR -j SNAT --to $ip
ExecStart=$iptables_path -I INPUT -p $protocol --dport $port -j ACCEPT
ExecStart=$iptables_path -I FORWARD -s $VPN_SUBNET_CIDR -j ACCEPT
ExecStart=$iptables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$iptables_path -t nat -D POSTROUTING -s $VPN_SUBNET_CIDR ! -d $VPN_SUBNET_CIDR -j SNAT --to $ip
ExecStop=$iptables_path -D INPUT -p $protocol --dport $port -j ACCEPT
ExecStop=$iptables_path -D FORWARD -s $VPN_SUBNET_CIDR -j ACCEPT
ExecStop=$iptables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
EOF
        if [[ -n "${ip6:-}" ]]; then
            cat >> /etc/systemd/system/openvpn-iptables.service <<EOF
ExecStart=$ip6tables_path -t nat -A POSTROUTING -s $VPN_SUBNET6 ! -d $VPN_SUBNET6 -j SNAT --to $ip6
ExecStart=$ip6tables_path -I FORWARD -s $VPN_SUBNET6 -j ACCEPT
ExecStart=$ip6tables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$ip6tables_path -t nat -D POSTROUTING -s $VPN_SUBNET6 ! -d $VPN_SUBNET6 -j SNAT --to $ip6
ExecStop=$ip6tables_path -D FORWARD -s $VPN_SUBNET6 -j ACCEPT
ExecStop=$ip6tables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
EOF
        fi
        printf "RemainAfterExit=yes\n[Install]\nWantedBy=multi-user.target\n" >> /etc/systemd/system/openvpn-iptables.service
        run systemctl daemon-reload
        run systemctl enable --now openvpn-iptables.service
    fi

    # SELinux custom port
    selinux_port a "$port" "$protocol"

    # Apply public IP before writing client-common.txt
    if [[ -n "${public_ip:-}" ]]; then ip="$public_ip"; fi

    # client-common.txt (hardened client config)
    cat > "$OVPN_SERVER_DIR/client-common.txt" <<EOF
client
dev tun
proto $protocol
remote $ip $port
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA512
cipher AES-256-GCM
data-ciphers AES-256-GCM:AES-128-GCM
tls-version-min 1.2
tls-cipher TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384
ignore-unknown-option block-outside-dns
block-outside-dns
verb 3
EOF

    run systemctl enable --now "$SVC"

    # Setup logrotate
    cat > /etc/logrotate.d/openvpn-manager <<'EOF'
/var/log/openvpn-manager.log /var/log/openvpn.log {
    weekly
    rotate 8
    compress
    missingok
    notifempty
}
EOF

    touch "$CLIENTS_DB"
    new_client "$client" "$cert_days"
    echo
    ok "Installation complete!"
    echo "Client config: ~/${client}.ovpn"
    echo "New clients: run this script again."
    log "Installation completed. First client: $client"

else
    # ─── Management Menu ─────────────────────────────────────────────────────
    while true; do
    clear
    info "OpenVPN is already installed."
    check_expired_clients
    echo
    echo "Select an option:"
    echo "   1) Add a new client"
    echo "   2) Add multiple clients (bulk)"
    echo "   3) Revoke an existing client"
    echo "   4) Revoke multiple clients (bulk)"
    echo "   5) Revoke all expired clients"
    echo "   6) Show status"
    echo "   7) Remove OpenVPN"
    echo "   8) Renew client certificate"
    echo "   9) Show client connection history"
    echo "   10) Restart/Reload OpenVPN"
    echo "   11) Backup & Restore"
    echo "   12) Show client QR code"
    echo "   13) Change client expiry"
    echo "   14) Disconnect a client"
    echo "   15) View live logs"
    echo "   16) Update EasyRSA"
    echo "   18) Export client .ovpn via SCP"
    echo "   19) Rename a client"
    echo "   20) Bandwidth usage per client"
    echo "   21) Rotate tls-crypt key"
    echo "   22) Test connectivity"
    echo "   23) Change server port/protocol"
    echo "   24) List revoked clients"
    echo "   0) Exit"
    read -rp "Option: " option
    until [[ "$option" =~ ^(0|[1-9]|1[0-6]|1[89]|2[0-4])$ ]]; do
        echo "$option: invalid selection."
        read -rp "Option: " option
    done

    case "$option" in
        1)
            echo; echo "Provide a name for the client (or 0 to go back):"
            read -rp "Name: " unsanitized_client
            [[ "$unsanitized_client" == "0" ]] && continue
            client=$(sanitize_name "$unsanitized_client")
            while [[ -z "$client" || -e "$EASYRSA_DIR/pki/issued/${client}.crt" ]]; do
                echo "$client: invalid or already exists."
                read -rp "Name (or 0 to go back): " unsanitized_client
                [[ "$unsanitized_client" == "0" ]] && continue 2
                client=$(sanitize_name "$unsanitized_client")
            done
            cert_days=$(read_days)
            read -rsp "Passphrase to protect .ovpn key (leave empty for none): " ovpn_pass; echo
            if [[ -n "$ovpn_pass" ]]; then
                read -rsp "Confirm passphrase: " ovpn_pass2; echo
                [[ "$ovpn_pass" != "$ovpn_pass2" ]] && err "Passphrases do not match."
            fi
            new_client "$client" "$cert_days" "$ovpn_pass"
            ;;
        2)
            echo; echo "Enter client names (one per line, empty line to finish):"
            bulk_days=$(read_days)
            bulk_count=0
            while true; do
                read -rp "Client name (or Enter to finish): " unsanitized_client
                [[ -z "$unsanitized_client" ]] && break
                client=$(sanitize_name "$unsanitized_client")
                if [[ -z "$client" || -e "$EASYRSA_DIR/pki/issued/${client}.crt" ]]; then
                    warn "$client: invalid or already exists, skipping."
                    continue
                fi
                new_client "$client" "$bulk_days"
                (( bulk_count++ )) || true
            done
            ok "$bulk_count client(s) created."
            ;;
        3)
            pick_client "Client to revoke" || continue
            client="$PICKED_CLIENT"
            echo; if confirm "Confirm revocation of '$client'"; then
                do_revoke "$client"; reload_service
            else
                echo; echo "$client revocation aborted!"
            fi
            ;;
        4)
            mapfile -t _all_clients < <(get_clients)
            if [[ ${#_all_clients[@]} -eq 0 ]]; then echo; echo "No existing clients!"; pause; continue; fi
            echo; echo "Select clients to revoke (space-separated numbers):"
            for i in "${!_all_clients[@]}"; do printf "  %s) %s\n" "$((i+1))" "${_all_clients[$i]}"; done
            echo "   0) Back"
            read -rp "Client numbers (0 to go back): " bulk_numbers
            [[ "$bulk_numbers" == "0" ]] && continue
            bulk_revoked=0
            for n in $bulk_numbers; do
                if [[ "$n" =~ ^[0-9]+$ && "$n" -ge 1 && "$n" -le ${#_all_clients[@]} ]]; then
                    do_revoke "${_all_clients[$((n-1))]}"
                    (( bulk_revoked++ )) || true
                fi
            done
            if [[ "$bulk_revoked" -gt 0 ]]; then
                reload_service; ok "$bulk_revoked client(s) revoked."
            fi
            ;;
        5)
            if [[ ! -f "$CLIENTS_DB" || ! -s "$CLIENTS_DB" ]]; then echo; echo "No clients in DB."; pause; continue; fi
            printf -v now '%(%s)T' -1; expired_count=0
            mapfile -t _to_revoke < <(
                awk -F'|' -v now="$now" 'NR==FNR{a[$1]=1;next} $3!="" && now>$3 && ($1 in a){print $1}' \
                    <(get_clients) "$CLIENTS_DB"
            )
            for _n in "${_to_revoke[@]}"; do do_revoke "$_n"; (( expired_count++ )) || true; done
            if [[ "$expired_count" -gt 0 ]]; then
                reload_service; ok "$expired_count expired client(s) revoked."
            else
                echo "No expired clients found."
            fi
            ;;
        6)
            show_status
            ;;
        7)
            echo; if confirm "Confirm OpenVPN removal"; then
                read port protocol < <(awk '/^port /{p=$2} /^proto /{r=$2} END{print p,r}' "$SERVER_CONF")
                [[ -n "$port" && -n "$protocol" ]] || err "Could not read port/protocol from $SERVER_CONF"
                if systemctl is-active --quiet firewalld.service; then
                    ip=$(firewall-cmd --direct --get-rules ipv4 nat POSTROUTING | awk '/10\.8\.0\.0\/24/{print $NF}')
                    firewall-cmd --remove-port="$port"/"$protocol"
                    firewall-cmd --zone=trusted --remove-source="$VPN_SUBNET_CIDR"
                    firewall-cmd --permanent --remove-port="$port"/"$protocol"
                    firewall-cmd --permanent --zone=trusted --remove-source="$VPN_SUBNET_CIDR"
                    firewall-cmd --direct --remove-rule ipv4 nat POSTROUTING 0 -s "$VPN_SUBNET_CIDR" ! -d "$VPN_SUBNET_CIDR" -j SNAT --to "$ip"
                    firewall-cmd --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -s "$VPN_SUBNET_CIDR" ! -d "$VPN_SUBNET_CIDR" -j SNAT --to "$ip"
                    if [[ -f "$SERVER_CONF" ]] && [[ "$(< "$SERVER_CONF")" == *"server-ipv6"* ]]; then
                        ip6=$(firewall-cmd --direct --get-rules ipv6 nat POSTROUTING | awk '/fddd:1194/{print $NF}')
                        firewall-cmd --zone=trusted --remove-source="$VPN_SUBNET6"
                        firewall-cmd --permanent --zone=trusted --remove-source="$VPN_SUBNET6"
                        firewall-cmd --direct --remove-rule ipv6 nat POSTROUTING 0 -s "$VPN_SUBNET6" ! -d "$VPN_SUBNET6" -j SNAT --to "$ip6"
                        firewall-cmd --permanent --direct --remove-rule ipv6 nat POSTROUTING 0 -s "$VPN_SUBNET6" ! -d "$VPN_SUBNET6" -j SNAT --to "$ip6"
                    fi
                else
                    systemctl disable --now openvpn-iptables.service
                    rm -f /etc/systemd/system/openvpn-iptables.service
                fi
                selinux_port d "$port" "$protocol"
                systemctl disable --now "$SVC"
                rm -rf "$OVPN_SERVER_DIR"
                rm -rf "/etc/systemd/system/$SVC.d"
                rm -f /etc/sysctl.d/30-openvpn-forward.conf
                sysctl -w net.ipv4.ip_forward=0 2>/dev/null || true
                sysctl -w net.ipv6.conf.all.forwarding=0 2>/dev/null || true
                rm -f /etc/logrotate.d/openvpn-manager
                if [[ "$os" == "debian" || "$os" == "ubuntu" ]]; then
                    apt-get remove --purge -y openvpn
                elif [[ "$os" == "alpine" ]]; then
                    apk del openvpn
                elif [[ "$os" == "opensuse" ]]; then
                    zypper remove -y openvpn
                elif [[ "$os" == "amzn" && "$os_version" == "2023" ]]; then
                    dnf remove -y openvpn
                elif [[ "$os" == "amzn" ]]; then
                    yum remove -y openvpn
                else
                    dnf remove -y openvpn
                fi
                find /root /home -maxdepth 2 -name "*.ovpn" -delete 2>/dev/null || true
                rm -f /var/log/openvpn-manager.log /var/log/openvpn.log
                systemctl daemon-reload
                ok "OpenVPN removed!"
                log "OpenVPN uninstalled."
            else
                echo; echo "OpenVPN removal aborted!"
            fi
            ;;
        8)
            pick_client "Client to renew" || continue
            client="$PICKED_CLIENT"
            renew_days=$(read_days)
            echo; if confirm "Confirm renewal of '$client'"; then
                run "$EASYRSA_DIR/easyrsa" --batch revoke "$client"
                crl_update
                rm -f "$OVPN_DIR/${client}.ovpn"
                sed -i "/^$(sed_escape "$client")|/d" "$CLIENTS_DB" 2>/dev/null || warn "Could not remove $client from DB."
                rm -f "$EASYRSA_DIR/pki/issued/${client}.crt" "$EASYRSA_DIR/pki/private/${client}.key" "$EASYRSA_DIR/pki/reqs/${client}.req"
                new_client "$client" "$renew_days"
                reload_service; log "Client renewed: $client (${renew_days} days)"
            else
                echo; echo "Renewal aborted."
            fi
            ;;
        9)
            info "=== Client Connection History ==="
            vpn_log="/var/log/openvpn.log"
            if [[ ! -f "$vpn_log" ]]; then
                echo "No OpenVPN log found at $vpn_log."
            else
                echo; printf "%-20s %-16s %-22s %s\n" "CLIENT" "REAL IP" "VIRTUAL IP" "TIMESTAMP"
                awk '/MULTI_SV|MULTI: Learn/ {
                    cl=""; rip=""; ts=""
                    if (match($0, /\[[^]]+\]/))       { cl=substr($0,RSTART+1,RLENGTH-2) }
                    if (match($0, /[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*(:[0-9][0-9]*)?/)) { rip=substr($0,RSTART,RLENGTH) }
                    if (match($0, /[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9]/)) { ts=substr($0,RSTART,RLENGTH) }
                    if (cl!="") printf "  %-20s %-16s %-22s %s\n", cl, rip, ts, ""
                }' "$vpn_log" | head -50 || true
                echo
                echo "--- Last 20 connect/disconnect events ---"
                awk '/CONNECTED|DISCONNECTED|peer info/' "$vpn_log" 2>/dev/null | tail -20 || echo "No connect/disconnect events found."
            fi
            ;;
        10)
            echo; echo "   1) Reload (apply config changes, keep connections)"
            echo "   2) Restart (drop all connections)"
            echo "   0) Back"
            read -rp "Action [1]: " svc_action
            [[ "$svc_action" == "0" ]] && continue
            [[ -z "$svc_action" ]] && svc_action=1
            if [[ "$svc_action" == "1" ]]; then
                if systemctl reload "$SVC"; then
                    ok "OpenVPN reloaded."
                else
                    err "Reload failed."
                fi
                log "OpenVPN reloaded."
            elif [[ "$svc_action" == "2" ]]; then
                test_server_config
                if systemctl restart "$SVC"; then
                    ok "OpenVPN restarted."
                else
                    err "Restart failed."
                fi
                log "OpenVPN restarted."
            else
                echo "Invalid selection."
            fi
            ;;
        11)
            echo; echo "   1) Backup"
            echo "   2) Restore from list"
            echo "   3) Restore from path"
            echo "   0) Back"
            read -rp "Action: " br_action
            [[ "$br_action" == "0" ]] && continue
            if [[ "$br_action" == "1" ]]; then
                printf -v _bts '%(%Y%m%d-%H%M%S)T' -1
                backup_file=$(mktemp "/root/openvpn-backup-${_bts}-XXXXXX.tar.gz")
                chmod 600 "$backup_file"
                tar -czf "$backup_file" "$OVPN_SERVER_DIR" 2>/dev/null || true
                ok "Backup saved: $backup_file"
                log "Backup created: $backup_file"
            elif [[ "$br_action" == "2" || "$br_action" == "3" ]]; then
                if [[ "$br_action" == "2" ]]; then
                    mapfile -t backups < <(find /root -maxdepth 1 -name 'openvpn-backup-*.tar.gz' -exec stat -c '%Y %n' {} + 2>/dev/null | sort -rn | awk '{print $2}')
                    if [[ ${#backups[@]} -eq 0 ]]; then echo "No backups found in /root/."; pause; continue; fi
                    echo; printf "%3s  %-45s %s\n" "#" "FILE" "SIZE"
                    for i in "${!backups[@]}"; do
                        printf "%3s) %-45s %s\n" "$((i+1))" "$(basename "${backups[$i]}")" "$(du -sh "${backups[$i]}" | awk '{print $1}')"
                    done
                    read -rp "Select backup: " bnum
                    until [[ "$bnum" =~ ^[0-9]+$ && "$bnum" -ge 1 && "$bnum" -le ${#backups[@]} ]]; do
                        echo "Invalid."; read -rp "Select backup: " bnum
                    done
                    restore_file="${backups[$((bnum-1))]}"
                else
                    read -rp "Path to backup file: " restore_file
                    [[ ! -f "$restore_file" ]] && err "File not found: $restore_file"
                fi
                if ! confirm "Overwrite current config with '$restore_file'?"; then
                    echo "Aborted."; pause; continue
                fi
                # Validate archive contains our expected path before overwriting anything
                tar -tzf "$restore_file" 2>/dev/null | grep -q "openvpn/server" \
                    || err "Backup does not appear to be a valid OpenVPN backup: $restore_file"
                systemctl stop "$SVC" 2>/dev/null || true
                tar -xzf "$restore_file" -C / 2>/dev/null || err "Restore failed."
                systemctl start "$SVC"
                ok "Restore complete."
                log "Restored from: $restore_file"
            else
                echo "Invalid selection."
            fi
            ;;
        12)
            if ! command -v qrencode &>/dev/null; then echo; echo "qrencode not installed."; pause; continue; fi
            pick_client "Client for QR" || continue
            ovpn_file="$OVPN_DIR/${PICKED_CLIENT}.ovpn"
            [[ ! -f "$ovpn_file" ]] && err ".ovpn not found: $ovpn_file"
            qrencode -t ansiutf8 < "$ovpn_file"
            ok "QR code for $PICKED_CLIENT"
            ;;
        13)
            [[ ! -f "$CLIENTS_DB" || ! -s "$CLIENTS_DB" ]] && { echo; echo "No clients in DB."; pause; continue; }
            echo; printf "%-4s %-20s %-12s %s\n" "#" "NAME" "CREATED" "EXPIRES"
            mapfile -t DB_LINES < "$CLIENTS_DB"
            list_db_clients
            read -rp "Select client (0 to go back): " ce_num
            [[ "$ce_num" == "0" ]] && continue
            until [[ "$ce_num" =~ ^[0-9]+$ && "$ce_num" -ge 1 && "$ce_num" -le ${#DB_LINES[@]} ]]; do
                echo "Invalid."; read -rp "Select client (0 to go back): " ce_num
                [[ "$ce_num" == "0" ]] && continue 2
            done
            IFS='|' read -r ce_name ce_created _ <<< "${DB_LINES[$((ce_num-1))]}"
            ce_days=$(read_days)
            printf -v _now '%(%s)T' -1; new_expiry=$(( _now + ce_days * SECONDS_PER_DAY ))
            sed -i "/^$(sed_escape "$ce_name")|/c\\$(sed_escape "$ce_name")|${ce_created}|${new_expiry}" "$CLIENTS_DB" \
                || { warn "Failed to update expiry in $CLIENTS_DB"; pause; continue; }
            printf -v new_date '%(%Y-%m-%d)T' "$new_expiry"
            ok "$ce_name expiry updated to $new_date"
            log "Client expiry changed: $ce_name -> $new_date"
            ;;
        14)
            if [[ ! -f "$OVPN_SERVER_DIR/openvpn-status.log" ]]; then
                echo; echo "No status log found."; pause; continue
            fi
            mapfile -t connected < <(get_connected)
            if [[ ${#connected[@]} -eq 0 ]]; then echo; echo "No clients connected."; pause; continue; fi
            echo; echo "Connected clients:"
            for i in "${!connected[@]}"; do echo "  $((i+1))) ${connected[$i]}"; done
            echo "  0) Back"
            read -rp "Select client to disconnect (0 to go back): " dc_num
            [[ "$dc_num" == "0" ]] && continue
            until [[ "$dc_num" =~ ^[0-9]+$ && "$dc_num" -ge 1 && "$dc_num" -le ${#connected[@]} ]]; do
                echo "Invalid."; read -rp "Select client to disconnect (0 to go back): " dc_num
                [[ "$dc_num" == "0" ]] && continue 2
            done
            dc_client="${connected[$((dc_num-1))]}"
            mgmt_pwd=$(< "$OVPN_SERVER_DIR/mgmt.pwd" 2>/dev/null) || mgmt_pwd=""
            _mgmt_cmd_arr=()
            if command -v nc &>/dev/null; then
                _mgmt_cmd_arr=(nc -q1 127.0.0.1 "$MGMT_PORT")
            elif command -v socat &>/dev/null; then
                _mgmt_cmd_arr=(socat - TCP:127.0.0.1:"$MGMT_PORT")
            else
                warn "Neither nc nor socat found; cannot reach management socket."
                pause; continue
            fi
            result=$(printf 'auth %s\nkill %s\nquit\n' "$mgmt_pwd" "$dc_client" | "${_mgmt_cmd_arr[@]}" 2>/dev/null || true)
            if [[ "$result" == *"SUCCESS"* ]]; then
                ok "$dc_client disconnected."
                log "Client disconnected: $dc_client"
            else
                warn "Could not disconnect $dc_client (management socket unreachable or auth failed)."
            fi
            ;;
        15)
            echo; echo "   1) OpenVPN log (tail -f /var/log/openvpn.log)"
            echo "   2) journalctl (follow systemd unit)"
            echo "   3) Manager log (tail -f $LOG_FILE)"
            echo "   0) Back"
            read -rp "Source [1]: " log_src
            [[ "$log_src" == "0" ]] && continue
            [[ -z "$log_src" ]] && log_src=1
            echo "Press Ctrl+C to stop."; echo
            case "$log_src" in
                1) tail -f /var/log/openvpn.log 2>/dev/null || echo "Log not found." ;;
                2) journalctl -u "$SVC" -f --no-pager ;;
                3) tail -f "$LOG_FILE" 2>/dev/null || echo "Log not found." ;;
                *) echo "Invalid selection." ;;
            esac
            ;;
        16)
            cur_ver=$("$EASYRSA_DIR/easyrsa" --version 2>/dev/null | awk '/EasyRSA/{print $2; exit}' || echo "unknown")
            echo; echo "Current EasyRSA version: $cur_ver"
            echo "Downloading latest from: $EASY_RSA_URL"
            # Subshell isolates the EXIT trap so it never leaks into the main script
            ( tmp_dir=$(mktemp -d)
              trap 'rm -rf "$tmp_dir"' EXIT
              download_easyrsa "$tmp_dir"
              cp -f "$tmp_dir/easyrsa" "$EASYRSA_DIR/easyrsa"
              chmod +x "$EASYRSA_DIR/easyrsa"
            )
            new_ver=$("$EASYRSA_DIR/easyrsa" --version 2>/dev/null | awk '/EasyRSA/{print $2; exit}' || echo "unknown")
            ok "EasyRSA updated: $cur_ver -> $new_ver"
            log "EasyRSA updated: $cur_ver -> $new_ver"
            ;;
        0) exit ;;
        18)
            pick_client "Client to export" || continue
            scp_client="$PICKED_CLIENT"
            [[ ! -f "$OVPN_DIR/${scp_client}.ovpn" ]] && err ".ovpn not found: $OVPN_DIR/${scp_client}.ovpn"
            read -rp "Destination (user@host[:path]): " scp_dest
            [[ -z "$scp_dest" ]] && continue
            if scp "$OVPN_DIR/${scp_client}.ovpn" "${scp_dest}"; then
                ok "Exported ${scp_client}.ovpn to ${scp_dest}"
            else
                warn "SCP failed."
            fi
            log "Exported ${scp_client}.ovpn to ${scp_dest}"
            ;;
        19)
            [[ ! -f "$CLIENTS_DB" || ! -s "$CLIENTS_DB" ]] && { echo; echo "No clients in DB."; pause; continue; }
            echo; printf "%-4s %s\n" "#" "NAME"
            mapfile -t DB_LINES < "$CLIENTS_DB"
            list_db_clients
            read -rp "Select client (0 to go back): " rn_num
            [[ "$rn_num" == "0" ]] && continue
            until [[ "$rn_num" =~ ^[0-9]+$ && "$rn_num" -ge 1 && "$rn_num" -le ${#DB_LINES[@]} ]]; do
                echo "Invalid."; read -rp "Select client (0 to go back): " rn_num
                [[ "$rn_num" == "0" ]] && continue 2
            done
            IFS='|' read -r rn_old rn_created rn_expiry <<< "${DB_LINES[$((rn_num-1))]}"
            read -rp "New name: " rn_new_raw
            rn_new=$(sanitize_name "$rn_new_raw")
            [[ -z "$rn_new" ]] && { warn "Invalid name."; continue; }
            sed -i "/^$(sed_escape "$rn_old")|/c\\$(sed_escape "$rn_new")|${rn_created}|${rn_expiry}" "$CLIENTS_DB" \
                || { warn "Failed to rename client in $CLIENTS_DB"; continue; }
            if [[ -f "$OVPN_DIR/${rn_old}.ovpn" ]]; then
                mv "$OVPN_DIR/${rn_old}.ovpn" "$OVPN_DIR/${rn_new}.ovpn"
            fi
            ok "Renamed '$rn_old' -> '$rn_new'"
            log "Client renamed: $rn_old -> $rn_new"
            ;;
        20)
            info "=== Bandwidth Usage ==="
            if [[ ! -f "$OVPN_SERVER_DIR/openvpn-status.log" ]]; then
                echo "No status log found."; pause; continue
            fi
            printf "%-20s %-12s %s\n" "CLIENT" "BYTES IN" "BYTES OUT"
            awk -F',' '/^CLIENT_LIST/{printf "  %-20s %-12s %s\n",$2,$6,$7}' \
                "$OVPN_SERVER_DIR/openvpn-status.log" 2>/dev/null || echo "No connected clients."
            ;;
        21)
            echo; if confirm "Rotate tls-crypt key? All clients will need new .ovpn files."; then
                run openvpn --genkey secret "$OVPN_SERVER_DIR/tc.key"
                reload_service
                warn "tls-crypt key rotated. Regenerate all client .ovpn files (option 8 or 1)."
                log "tls-crypt key rotated."
            fi
            ;;
        22)
            read s_port s_proto < <(awk '/^port /{p=$2} /^proto /{r=$2} END{print p,r}' "$SERVER_CONF")
            [[ -n "$s_port" && -n "$s_proto" ]] || { warn "Could not read port/protocol from config."; pause; continue; }
            echo; echo "Testing port ${s_port}/${s_proto}..."
            if nc -zv 127.0.0.1 "$s_port" 2>&1 | grep -qi "open\|succeeded\|connected"; then
                ok "Port $s_port is open."
            else
                warn "Port $s_port not responding on localhost."
            fi
            echo; echo "Testing VPN tunnel routing..."
            if ip addr show tun0 &>/dev/null; then
                tun_ip=$(ip -4 -o addr show tun0 | awk '{gsub(/\/.*$/,"",$4); print $4; exit}')
                if ping -c 2 -W 2 "$tun_ip" &>/dev/null; then
                    ok "Tunnel $tun_ip is reachable."
                else
                    warn "Tunnel ping failed."
                fi
            else
                warn "tun0 interface not found — VPN may not be running."
            fi
            ;;
        23)
            read _cp _cr < <(awk '/^port /{p=$2} /^proto /{r=$2} END{print p,r}' "$SERVER_CONF")
            [[ -n "$_cp" && -n "$_cr" ]] || err "Could not read port/protocol from $SERVER_CONF"
            echo; echo "Current port: $_cp  protocol: $_cr"
            read -rp "New port [1-65535]: " new_port
            until [[ "$new_port" =~ ^[0-9]+$ && "$new_port" -ge 1 && "$new_port" -le 65535 ]]; do
                echo "Invalid."; read -rp "New port: " new_port
            done
            if ss -tulnp 2>/dev/null | grep -qF ":${new_port} "; then
                warn "Port $new_port appears to be in use. Proceeding anyway."
            fi
            echo "   1) UDP  2) TCP"
            read -rp "Protocol [1]: " new_proto_sel
            [[ -z "$new_proto_sel" ]] && new_proto_sel=1
            if [[ "$new_proto_sel" == "2" ]]; then new_proto="tcp"; else new_proto="udp"; fi
            old_port="$_cp"; old_proto="$_cr"
            awk -v p="$new_port" -v r="$new_proto" '/^port /{$0="port "p} /^proto /{$0="proto "r} {print}' \
                "$SERVER_CONF" > "${SERVER_CONF}.tmp"
            if [[ -s "${SERVER_CONF}.tmp" ]]; then
                mv "${SERVER_CONF}.tmp" "$SERVER_CONF"
            else
                rm -f "${SERVER_CONF}.tmp"
                err "Failed to update server config."
            fi
            _ipt=$(command -v iptables)
            _ipt_tmp=$(mktemp)
            if awk -v np="$new_proto" -v nd="$new_port" -v ipt="$_ipt" \
                '/ExecStart=.*--dport/{$0="ExecStart="ipt" -I INPUT -p "np" --dport "nd" -j ACCEPT"} \
                 /ExecStop=.*--dport/{$0="ExecStop="ipt" -D INPUT -p "np" --dport "nd" -j ACCEPT"} \
                 {print}' /etc/systemd/system/openvpn-iptables.service > "$_ipt_tmp" 2>/dev/null; then
                mv "$_ipt_tmp" /etc/systemd/system/openvpn-iptables.service
            else
                rm -f "$_ipt_tmp"
            fi
            systemctl daemon-reload
            systemctl restart openvpn-iptables.service 2>/dev/null || true
            test_server_config
            systemctl restart "$SVC"
            ok "Port changed to $new_port/$new_proto"
            log "Port changed: $old_port/$old_proto -> $new_port/$new_proto"
            ;;
        24)
            info "=== Revoked Clients ==="
            _rev=$(get_revoked)
            if [[ -n "$_rev" ]]; then echo "$_rev"; else echo "No revoked clients."; fi
            ;;
    esac
    echo; pause
    done
fi
