#!/bin/bash
set -e

# Global arrays for domain/port mapping
declare -A DOMAIN_PORTSET  # domain -> port set name mapping
declare -A PORTSET_PORTS   # port set name -> actual ports mapping
declare -A PORTSET_DOMAINS # port set name -> domains mapping
declare -a ALL_PORTSETS    # unique port set names

# --- Configuration ---
setup_env() {
    DNS_SERVERS="${DNS_SERVERS:-8.8.8.8,8.8.4.4}"
    RUN_SELFTEST="${RUN_SELFTEST:-false}"
    IPSET_TIMEOUT="${IPSET_TIMEOUT:-600}"  # 10 minutes default

    echo "--- Configuration ---"
    echo "DNS Servers: $DNS_SERVERS"
    echo "Allowed Domains: $ALLOWED_DOMAINS"
    echo "IPSet Timeout: $IPSET_TIMEOUT seconds"
    echo "Run Selftest on start: $RUN_SELFTEST"
}

# --- Domain Parsing ---
parse_domains() {
    if [[ -z "$ALLOWED_DOMAINS" ]]; then
        return
    fi

    IFS=',' read -ra DOMAINS <<< "$ALLOWED_DOMAINS"
    for domain_spec in "${DOMAINS[@]}"; do
        domain_spec=$(echo "$domain_spec" | xargs)
        local domain=$(echo "$domain_spec" | cut -d':' -f1)
        local ports_part=$(echo "$domain_spec" | cut -d':' -f2-)

        local ports=()
        if [[ "$domain_spec" == *":"* ]]; then
            IFS=':' read -ra PORT_LIST <<< "$ports_part"
            for port in "${PORT_LIST[@]}"; do
                if [[ "$port" =~ ^[0-9]+$ ]] && [[ "$port" -ge 1 ]] && [[ "$port" -le 65535 ]]; then
                    ports+=("$port")
                fi
            done
        else
            ports=(80 443)  # Default ports
        fi

        # Sort ports for consistent naming
        IFS=$'\n' sorted_ports=($(sort -n <<<"${ports[*]}")); unset IFS

        # Create port set name (e.g., "80_443" or "22_80")
        local portset_name=$(IFS='_'; echo "${sorted_ports[*]}")

        DOMAIN_PORTSET[$domain]="$portset_name"
        PORTSET_PORTS[$portset_name]="${sorted_ports[*]}"

        # Track domains using this port set
        if [[ -z "${PORTSET_DOMAINS[$portset_name]}" ]]; then
            PORTSET_DOMAINS[$portset_name]="$domain"
            ALL_PORTSETS+=("$portset_name")
        else
            PORTSET_DOMAINS[$portset_name]="${PORTSET_DOMAINS[$portset_name]} $domain"
        fi
    done
}

# --- ipset Management ---
setup_ipsets() {
    # Clean up any existing ipsets
    for portset in "${ALL_PORTSETS[@]}"; do
        ipset destroy "allowed_${portset}" 2>/dev/null || true
    done

    # Create ipset for each port set
    for portset in "${ALL_PORTSETS[@]}"; do
        ipset create "allowed_${portset}" hash:ip timeout "${IPSET_TIMEOUT}"
        echo "Created ipset: allowed_${portset} for ports ${PORTSET_PORTS[$portset]}"
    done
}

# --- iptables ---
setup_iptables() {
    # Clear existing rules
    iptables -t filter -F OUTPUT
    iptables -t nat -F
    iptables -P OUTPUT DROP

    # Allow local traffic
    iptables -A OUTPUT -o lo -j ACCEPT
    iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    iptables -A OUTPUT -d 127.0.0.0/8 -j ACCEPT
    iptables -A OUTPUT -d 10.0.0.0/8 -j ACCEPT
    iptables -A OUTPUT -d 172.16.0.0/12 -j ACCEPT
    iptables -A OUTPUT -d 192.168.0.0/16 -j ACCEPT

    # Allow DNS
    iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT

    # Allow configured DNS servers
    IFS=',' read -ra DNS_LIST <<< "$DNS_SERVERS"
    for dns_server in "${DNS_LIST[@]}"; do
        dns_server=$(echo "$dns_server" | xargs)
        iptables -A OUTPUT -d "$dns_server" -p udp --dport 53 -j ACCEPT
        iptables -A OUTPUT -d "$dns_server" -p tcp --dport 53 -j ACCEPT
    done

    # Add ipset-based rules for each port set
    for portset in "${ALL_PORTSETS[@]}"; do
        IFS=' ' read -ra ports <<< "${PORTSET_PORTS[$portset]}"
        for port in "${ports[@]}"; do
            iptables -A OUTPUT -p tcp --dport "$port" -m set --match-set "allowed_${portset}" dst -j ACCEPT
            echo "Added iptables rule for port $port using ipset allowed_${portset}"
        done
    done
}

# --- DNS ---
setup_dnsmasq() {
    PRIMARY_DNS=$(echo "$DNS_SERVERS" | cut -d',' -f1 | xargs)

    # Start building dnsmasq config
    cat > /etc/dnsmasq.conf << EOF
listen-address=0.0.0.0
port=53
bind-interfaces
no-hosts
no-resolv
no-poll
log-queries
filter-AAAA
EOF

    # Add server and ipset entries for all domains
    for domain in "${!DOMAIN_PORTSET[@]}"; do
        echo "server=/${domain}/${PRIMARY_DNS}" >> /etc/dnsmasq.conf
        echo "ipset=/${domain}/allowed_${DOMAIN_PORTSET[$domain]}" >> /etc/dnsmasq.conf
    done

    echo "--- Generated dnsmasq configuration ---"
    cat /etc/dnsmasq.conf
}

override_dns() {
    pkill -f "127.0.0.11" 2>/dev/null || true
    echo "nameserver 127.0.0.1" > /etc/resolv.conf
    echo "options timeout:1 attempts:1" >> /etc/resolv.conf
}

# --- Self Test ---
run_tests() {
    echo "--- Running Self Test ---"
    echo "--- Checking ipsets ---"
    for portset in "${ALL_PORTSETS[@]}"; do
        echo "IPSet allowed_${portset} (ports: ${PORTSET_PORTS[$portset]}):"
        ipset list "allowed_${portset}" | grep -E "^(Name:|Type:|Timeout:|Number of entries:)"
    done

    echo "--- Testing DNS functionality ---"
    ss -ln | grep :53 || echo "No process listening on port 53"

    PRIMARY_DNS=$(echo "$DNS_SERVERS" | cut -d',' -f1 | xargs)

    # Test allowed domain
    if [[ -n "${!DOMAIN_PORTSET[@]}" ]]; then
        test_domain=$(echo "${!DOMAIN_PORTSET[@]}" | cut -d' ' -f1)
        portset="${DOMAIN_PORTSET[$test_domain]}"
        echo "Testing allowed domain ($test_domain) with dig:"
        timeout 10 dig @127.0.0.1 "$test_domain" +short || echo "Failed to resolve $test_domain"

        # Check if IPs were added to ipsets
        sleep 2  # Give dnsmasq time to populate ipsets
        echo "Checking ipset allowed_${portset} for $test_domain entries:"
        ipset list "allowed_${portset}" | grep -E "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" || echo "No entries found"
    fi

    echo "Testing blocked domain (example.org) with dig:"
    timeout 10 dig @127.0.0.1 example.org +short || echo "Successfully blocked example.org"

    echo "--- Self Test Complete ---"
}

# --- Monitoring ---
monitor_ipsets() {
    while true; do
        sleep 60
        echo "--- IPSet Status ---"
        for portset in "${ALL_PORTSETS[@]}"; do
            count=$(ipset list "allowed_${portset}" | grep -c "^[0-9]" || echo "0")
            echo "allowed_${portset} (ports ${PORTSET_PORTS[$portset]}): $count entries"
        done
    done
}

# --- Main ---
start() {
    setup_env
    parse_domains

    echo "Debug: ALL_PORTSETS array has ${#ALL_PORTSETS[@]} elements"
    echo "Debug: ALL_PORTSETS contents: ${ALL_PORTSETS[@]}"

    if [[ ${#ALL_PORTSETS[@]} -eq 0 ]]; then
        echo "No allowed domains configured. Exiting."
        exit 1
    fi

    setup_ipsets
    setup_iptables
    setup_dnsmasq
    override_dns

    # Test dnsmasq config
    dnsmasq --test

    # Start dnsmasq
    dnsmasq --no-daemon --log-facility=- &
    DNSMASQ_PID=$!
    sleep 3

    if [[ "$RUN_SELFTEST" == "true" ]]; then
        run_tests
    fi

    echo "Network filter setup complete. Monitoring..."

    # Start ipset monitor in background
    monitor_ipsets &
    MONITOR_PID=$!

    # Main loop - just monitor dnsmasq health
    while true; do
        sleep 60

        # Check dnsmasq health
        if ! kill -0 $DNSMASQ_PID 2>/dev/null; then
            echo "dnsmasq died, restarting..."
            dnsmasq --no-daemon --log-facility=- &
            DNSMASQ_PID=$!
        fi

        # Check resolv.conf
        if [[ "$(cat /etc/resolv.conf | grep -c '127.0.0.1')" -eq 0 ]]; then
            echo "resolv.conf was modified, fixing..."
            override_dns
        fi
    done
}

# --- Cleanup ---
cleanup() {
    echo "Cleaning up..."

    # Kill processes
    [[ -n "$DNSMASQ_PID" ]] && kill $DNSMASQ_PID 2>/dev/null || true
    [[ -n "$MONITOR_PID" ]] && kill $MONITOR_PID 2>/dev/null || true

    # Clean up ipsets
    for portset in "${ALL_PORTSETS[@]}"; do
        ipset destroy "allowed_${portset}" 2>/dev/null || true
    done

    # Reset iptables
    iptables -P OUTPUT ACCEPT
    iptables -F OUTPUT

    exit 0
}

trap cleanup EXIT INT TERM

# --- Command Dispatcher ---
CMD="${1:-start}"
case "$CMD" in
    start)
        start
        ;;
    selftest)
        RUN_SELFTEST=true
        start
        ;;
    *)
        echo "Unknown command: $CMD"
        echo "Usage: $0 [start|selftest]"
        exit 1
        ;;
esac
