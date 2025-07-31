#!/bin/bash
set -e
set -x

# --- Configuration ---
setup_env() {
    DNS_SERVERS="${DNS_SERVERS:-8.8.8.8,8.8.4.4}"
    REFRESH_INTERVAL="${REFRESH_INTERVAL:-300}"
    RUN_SELFTEST="${RUN_SELFTEST:-false}"

    echo "--- Configuration ---"
    echo "DNS Servers: $DNS_SERVERS"
    echo "Allowed Domains: $ALLOWED_DOMAINS"
    echo "Refresh Interval: $REFRESH_INTERVAL seconds"
    echo "Run Selftest on start: $RUN_SELFTEST"
}

# --- iptables ---
setup_iptables() {
    iptables -t filter -F OUTPUT
    iptables -t nat -F
    iptables -P OUTPUT DROP

    iptables -A OUTPUT -o lo -j ACCEPT
    iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    iptables -A OUTPUT -d 127.0.0.0/8 -j ACCEPT
    iptables -A OUTPUT -d 10.0.0.0/8 -j ACCEPT
    iptables -A OUTPUT -d 172.16.0.0/12 -j ACCEPT
    iptables -A OUTPUT -d 192.168.0.0/16 -j ACCEPT
    iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT

    IFS=',' read -ra DNS_LIST <<< "$DNS_SERVERS"
    for dns_server in "${DNS_LIST[@]}"; do
        dns_server=$(echo "$dns_server" | xargs)
        iptables -A OUTPUT -d "$dns_server" -p udp --dport 53 -j ACCEPT
        iptables -A OUTPUT -d "$dns_server" -p tcp --dport 53 -j ACCEPT
    done
}

add_domain_rule() {
    local domain_spec=$1
    local domain=$(echo "$domain_spec" | cut -d':' -f1)
    local ports_part=$(echo "$domain_spec" | cut -d':' -f2-)

    local ports_to_allow=()
    if [[ "$domain_spec" == *":"* ]]; then
        IFS=':' read -ra PORT_LIST <<< "$ports_part"
        for port in "${PORT_LIST[@]}"; do
            if [[ "$port" =~ ^[0-9]+$ ]] && [[ "$port" -ge 1 ]] && [[ "$port" -le 65535 ]]; then
                ports_to_allow+=("$port")
            fi
        done
    else
        ports_to_allow=(80 443)
    fi

    local ipv4_addresses=$(nslookup "$domain" 127.0.0.1 2>/dev/null | awk '/^Address:/ && !/127.0.0.1/ { print $2 }' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$')

    for ip in $ipv4_addresses; do
        if [[ -n "$ip" ]]; then
            for port in "${ports_to_allow[@]}"; do
                iptables -A OUTPUT -d "$ip" -p tcp --dport "$port" -j ACCEPT
            done
        fi
    done
}

apply_domain_rules() {
    if [[ -n "$ALLOWED_DOMAINS" ]]; then
        IFS=',' read -ra DOMAINS <<< "$ALLOWED_DOMAINS"
        for domain in "${DOMAINS[@]}"; do
            domain=$(echo "$domain" | xargs)
            add_domain_rule "$domain"
        done
    fi
}

# --- DNS ---
setup_dnsmasq() {
    PRIMARY_DNS=$(echo "$DNS_SERVERS" | cut -d',' -f1 | xargs)

    cat > /etc/dnsmasq.conf << EOF
listen-address=0.0.0.0
port=53
bind-interfaces
no-hosts
no-resolv
no-poll
log-queries
filter-AAAA
min-cache-ttl=$((REFRESH_INTERVAL * 2))
max-cache-ttl=$((REFRESH_INTERVAL * 2))
$(if [[ -n "$ALLOWED_DOMAINS" ]]; then
    IFS=',' read -ra DOMAINS <<< "$ALLOWED_DOMAINS"
    for domain in "${DOMAINS[@]}"; do
        domain_name=$(echo "$domain" | cut -d':' -f1 | xargs)
        echo "server=/$domain_name/$PRIMARY_DNS"
    done
fi)
EOF
}

override_dns() {
    pkill -f "127.0.0.11" 2>/dev/null || true
    echo "nameserver 127.0.0.1" > /etc/resolv.conf
    echo "options timeout:1 attempts:1" >> /etc/resolv.conf
}

# --- Self Test ---
run_tests() {
    echo "--- Running Self Test ---"
    echo "--- Testing DNS functionality ---"
    ss -ln | grep :53 || echo "No process listening on port 53"

    PRIMARY_DNS=$(echo "$DNS_SERVERS" | cut -d',' -f1 | xargs)
    echo "Testing allowed domain (github.com) with dig:"
    timeout 10 dig @127.0.0.1 github.com +short || echo "Failed to resolve github.com"

    echo "Testing blocked domain (monadical.com) with dig:"
    timeout 10 dig @127.0.0.1 monadical.com +short || echo "Successfully blocked monadical.com"

    echo "Testing direct upstream DNS ($PRIMARY_DNS):"
    timeout 10 dig @"$PRIMARY_DNS" github.com +short || echo "Cannot reach upstream DNS"

    echo "--- Self Test Complete ---"
}

selftest() {
    setup_env
    setup_iptables
    setup_dnsmasq
    override_dns

    dnsmasq --test

    dnsmasq --no-daemon --log-facility=- &
    DNSMASQ_PID=$!
    sleep 3
    apply_domain_rules


    run_tests

    kill $DNSMASQ_PID
}

# --- Main ---
start() {
    setup_env
    setup_iptables
    setup_dnsmasq
    override_dns

    dnsmasq --no-daemon --log-facility=- &
    DNSMASQ_PID=$!
    sleep 3

    apply_domain_rules

    if [[ "$RUN_SELFTEST" == "true" ]]; then
        run_tests
    fi

    echo "Network filter setup complete. Monitoring..."

    while true; do
        sleep "$REFRESH_INTERVAL"
        if ! kill -0 $DNSMASQ_PID 2>/dev/null; then
            dnsmasq --no-daemon &
            DNSMASQ_PID=$!
        fi
        if [[ "$(cat /etc/resolv.conf | grep -c '127.0.0.1')" -eq 0 ]]; then
            override_dns
        fi

        # Clear dnsmasq cache before refreshing rules
        kill -HUP $DNSMASQ_PID 2>/dev/null || true

        setup_iptables
        apply_domain_rules
    done
}

# --- Command Dispatcher ---
CMD="${1:-start}"
case "$CMD" in
    start)
        start
        ;;
    selftest)
        selftest
        ;;
    *)
        echo "Unknown command: $CMD"
        exit 1
        ;;
esac
