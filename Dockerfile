FROM alpine:latest

RUN apk add --no-cache \
    iptables \
    dnsmasq \
    bind-tools \
    curl \
    bash \
    iproute2 \
    ipset

COPY network-filter.sh /network-filter.sh

EXPOSE 53/udp 53/tcp

CMD ["/network-filter.sh"]
