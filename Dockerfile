# syntax=docker/dockerfile:1
FROM golang:1.21.3-alpine3.18 as builder

RUN <<EOT /bin/sh
apk --no-cache --update add git
apk --no-cache --update add build-base
EOT

RUN <<EOT /bin/sh
git clone https://github.com/WireGuard/wireguard-go.git /wgbuild
cd /wgbuild
make
EOT

# >.<
FROM golang:1.21.3-alpine3.18

COPY --from=builder /lib/ld-musl-x86_64.so.1 /lib/ld-musl-x86_64.so.1
COPY --from=builder /wgbuild/wireguard-go /bin/wireguard-go

WORKDIR /app
COPY go.mod go.sum /app
RUN apk --no-cache --update add libcap iptables tcpdump iproute2 && go mod download

COPY *.go /app
RUN CGO_ENABLED=0 GOOS=linux go build -o /wireguard-connectivity-test

RUN mkdir -p /etc/wireguard && \
    setcap cap_net_raw=+ep /wireguard-connectivity-test

USER 0:0

CMD ["/wireguard-connectivity-test"]