# syntax=docker/dockerfile:1
FROM golang:1.21.3-alpine3.18 as wireguardgo

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
FROM golang:1.21.3-alpine3.18 as tester

COPY --from=wireguardgo /lib/ld-musl-x86_64.so.1 /lib/ld-musl-x86_64.so.1
COPY --from=wireguardgo /wgbuild/wireguard-go /bin/wireguard-go

WORKDIR /app
COPY go.mod go.sum /app
RUN apk --no-cache --update add libcap iptables tcpdump iproute2 && go mod download
COPY *.go /app
COPY ./dev/profile.json /app

RUN CGO_ENABLED=0 GOOS=linux go build -o /wireguard-connectivity-test && \
    setcap cap_net_raw=+ep /wireguard-connectivity-test && \
    rm -rf ~/.cache && \
    rm -rf /go

USER 0:0

CMD ["/wireguard-connectivity-test"]