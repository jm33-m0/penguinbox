FROM golang:1.26-trixie AS penguinboxd

WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags '-s -w' -o /out/penguinboxd ./cmd/penguinboxd

FROM debian:trixie-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        cloud-image-utils \
        curl \
        genisoimage \
        iproute2 \
        jq \
        novnc \
        openssh-client \
        passt \
        procps \
        python3 \
        qemu-system-x86 \
        qemu-utils \
        tini \
        websockify \
    && rm -rf /var/lib/apt/lists/*

# Serve the console at the web root and replace every directory index so the
# websockify file server cannot list the noVNC tree.
RUN ln -s vnc.html /usr/share/novnc/index.html \
    && for dir in $(find /usr/share/novnc -mindepth 1 -type d); do \
        printf '%s\n' '<!DOCTYPE html><meta http-equiv="refresh" content="0; url=/">' >"$dir/index.html"; \
    done

COPY --from=penguinboxd /out/penguinboxd /usr/local/bin/penguinboxd
COPY entrypoint.sh /usr/local/bin/penguinbox-entrypoint
COPY cloud-init /etc/penguinbox/cloud-init
COPY guest /etc/penguinbox/guest

RUN chmod 0755 /usr/local/bin/penguinbox-entrypoint /usr/local/bin/penguinboxd

EXPOSE 2222 8006

VOLUME ["/storage"]

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/penguinbox-entrypoint"]
