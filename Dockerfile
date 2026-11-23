FROM golang:1.26-trixie AS penguinboxd

WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags '-s -w' -o /out/penguinboxd ./cmd/penguinboxd

FROM debian:trixie-slim

ENV DEBIAN_FRONTEND=noninteractive

# The trixie release passt (0.0~git20250503) crashes with SIGSEGV when QEMU's
# tap send is short: tcp_buf_send_flag() queues a flag-only frame without
# recording its connection, so tcp_revert_seq() dereferences NULL. The fix
# landed upstream after that snapshot. Install the pinned trixie-backports
# build instead of the release package.
ARG PASST_DEB_VERSION=0.0~git20260728.f8df3f1-1~bpo13+1
ARG PASST_DEB_SHA256=c8ac47eb51979289f8bbb1761d9954cf1ee8dd1ac42ea5d2ce5136330099f43a

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
        procps \
        python3 \
        qemu-system-x86 \
        qemu-utils \
        tini \
        websockify \
    && curl -fsSL -o /tmp/passt.deb \
        "https://deb.debian.org/debian/pool/main/p/passt/passt_${PASST_DEB_VERSION}_amd64.deb" \
    && echo "${PASST_DEB_SHA256}  /tmp/passt.deb" | sha256sum -c - \
    && apt-get install -y --no-install-recommends /tmp/passt.deb \
    && rm -f /tmp/passt.deb \
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

EXPOSE 2222 8006 1338

VOLUME ["/storage"]

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/penguinbox-entrypoint"]
