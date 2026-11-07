# teknoir-desktop: a browser remote desktop for the Teknoir platform.
#
# One container, one port (6080): websockify serves the noVNC web client and
# bridges its WebSocket to a VNC server that listens on a unix socket only.
#
#   virtual  Xvnc + XFCE + Chromium inside the container (a TeknoirBot desktop)
#   host     websockify only, to a socket a systemd unit makes on the host
#
# Multi-arch (linux/amd64, linux/arm64): only Debian packages and the noarch
# noVNC tarball are used, nothing arch-specific is downloaded.

ARG DEBIAN_IMAGE=docker.io/library/debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
FROM ${DEBIAN_IMAGE}

LABEL org.opencontainers.image.source="https://github.com/teknoir/teknoir-desktop" \
      org.opencontainers.image.title="teknoir-desktop" \
      org.opencontainers.image.licenses="Apache-2.0"

# Needed for the sha256sum pipeline below (and for the guarded rm -rf globs).
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Debian 13 ships the TigerVNC server as /usr/bin/Xtigervnc and no Xvnc; the
# symlink made further down gives it the upstream name the scripts use. The
# websockify console script comes in with python3-websockify, a dependency.
#
# /etc/chromium.d/dev-shm is removed at the end of this RUN: Debian's
# /usr/bin/chromium sources every file in that directory, and this one adds
# --disable-dev-shm-usage whenever /dev/shm has less than 3.8 GB free, so the
# flag would always be set with the 1Gi /dev/shm and Chromium would be told to
# keep any /dev/shm fallback in the disk-backed /tmp. The desktop-browser wrapper makes
# that decision itself (only under 512 MiB). The removal lives in this RUN, so
# it is re-applied on every rebuild with a new Chromium package.
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      tigervnc-standalone-server \
      tigervnc-tools \
      websockify \
      python3 \
      tini \
      ca-certificates \
      procps \
      dbus-x11 \
      xfce4-session \
      xfwm4 \
      xfce4-panel \
      xfdesktop4 \
      xfce4-settings \
      xfce4-terminal \
      thunar \
      xfconf \
      chromium \
      xauth \
      xdotool \
      scrot \
      x11-xserver-utils \
      x11-xkb-utils \
      xkb-data \
      fonts-dejavu-core \
      fonts-liberation2 \
      locales \
 && sed -i \
      -e 's/^# *en_US\.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' \
      -e 's/^# *sv_SE\.UTF-8 UTF-8/sv_SE.UTF-8 UTF-8/' \
      /etc/locale.gen \
 && locale-gen \
 && rm -f /etc/chromium.d/dev-shm \
 && rm -rf /var/lib/apt/lists/*

ENV LANG=en_US.UTF-8 \
    LANGUAGE=en_US:en

# noVNC 1.7.0 from upstream (Debian ships 1.6.0 as "novnc"). The tarball is
# checksum-pinned; it is noarch, so the same file works on every architecture.
ARG NOVNC_VERSION=1.7.0
ARG NOVNC_SHA256=b1003a11b6e6e8d8f7f5e5586daae7f8ca651d8aee0aa155ff9ac841c48f52c6

ADD https://github.com/novnc/noVNC/archive/refs/tags/v${NOVNC_VERSION}.tar.gz /tmp/novnc.tar.gz

RUN echo "${NOVNC_SHA256}  /tmp/novnc.tar.gz" | sha256sum -c - \
 && mkdir -p /opt/novnc \
 && tar -xzf /tmp/novnc.tar.gz -C /opt/novnc --strip-components=1 \
 && rm -rf /opt/novnc/tests /opt/novnc/snap /opt/novnc/.github /opt/novnc/utils/*.md /opt/novnc/vnc_lite.html \
 && rm -f /tmp/novnc.tar.gz

COPY rootfs/ /

# The landing page, the health probe file and the shared-desktop notice banner
# are added to the noVNC tree at build time, so the container filesystem can
# stay read-only at runtime. mandatory.json pins the WebSocket target (host and
# path), so a link cannot point the client at another server; vnc_lite.html is
# removed above because it ignores it.
#
# The notice: the page loads teknoir-notice.js, which fetches
# teknoir-notice.json from the same origin. That name is a symlink to
# /run/desktop/notice.json (written by the entrypoint, an emptyDir at
# runtime), which websockify follows; without a notice the entrypoint writes
# {"text": ""}, and only in host mode, where nothing writes /run/desktop, does
# the link stay dangling and the page get a 404. Only that one file is
# linked, never the directory: the rest of /run/desktop (Xauthority, vnc.sock)
# must not become reachable. The sed inserts the script tag, and the grep
# fails the build if </head> is not in vnc.html, where a silently unchanged
# file would mean a banner that never loads. The last grep checks that noVNC
# still marks a connection with the noVNC_connected class, which the script
# watches to fetch again on connect.
RUN chmod 0755 /usr/local/bin/desktop-* \
 && cp /opt/novnc-extra/index.html /opt/novnc/index.html \
 && cp /opt/novnc-extra/healthz /opt/novnc/healthz \
 && cp /opt/novnc-extra/mandatory.json /opt/novnc/mandatory.json \
 && cp /opt/novnc-extra/teknoir-notice.js /opt/novnc/teknoir-notice.js \
 && ln -s /run/desktop/notice.json /opt/novnc/teknoir-notice.json \
 && sed -i 's#</head>#<script src="teknoir-notice.js?v=2" defer></script></head>#' /opt/novnc/vnc.html \
 && grep -qF '<script src="teknoir-notice.js?v=2" defer></script>' /opt/novnc/vnc.html \
 && grep -qF 'classList.add("noVNC_connected")' /opt/novnc/app/ui.js \
 && groupadd -g 1000 desktop \
 && useradd -u 1000 -g 1000 -d /home/desktop -m -s /bin/bash desktop \
 && install -d -o 1000 -g 1000 -m 0750 /run/desktop \
 && ln -s /usr/bin/Xtigervnc /usr/local/bin/Xvnc

# HOME is set explicitly: a container gets no login shell to set it, and XFCE,
# dbus and Chromium all write their configuration under it.
ENV DESKTOP_MODE=virtual \
    HOME=/home/desktop

EXPOSE 6080

USER 1000:1000
WORKDIR /home/desktop

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/desktop-entrypoint"]

# Kubernetes probes run desktop-healthcheck (see deploy/examples).
HEALTHCHECK NONE
