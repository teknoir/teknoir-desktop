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
#
# Two images come from this file, so a build names its target:
#
#   desktop  the remote desktop above; multi-arch (`make image`)
#   agent    the desktop plus the TeknoirBot agent, the AI agent that runs in
#            an xfce4-terminal on that desktop; amd64 only, because three of
#            the released binaries it carries are (`make image-agent`)
#
# `agent` is the last stage, so it is also what a plain `docker build` builds:
# it needs the TNCTL_REF below, and that is the Makefile's job.

ARG DEBIAN_IMAGE=docker.io/library/debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
FROM ${DEBIAN_IMAGE} AS desktop

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

# tnctl, from a pinned commit of teknoir/cli, for the agent stage only. The Go
# toolchain runs on the build host's architecture and cross-compiles (CGO off,
# so no emulation is needed); the build is always linux/amd64, because the
# agent image is.
#
# The default TNCTL_REF is `cli` main as of the agent image's first release,
# which has no `tnctl agent install` yet: a build with the default therefore
# fails at the agent kit step below. That is intended, and it is why `make
# image-agent` refuses to run without TNCTL_REF. Pass the commit of the cli
# branch that adds the agent kit.
ARG GO_IMAGE=docker.io/library/golang:1.26-alpine@sha256:3082400e369fa24d5fc60bca20edab3f6d604e0c5a690ec66b295eff4dd87ade

FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS tnctl

ARG TNCTL_REPO=https://github.com/teknoir/cli.git
ARG TNCTL_REF=59dbc3b29244aabdce1ea563b4b037a27b198aa0
ARG TNCTL_VERSION=dev

WORKDIR /src

# Exactly TNCTL_REF, not whatever its branch points at now: a tag or branch
# name is fetched as it is, a 40-hex commit is checked against what arrived.
# No pipe in this RUN: the stage's shell is busybox ash, without pipefail.
RUN apk add --no-cache git \
 && git init -q \
 && git fetch -q --depth 1 "$TNCTL_REPO" "$TNCTL_REF" \
 && git checkout -q --detach FETCH_HEAD \
 && got="$(git rev-parse HEAD)" \
 && if [ "${#TNCTL_REF}" -eq 40 ]; then \
      case "$TNCTL_REF" in \
        *[!0-9a-f]*) ;; \
        *) [ "$got" = "$TNCTL_REF" ] || { \
             echo "tnctl: fetched $got, not TNCTL_REF $TNCTL_REF" >&2; \
             exit 1; \
           } ;; \
      esac; \
    fi \
 && mkdir -p /out

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
      -ldflags "-s -w -X main.version=${TNCTL_VERSION}" \
      -o /out/tnctl .

# The agent image: the desktop above, plus the platform's AI agent for this
# bot. An xfce4-terminal runs /usr/local/bin/teknoirbot-agent from the XFCE
# autostart; that launcher starts the unmodified terminal UI against the
# platform's model proxy with the bot's own key, or against the user's own
# Anthropic account for one terminal. tnctl runs in bot mode (its key is
# mounted at /run/teknoirbot/key), and the kit of Teknoir skills and the guard
# hook comes from tnctl into /etc/claude-code, which uid 1000 can read but not
# change.
FROM desktop AS agent

# Root for the install steps below, then back to 1000:1000. DL3066 asks for a
# numeric id; Debian's root always resolves, and the name reads as the stage's
# one privileged section.
# hadolint ignore=DL3066
USER root

# The same shell as the desktop stage: the checksum pipelines below need
# pipefail, and hadolint does not carry a parent stage's SHELL into this one.
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# The agent's tools: git and curl for tnctl and the skills, jq for the bot
# API's JSON, mosquitto-clients and paho-mqtt for the teamspace MQTT, and
# python3-venv/-pip for the skills' Python (python3, ca-certificates are in
# the desktop stage already).
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      git \
      curl \
      jq \
      mosquitto-clients \
      python3-venv \
      python3-pip \
      python3-paho-mqtt \
 && rm -rf /var/lib/apt/lists/*

# The terminal UI, pinned by version and checksum and never modified: the
# agent's permissions, skills and hook are configuration around it
# (/etc/claude-code/managed-settings.json), not a patched binary.
ARG CLAUDE_VERSION=2.1.319
ARG CLAUDE_SHA256=dabafec82ca1319fa43d8be36a10fc61b1d11821cb98ad5df04ad95e199b8eed

ADD https://downloads.claude.ai/claude-code-releases/${CLAUDE_VERSION}/linux-x64/claude /opt/claude/${CLAUDE_VERSION}/claude

RUN echo "${CLAUDE_SHA256}  /opt/claude/${CLAUDE_VERSION}/claude" | sha256sum -c - \
 && chmod 0755 /opt/claude/${CLAUDE_VERSION}/claude \
 && ln -s /opt/claude/${CLAUDE_VERSION}/claude /usr/local/bin/claude

# kubectl, to read this bot's own cluster (and to change it, which the managed
# settings put behind a confirmation).
ARG KUBECTL_VERSION=1.34.13
ARG KUBECTL_SHA256=b4bb494e9466a7a94bb851414548bc0d3e2f8da90757e6eccc3371e648648591

ADD https://dl.k8s.io/release/v${KUBECTL_VERSION}/bin/linux/amd64/kubectl /usr/local/bin/kubectl

RUN echo "${KUBECTL_SHA256}  /usr/local/bin/kubectl" | sha256sum -c - \
 && chmod 0755 /usr/local/bin/kubectl

# buildctl, the client of the buildkitd that runs on the bot's own computer,
# at the same version. Only the client is taken from the release tarball.
ARG BUILDKIT_VERSION=0.25.1
ARG BUILDKIT_SHA256=85aa27c480fc9159705d21a3e66abe305f8dc708b8aeecd1e87bbc5c3de98642

ADD https://github.com/moby/buildkit/releases/download/v${BUILDKIT_VERSION}/buildkit-v${BUILDKIT_VERSION}.linux-amd64.tar.gz /tmp/buildkit.tgz

RUN echo "${BUILDKIT_SHA256}  /tmp/buildkit.tgz" | sha256sum -c - \
 && tar -xzf /tmp/buildkit.tgz -C /tmp bin/buildctl \
 && install -m 0755 /tmp/bin/buildctl /usr/local/bin/buildctl \
 && rm -rf /tmp/buildkit.tgz /tmp/bin

COPY --from=tnctl /out/tnctl /usr/local/bin/tnctl

# The Teknoir agent kit: the skills and the guard hook, from tnctl's embedded
# copy, into the managed directory the desktop user cannot write. `--check`
# fails the build if what was installed does not match what tnctl carries.
RUN chmod 0755 /usr/local/bin/tnctl \
 && tnctl agent install --agent claude --managed /etc/claude-code/.claude \
 && tnctl agent list --managed /etc/claude-code/.claude --check

# The agent's own files: the managed settings and MCP registration (root-owned
# so uid 1000 can neither change them nor point the hook elsewhere), the
# launcher and the two menu entries. A tree of its own, so the desktop image
# never gets them.
COPY rootfs-agent/ /

RUN chown -R root:root /etc/claude-code \
 && chmod -R go-w /etc/claude-code \
 && chmod 0755 /usr/local/bin/teknoirbot-agent \
 && chmod 0644 /etc/xdg/autostart/teknoirbot-agent.desktop \
      /usr/share/applications/teknoirbot-agent.desktop \
      /usr/share/applications/teknoirbot-agent-own.desktop

# The binary is pinned above; it must not replace itself at runtime.
ENV DISABLE_AUTOUPDATER=1

USER 1000:1000
