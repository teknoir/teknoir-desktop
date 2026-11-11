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
#   council  the TeknoirBot council: a headless daemon with no desktop that
#            runs `tnctl council serve`, which drives OpenCode as its Coder;
#            amd64 only, because the OpenCode, kubectl and buildctl binaries
#            it carries are (`make image-council`)
#
# `council` is the last stage, so it is also what a plain `docker build`
# builds: it needs the TNCTL_REF below, and that is the Makefile's job.

ARG DEBIAN_IMAGE=docker.io/library/debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

# The Go toolchain of the two build stages (tnctl and buildctl), shared so that
# nothing new is pinned. It runs on the build host's architecture and
# cross-compiles (CGO off, so no emulation is needed); the tnctl build is
# always linux/amd64, because the council image is. 1.27.4 is the oldest
# toolchain tnctl releases are built with, so the build uses no older one.
# Declared here, before the first FROM, because a FROM can only see the ARGs
# declared outside every stage.
ARG GO_IMAGE=docker.io/library/golang:1.27.4-alpine@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf

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

# tnctl, from a pinned commit of teknoir/cli, for the council stage. The Go
# image is the one at the top of this file.
#
# The default TNCTL_REF is `cli` main as of the first release, which predates
# `tnctl council serve`: a build with the default therefore fails at the kit
# step below. That is intended, and it is why `make image-council` refuses to
# run without TNCTL_REF. Pass the commit of the cli branch that adds the
# council.
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

# buildctl, the client of the buildkitd that runs on the bot's own computer, at
# the same version. It is unpacked in a stage of its own, so the release
# tarball stays in that stage and the council image gets only the client.
FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS buildctl

ARG BUILDKIT_VERSION=0.25.1
ARG BUILDKIT_SHA256=85aa27c480fc9159705d21a3e66abe305f8dc708b8aeecd1e87bbc5c3de98642

ADD https://github.com/moby/buildkit/releases/download/v${BUILDKIT_VERSION}/buildkit-v${BUILDKIT_VERSION}.linux-amd64.tar.gz /tmp/buildkit.tgz

# DL4006 asks for pipefail before the pipe. The pipe's only producer is echo,
# and if it failed, sha256sum -c would find no line to check and fail itself,
# so the RUN fails either way.
# hadolint ignore=DL4006
RUN echo "${BUILDKIT_SHA256}  /tmp/buildkit.tgz" | sha256sum -c - \
 && mkdir -p /out \
 && tar -xzf /tmp/buildkit.tgz -C /out bin/buildctl

# The council image: the TeknoirBot council, headless. It is built on the slim
# Debian base, not on the desktop: a bot's council is a pod of its own, and the
# bot's desktop stays the plain desktop image above. Its entrypoint runs
# `tnctl council serve`, which drives OpenCode as the bot's Coder; OpenCode is
# pinned by version and checksum, and configured by /etc/teknoirbot/
# opencode.json, root-owned at the end of this stage.
FROM ${DEBIAN_IMAGE} AS council

# The same shell as the desktop stage: the checksum pipelines below need
# pipefail, and hadolint does not carry a parent stage's SHELL into this one.
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# The Coder's tools: git and ripgrep for OpenCode and the work volume, curl and
# jq for the bot API, openssh-client for git over ssh, less and procps for the
# terminal tools, mosquitto-clients and python3-paho-mqtt for the teamspace
# MQTT, python3-venv/-pip for the skills' Python, and tini to reap what the
# Coder starts.
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      tini \
      git \
      curl \
      jq \
      ripgrep \
      ca-certificates \
      python3 \
      python3-venv \
      python3-pip \
      python3-paho-mqtt \
      mosquitto-clients \
      openssh-client \
      less \
      procps \
 && rm -rf /var/lib/apt/lists/*

# The same uid and gid as the desktop container, so one owner reads the same to
# both. No home is made here: the bot's home is /work/home, under the volume
# the pod mounts at /work, and /work itself is made so that a volume, or
# nothing, can be mounted over it.
RUN groupadd -g 1000 teknoir \
 && useradd -u 1000 -g 1000 -d /work/home -M -s /bin/bash teknoir \
 && install -d -o 1000 -g 1000 -m 0755 /work

# kubectl, to read this bot's own cluster, and to change it, as the Coder's
# shell may.
ARG KUBECTL_VERSION=1.34.13
ARG KUBECTL_SHA256=b4bb494e9466a7a94bb851414548bc0d3e2f8da90757e6eccc3371e648648591

ADD --chmod=0755 https://dl.k8s.io/release/v${KUBECTL_VERSION}/bin/linux/amd64/kubectl /usr/local/bin/kubectl

RUN echo "${KUBECTL_SHA256}  /usr/local/bin/kubectl" | sha256sum -c -

# buildctl, at the same version as the buildkitd on the bot's own computer.
# The tarball was checked and unpacked in the buildctl stage above; only the
# client is taken from it.
COPY --from=buildctl --chmod=0755 /out/bin/buildctl /usr/local/bin/buildctl

COPY --from=tnctl --chmod=0755 /out/tnctl /usr/local/bin/tnctl

# OpenCode, the Coder, pinned by version and checksum. The baseline build is
# the one that runs on the bots' VMs, which have no AVX2. The tarball holds one
# file, which is unpacked under its version so that the path names it too, and
# --version proves the binary actually runs before the image is built.
ARG OPENCODE_VERSION=2.2.7
ARG OPENCODE_SHA256=89a6cee227b54bc011179c528a5e63176032462b1a5e21723b616801cddc2ca7

ADD https://github.com/anomalyco/opencode/releases/download/v${OPENCODE_VERSION}/opencode-linux-x64-baseline.tar.gz /tmp/opencode.tgz

RUN echo "${OPENCODE_SHA256}  /tmp/opencode.tgz" | sha256sum -c - \
 && mkdir -p /opt/opencode/${OPENCODE_VERSION} \
 && tar -xzf /tmp/opencode.tgz -C /opt/opencode/${OPENCODE_VERSION} opencode \
 && chmod 0755 /opt/opencode/${OPENCODE_VERSION}/opencode \
 && rm -f /tmp/opencode.tgz \
 && ln -s /opt/opencode/${OPENCODE_VERSION}/opencode /usr/local/bin/opencode \
 && got="$(HOME=/tmp/oc-home opencode --version 2>&1)" \
 && if ! printf '%s\n' "$got" | grep -qxF "opencode v${OPENCODE_VERSION}"; then \
      echo "opencode: printed '$got', want 'opencode v${OPENCODE_VERSION}'" >&2; \
      exit 1; \
    fi \
 && rm -rf /tmp/oc-home

# The Teknoir kit: the skills, from tnctl's embedded copy, into the managed
# directory the container user cannot write. The Coder links each work
# directory's .agents/skills to /etc/teknoirbot/kit/skills. `--check` fails the
# build if what was installed does not match what tnctl carries. Both name
# OpenCode, the only agent in this image, so the kit holds only the skills
# (no guard hook).
#
# A throwaway HOME keeps the build from writing /root/.tnctl.yaml into the
# image: a first tnctl run creates its default configuration file.
RUN HOME=/tmp/kit-home tnctl agent install --agent opencode --managed /etc/teknoirbot/kit \
 && HOME=/tmp/kit-home tnctl agent list --agent opencode --managed /etc/teknoirbot/kit --check \
 && test -d /etc/teknoirbot/kit/skills \
 && rm -rf /tmp/kit-home

# The council's own files: OpenCode's configuration. Root-owned, so uid 1000
# can neither change the provider it points at nor the permissions; 0644, so
# every process in the container can read it.
COPY rootfs-council/ /

RUN chown -R root:root /etc/teknoirbot \
 && chmod -R go-w /etc/teknoirbot \
 && chmod 0644 /etc/teknoirbot/opencode.json

# OpenCode reads this one file, not whatever a work directory might carry; HOME
# and the XDG directories live on the work volume, so a new pod keeps the
# Coder's sessions, state and cache.
ENV OPENCODE_CONFIG=/etc/teknoirbot/opencode.json \
    HOME=/work/home \
    XDG_DATA_HOME=/work/home/.local/share \
    XDG_STATE_HOME=/work/home/.local/state \
    XDG_CACHE_HOME=/work/home/.cache \
    XDG_CONFIG_HOME=/work/home/.config

WORKDIR /work

USER 1000:1000

# tini reaps whatever the Coder starts; the council is the container's process.
ENTRYPOINT ["/usr/bin/tini", "--", "tnctl", "council", "serve", "--work-dir", "/work"]
