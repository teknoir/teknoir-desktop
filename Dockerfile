# teknoir-desktop: a browser remote desktop for the Teknoir platform.
#
# One container, one port (6080): websockify serves the noVNC web client and
# bridges its WebSocket to a VNC server that listens on a unix socket only.
#
#   virtual  Xvnc + XFCE + Chromium inside the container (a TeknoirBot desktop)
#   host     websockify only, to a socket a systemd unit makes on the host
#
# Multi-arch (linux/amd64, linux/arm64): only Debian packages and noarch
# downloads are used (the noVNC tarball and the fonts, both checksum-pinned),
# nothing arch-specific is downloaded.
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
# librsvg2-common (400 KB; librsvg2-2 is already pulled in) is the gdk-pixbuf
# SVG loader, and only it makes GTK able to draw an SVG: without it the panel
# logs "Couldn't recognize the image file format" for its logo and shows a
# missing-image icon. The grep at the end of this RUN proves the loader landed
# in the gdk-pixbuf loader cache; if a Debian change ever drops it, the build
# fails here instead of the panel quietly losing its logo.
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
      librsvg2-common \
      fonts-dejavu-core \
      fonts-liberation2 \
      locales \
 && sed -i \
      -e 's/^# *en_US\.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' \
      -e 's/^# *sv_SE\.UTF-8 UTF-8/sv_SE.UTF-8 UTF-8/' \
      /etc/locale.gen \
 && locale-gen \
 && grep -q 'image/svg' /usr/lib/*/gdk-pixbuf-2.0/2.10.0/loaders.cache \
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

# The Teknoir fonts: Hanken Grotesk, the UI font of the platform (Backstage
# nextgen), and JetBrains Mono, the monospace one. Both are vendored from
# google/fonts rather than installed from Debian:
#
#   - Hanken Grotesk is not packaged in trixie at all (`apt-cache search
#     hanken` finds nothing), so it has to come from upstream either way.
#   - JetBrains Mono would come from fonts-jetbrains-mono, 7.5 MB installed
#     for two styles this image would never show. The variable font below is
#     187 KB and every weight is in it.
#
# Both files are noarch, so the same download serves amd64 and arm64, and they
# are pinned the way the noVNC tarball is: the commit names the tree the file
# came from (a branch or tag could move; a commit cannot), and the four
# sha256 values name the exact bytes. They are OFL-1.1, and the licence files
# are installed next to the fonts, in /usr/local/share/fonts/teknoir/, as the
# licence asks.
#
# To bump: pick a newer commit of google/fonts, put it in
# GOOGLE_FONTS_COMMIT, run `sha256sum` on the four files it serves, and put
# those values in the four *_SHA256 arguments. A stale commit with fresh
# hashes, or the reverse, fails the build at sha256sum -c.
#
# The RUN pipes into sha256sum -c, so it needs this stage's pipefail. fc-cache
# is part of the desktop package set; the two fc-list greps prove the fonts
# are not only on disk but in fontconfig's cache, under the family names
# /etc/fonts/local.conf prefers. fc-list's output goes to a file that is then
# searched, never piped into `grep -q`: grep -q exits at the first match,
# fc-list then dies of SIGPIPE writing the rest, and pipefail turns that into
# a failed build (exit 141) whenever the list is longer than one pipe buffer
# write, which is what broke the first CI build on main.
ARG GOOGLE_FONTS_COMMIT=06bfe0d62a98375cb09c942fa18e68bd32cff057
ARG HANKEN_GROTESK_SHA256=813b3f8fa0965405669a89b38e51bbefd95eef6b8e20d1cb2d8c10cce062662f
ARG HANKEN_GROTESK_OFL_SHA256=e02ccb89a86839b22feff7872ff5cc355cc0f58318d29eee20e2cf83a612f16d
ARG JETBRAINS_MONO_SHA256=48715a42ec242c21e9f02692891e147d022299a52e48d5e413e1a942193ffeda
ARG JETBRAINS_MONO_OFL_SHA256=b2fe5e8987594e9ffd1d2ca52a2f5d73eb8335243893c5d6254b5ad69269591d

ADD https://raw.githubusercontent.com/google/fonts/${GOOGLE_FONTS_COMMIT}/ofl/hankengrotesk/HankenGrotesk%5Bwght%5D.ttf /tmp/fonts/HankenGrotesk-VF.ttf
ADD https://raw.githubusercontent.com/google/fonts/${GOOGLE_FONTS_COMMIT}/ofl/hankengrotesk/OFL.txt /tmp/fonts/HankenGrotesk-OFL.txt
ADD https://raw.githubusercontent.com/google/fonts/${GOOGLE_FONTS_COMMIT}/ofl/jetbrainsmono/JetBrainsMono%5Bwght%5D.ttf /tmp/fonts/JetBrainsMono-VF.ttf
ADD https://raw.githubusercontent.com/google/fonts/${GOOGLE_FONTS_COMMIT}/ofl/jetbrainsmono/OFL.txt /tmp/fonts/JetBrainsMono-OFL.txt

RUN printf '%s  %s\n' \
      "$HANKEN_GROTESK_SHA256" /tmp/fonts/HankenGrotesk-VF.ttf \
      "$HANKEN_GROTESK_OFL_SHA256" /tmp/fonts/HankenGrotesk-OFL.txt \
      "$JETBRAINS_MONO_SHA256" /tmp/fonts/JetBrainsMono-VF.ttf \
      "$JETBRAINS_MONO_OFL_SHA256" /tmp/fonts/JetBrainsMono-OFL.txt \
    | sha256sum -c - \
 && install -d -m 0755 /usr/local/share/fonts/teknoir \
 && install -m 0644 /tmp/fonts/* /usr/local/share/fonts/teknoir/ \
 && rm -rf /tmp/fonts \
 && fc-cache -f /usr/local/share/fonts \
 && fc-list > /tmp/fc-list.txt \
 && grep -qF 'HankenGrotesk-VF.ttf: Hanken Grotesk' /tmp/fc-list.txt \
 && grep -qF 'JetBrainsMono-VF.ttf: JetBrains Mono' /tmp/fc-list.txt \
 && rm -f /tmp/fc-list.txt

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
#
# The theme: teknoir.css restyles the client to the Teknoir tokens (see its
# header), and it is linked into vnc.html right after input.css, the last of
# noVNC's three stylesheets, so its rules come later in the cascade and need
# no !important. The same RUN puts the brand mark and the Hanken Grotesk font
# where the page loads them from (app/images/ and app/styles/; the font comes
# from the RUN above, which is why that one runs first), swaps the favicon for
# the mark, sets the browser's theme color and the page title, and patches
# PAGE_TITLE in ui.js: ui.js overwrites document.title at runtime, so the
# <title> sed alone would not stick and the tab would read "noVNC" again as
# soon as the UI starts.
#
# Every sed here is followed by a grep for exactly what it wrote, because each
# one anchors on byte-exact markup in a noVNC file (vnc.html, ui.js,
# constants.css). A noVNC bump can change that markup without any checksum
# noticing - the checksum only covers the tarball that was downloaded, and the
# bump changes it on purpose - and without the greps the theme would silently
# half-apply: an unstyled panel here, a "noVNC" tab there. With them the build
# stops at the first thing that moved. The loop and the count after the seds
# guard the markup teknoir.css depends on (the six ids it styles, and the two
# .noVNC_logo elements it replaces with the mark), and the two greps guard the
# class and the variable it reads.
RUN chmod 0755 /usr/local/bin/desktop-* \
 && cp /opt/novnc-extra/index.html /opt/novnc/index.html \
 && cp /opt/novnc-extra/healthz /opt/novnc/healthz \
 && cp /opt/novnc-extra/mandatory.json /opt/novnc/mandatory.json \
 && cp /opt/novnc-extra/teknoir-notice.js /opt/novnc/teknoir-notice.js \
 && cp /opt/novnc-extra/teknoir.css /opt/novnc/app/styles/teknoir.css \
 && cp /usr/local/share/fonts/teknoir/HankenGrotesk-VF.ttf /usr/local/share/fonts/teknoir/HankenGrotesk-OFL.txt /opt/novnc/app/styles/ \
 && cp /usr/share/teknoir/teknoir-mark.svg /opt/novnc/app/images/teknoir-mark.svg \
 && ln -s /run/desktop/notice.json /opt/novnc/teknoir-notice.json \
 && sed -i 's#</head>#<script src="teknoir-notice.js?v=3" defer></script></head>#' /opt/novnc/vnc.html \
 && grep -qF '<script src="teknoir-notice.js?v=3" defer></script>' /opt/novnc/vnc.html \
 && sed -i 's#<link rel="stylesheet" href="app/styles/input.css">#&<link rel="stylesheet" href="app/styles/teknoir.css?v=3">#' /opt/novnc/vnc.html \
 && grep -qF '<link rel="stylesheet" href="app/styles/teknoir.css?v=3">' /opt/novnc/vnc.html \
 && sed -i 's#<link rel="icon" type="image/x-icon" href="app/images/icons/novnc.ico">#<link rel="icon" type="image/svg+xml" href="app/images/teknoir-mark.svg">#' /opt/novnc/vnc.html \
 && grep -qF '<link rel="icon" type="image/svg+xml" href="app/images/teknoir-mark.svg">' /opt/novnc/vnc.html \
 && sed -i 's|<meta name="theme-color" content="#313131">|<meta name="theme-color" content="#000000">|' /opt/novnc/vnc.html \
 && grep -qF '<meta name="theme-color" content="#000000">' /opt/novnc/vnc.html \
 && sed -i 's|<title>noVNC</title>|<title>Teknoir desktop</title>|' /opt/novnc/vnc.html \
 && grep -qF '<title>Teknoir desktop</title>' /opt/novnc/vnc.html \
 && sed -i 's|const PAGE_TITLE = "noVNC";|const PAGE_TITLE = "Teknoir desktop";|' /opt/novnc/app/ui.js \
 && grep -qF 'const PAGE_TITLE = "Teknoir desktop";' /opt/novnc/app/ui.js \
 && for id in noVNC_control_bar noVNC_control_bar_handle noVNC_status noVNC_connect_dlg noVNC_connect_button noVNC_transition; do grep -qF "id=\"$id\"" /opt/novnc/vnc.html || exit 1; done \
 && [ "$(grep -c 'class="noVNC_logo"' /opt/novnc/vnc.html)" = 2 ] \
 && grep -qF 'noVNC_status_warn' /opt/novnc/app/ui.js \
 && grep -qF -- '--novnc-blue' /opt/novnc/app/styles/constants.css \
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
# directory the container user cannot write. OpenCode finds them through the
# config's skills.paths (/etc/teknoirbot/kit/skills), not through a work
# directory's .agents/skills, which the Coder turns off. `--check` fails the
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
# every process in the container can read it. /etc/teknoirbot/xdg is OpenCode's
# config home: it must hold an opencode/ directory, and OpenCode writes nothing
# else there, so an empty root-owned one leaves uid 1000 no global config to
# plant either.
COPY rootfs-council/ /

RUN install -d -o root -g root -m 0755 /etc/teknoirbot/xdg/opencode \
 && chown -R root:root /etc/teknoirbot \
 && chmod -R go-w /etc/teknoirbot \
 && chmod 0644 /etc/teknoirbot/opencode.json

# OpenCode reads this one file, not whatever a work directory might carry
# (project configs are off), and its config home is the read-only one above;
# HOME and the other XDG directories live on the work volume, so a new pod
# keeps the Coder's sessions, state and cache. The Coder sets the same values
# for every task; these cover anything else that starts OpenCode here.
ENV OPENCODE_CONFIG=/etc/teknoirbot/opencode.json \
    OPENCODE_DISABLE_PROJECT_CONFIG=1 \
    HOME=/work/home \
    XDG_DATA_HOME=/work/home/.local/share \
    XDG_STATE_HOME=/work/home/.local/state \
    XDG_CACHE_HOME=/work/home/.cache \
    XDG_CONFIG_HOME=/etc/teknoirbot/xdg

WORKDIR /work

USER 1000:1000

# tini reaps whatever the Coder starts; the council is the container's process.
ENTRYPOINT ["/usr/bin/tini", "--", "tnctl", "council", "serve", "--work-dir", "/work"]
