# teknoir-desktop
#
#   make test           the whole test suite (no docker, no root)
#   make lint           shellcheck, hadolint and the config file checks
#   make image          multi-arch build of ghcr.io/teknoir/teknoir-desktop:dev
#   make image-agent    amd64 build of the agent image, :dev-agent
#   make seccomp        regenerate deploy/seccomp/teknoir-desktop.json
#   make seccomp-check  verify that it is up to date
#
# The image is normally built by CI; `make image` is for a local buildx.

IMAGE ?= ghcr.io/teknoir/teknoir-desktop
TMP ?= $(or $(TMPDIR),/var/tmp)/teknoir-desktop-seccomp

# The agent image embeds tnctl, built from this commit of teknoir/cli. It has
# no default on purpose: the cli commit has to be the one with
# `tnctl agent install`, and a stale default would build an image whose kit
# step fails, or worse, one that passes with an old kit.
TNCTL_REF ?=
TNCTL_VERSION ?= dev

.PHONY: test lint image image-agent seccomp seccomp-check

test:
	bash test/run.sh

lint:
	shellcheck -x rootfs/usr/local/bin/* rootfs-agent/usr/local/bin/* host/* test/*.sh
	hadolint Dockerfile

# buildx with two platforms needs a builder that supports them
# (`docker buildx create --use --name teknoir-multiarch`), and the push is
# skipped: the image stays in the local build cache.
image:
	docker buildx build --target desktop --platform linux/amd64,linux/arm64 -t $(IMAGE):dev .

# The agent image is amd64 only (three of the binaries it carries are), and
# its kit comes from tnctl, so TNCTL_REF must name the cli commit that has
# `tnctl agent install`. It must be the full commit, not a branch or a tag:
# the tnctl stage fetches exactly that name, and a moving name would keep the
# first commit BuildKit cached, silently.
image-agent:
	@if [ -z "$(TNCTL_REF)" ]; then \
	  echo "make image-agent: set TNCTL_REF to the teknoir/cli commit with 'tnctl agent install', e.g. make image-agent TNCTL_REF=<40-hex commit>" >&2; \
	  exit 1; \
	fi
	@if ! printf '%s' "$(TNCTL_REF)" | grep -qxE '[0-9a-f]{40}'; then \
	  echo "make image-agent: TNCTL_REF must be a full 40-character teknoir/cli commit" >&2; \
	  exit 1; \
	fi
	docker buildx build --target agent --platform linux/amd64 \
	  --build-arg TNCTL_REF=$(TNCTL_REF) --build-arg TNCTL_VERSION=$(TNCTL_VERSION) \
	  -t $(IMAGE):dev-agent .

# The seccomp profile: containerd's RuntimeDefault per architecture, merged and
# extended with the chroot/clone/unshare rule Chromium's sandbox needs. The
# arm64 binary runs under qemu-user binfmt.
seccomp:
	mkdir -p $(TMP)
	cd deploy/seccomp/gen && go build -o $(TMP)/gen-amd64 . && GOARCH=arm64 go build -o $(TMP)/gen-arm64 .
	$(TMP)/gen-amd64 -arch > $(TMP)/amd64.json
	$(TMP)/gen-arm64 -arch > $(TMP)/arm64.json   # runs under qemu-user binfmt
	$(TMP)/gen-amd64 -merge $(TMP)/amd64.json $(TMP)/arm64.json > deploy/seccomp/teknoir-desktop.json

seccomp-check:
	mkdir -p $(TMP)
	cd deploy/seccomp/gen && go build -o $(TMP)/gen-amd64 . && GOARCH=arm64 go build -o $(TMP)/gen-arm64 .
	$(TMP)/gen-amd64 -arch > $(TMP)/amd64.json
	$(TMP)/gen-arm64 -arch > $(TMP)/arm64.json   # runs under qemu-user binfmt
	$(TMP)/gen-amd64 -merge $(TMP)/amd64.json $(TMP)/arm64.json > $(TMP)/check.json
	diff -u deploy/seccomp/teknoir-desktop.json $(TMP)/check.json
