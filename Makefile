# teknoir-desktop
#
#   make test           the whole test suite (no docker, no root)
#   make lint           shellcheck, hadolint and the config file checks
#   make image          multi-arch build of ghcr.io/teknoir/teknoir-desktop:dev
#   make seccomp        regenerate deploy/seccomp/teknoir-desktop.json
#   make seccomp-check  verify that it is up to date
#
# The image is normally built by CI; `make image` is for a local buildx.

IMAGE ?= ghcr.io/teknoir/teknoir-desktop
TMP ?= $(or $(TMPDIR),/var/tmp)/teknoir-desktop-seccomp

.PHONY: test lint image seccomp seccomp-check

test:
	bash test/run.sh

lint:
	shellcheck -x rootfs/usr/local/bin/* host/* test/*.sh
	hadolint Dockerfile

# buildx with two platforms needs a builder that supports them
# (`docker buildx create --use --name teknoir-multiarch`), and the push is
# skipped: the image stays in the local build cache.
image:
	docker buildx build --platform linux/amd64,linux/arm64 -t $(IMAGE):dev .

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
