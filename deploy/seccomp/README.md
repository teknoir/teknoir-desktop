# teknoir-desktop seccomp profile

`teknoir-desktop.json` is the seccomp profile a **virtual-mode** teknoir-desktop
pod runs with:

```yaml
securityContext:
  seccompProfile:
    type: Localhost
    localhostProfile: profiles/teknoir-desktop.json
```

## What it is

It is containerd's `RuntimeDefault` profile for a container with **no
capabilities** (what the pod runs with: `capabilities.drop: [ALL]`), from the
containerd version that k3s v1.34.11+k3s1 ships, plus one rule:

```json
{"names": ["chroot", "clone", "unshare"], "action": "SCMP_ACT_ALLOW"}
```

That rule is what Chromium's renderer sandbox needs: an unprivileged user
namespace (`unshare`), the zygote inside it (`clone`), and `chroot` into the new
root. Under plain `RuntimeDefault` those calls are refused without
`CAP_SYS_ADMIN`, Chromium aborts with "No usable sandbox!", and the desktop
would have to run the browser with `--no-sandbox`.

Everything else stays as `RuntimeDefault` has it: `mount`, `umount2`, `setns`,
`bpf`, `keyctl`, `add_key`, `kexec_load`, `init_module` and the rest are still
denied, and `clone3` still answers `ENOSYS` (errno 38) so glibc falls back to
`clone`. The default action is `SCMP_ACT_ERRNO`.

The profile is merged from containerd's per-architecture profiles, so one file
serves `amd64` and `arm64` (rules for a syscall an architecture does not have
are skipped by runc).

## Where it goes

On every node that can run a virtual desktop, at

```
/var/lib/kubelet/seccomp/profiles/teknoir-desktop.json
```

(the kubelet's seccomp root plus the `localhostProfile` path). Device bootstrap
and the Ansible role install it on devices; the VM image of a TeknoirBot needs
it in the image too.

The host must allow unprivileged user namespaces as well — see README "Browser
sandbox".

## Regenerating it

```sh
make seccomp        # rewrite the JSON (needs qemu-user binfmt for arm64)
make seccomp-check  # generate into a temp directory and diff against the file
```

`gen/` holds the small Go program behind both targets.
