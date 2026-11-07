# teknoir-desktop

A browser remote desktop for the Teknoir platform, as the container image
`ghcr.io/teknoir/teknoir-desktop`.

The browser client is stock [noVNC](https://github.com/novnc/noVNC) 1.7.0. It is
served, together with the WebSocket bridge, by
[websockify](https://github.com/novnc/websockify) on **one port, 6080**: plain
HTTP for the noVNC page, a WebSocket on path `/websockify`. The VNC server sits
behind that on a unix socket, so nothing else listens on TCP.

## The two modes

| Mode | What the container is | VNC socket |
|---|---|---|
| `virtual` | the whole desktop: TigerVNC `Xvnc` as the X server (unix socket only), an XFCE session and Chromium | `/run/desktop/vnc.sock`, created by the container |
| `host` | only noVNC + websockify, bridging to a desktop that already runs on the **host** | `/run/teknoir-desktop/vnc.sock`, created by a systemd unit on the host, mounted in with a `hostPath` volume |

`virtual` is the computer of a TeknoirBot (an AI agent VM); a user watches it
and takes it over in the browser. `host` is for edge devices: the container adds
a browser view to the device's own desktop instead of running a second one.

## Ports and paths

| Path / port | What |
|---|---|
| `6080/tcp` | websockify: the noVNC client and the WebSocket, on one port |
| `/` | landing page, redirects to `vnc.html` with autoconnect on |
| `/vnc.html` | the noVNC client |
| `/websockify` | the WebSocket the client connects to |
| `/healthz` | static text `ok`, for a liveness probe (it does not check the VNC side) |
| `/teknoir-notice.json` | the notice banner text (see [Notice banner](#notice-banner)); a symlink to `/run/desktop/notice.json`, `{"text": ""}` without a notice in virtual mode; 404 in host mode |
| `/teknoir-notice.js` | the notice banner script, loaded by `vnc.html` (see [Notice banner](#notice-banner)) |
| `desktop-healthcheck` | the readiness probe: completes an RFB 3.8 handshake on the VNC socket and checks `/vnc.html` |

## Environment variables

Everything is configured by environment variables. The entrypoint validates
them at startup and exits with status 64 (and a message on stderr) on a bad
value.

| Variable | Default | Modes | Meaning |
|---|---|---|---|
| `DESKTOP_MODE` | `virtual` | both | `virtual` or `host` |
| `DESKTOP_PORT` | `6080` | both | web port, 1024–65535 |
| `DESKTOP_LISTEN` | `0.0.0.0` | both | address websockify binds to |
| `DESKTOP_SOCKET` | `virtual`: `/run/desktop/vnc.sock`<br>`host`: `/run/teknoir-desktop/vnc.sock` | both | the VNC unix socket |
| `DESKTOP_IDLE_TIMEOUT` | `0` | both | websockify `--idle-timeout` in seconds; 0 = never exit when idle |
| `DESKTOP_DRY_RUN` | `0` | both | `1` prints the commands it would run (`RUN: …`), starts nothing, exits 0; in virtual mode with a notice it also prints one `notice: <JSON>` line after the `RUN:` lines |
| `DESKTOP_GEOMETRY` | `1280x800` | virtual | screen size, `WIDTHxHEIGHT` |
| `DESKTOP_DEPTH` | `24` | virtual | colour depth: 16, 24 or 32 |
| `DESKTOP_DISPLAY` | `:1` | virtual | X display number |
| `DESKTOP_CLIPBOARD` | `both` | virtual | `both`, `to-desktop`, `from-desktop` or `off` |
| `DESKTOP_NOTICE` | *(empty)* | virtual | the shared-desktop banner: at most 300 characters, no control characters, valid UTF-8, leading and trailing whitespace (spaces, tabs, newlines) trimmed before the checks (a value over 4096 bytes is refused untrimmed); empty = no banner (see [Notice banner](#notice-banner)) |
| `DESKTOP_NOTICE_FILE` | `/run/desktop/notice.json` | virtual | where the entrypoint writes the banner text. **Test only**: the page always reads `/run/desktop/notice.json` through a fixed symlink, so any other value hides the notice from the page (a 404, or a stale file from an earlier start) |
| `DESKTOP_BROWSER` | `true` | virtual | start Chromium from the XFCE autostart; `false` leaves the desktop without a browser (the user can still open one from the application menu) |
| `DESKTOP_BROWSER_URL` | `about:blank` | virtual | the page Chromium opens |
| `DESKTOP_BROWSER_FLAGS` | *(empty)* | virtual | extra Chromium flags, split on spaces; never add `--no-sandbox` here (see [Browser sandbox](#browser-sandbox)) |
| `DESKTOP_BROWSER_SANDBOX` | `auto` | virtual | `auto`, `on` or `off`: whether Chromium may run with, must run with, or runs without its renderer sandbox (see [Browser sandbox](#browser-sandbox)) |

Rebuilding the desktop (virtual mode) needs a pod restart: the geometry, depth
and display are set when `Xvnc` starts.

## Browser sandbox

Virtual mode runs Chromium from the XFCE autostart
(`/usr/local/bin/desktop-browser`), so closing the browser window is harmless:
the desktop stays up and the user can open a new browser from the application
menu.

Chromium runs with its **renderer sandbox**, which needs an unprivileged user
namespace (`unshare`/`clone` with `CLONE_NEWUSER`). `RuntimeDefault` seccomp
refuses those calls without `CAP_SYS_ADMIN`, so a virtual-mode pod runs with the
`teknoir-desktop` **Localhost** seccomp profile instead:
`deploy/seccomp/teknoir-desktop.json`, which is RuntimeDefault plus
`chroot`/`clone`/`unshare`. The node must hold the file at
`/var/lib/kubelet/seccomp/profiles/teknoir-desktop.json` (see
[docs](deploy/seccomp/README.md)).

Before starting Chromium the wrapper probes the sandbox with
`unshare --user --map-root-user --pid --net --fork --root=/ true`:

| `DESKTOP_BROWSER_SANDBOX` | Probe succeeds | Probe fails |
|---|---|---|
| `auto` (default) | Chromium starts, sandboxed | Chromium is **not** started; the log names the seccomp profile; exit 78 |
| `on` | Chromium starts, sandboxed | Chromium is **not** started (the sandbox is required); exit 78 |
| `off` | probe skipped | `--no-sandbox`: **the renderer sandbox is off**; a warning is logged |

`off` is for trusted pages only and is never the default: an unsandboxed
renderer runs a hostile page with the privileges of the desktop user. Prefer
the seccomp profile.

Node requirements: unprivileged user namespaces enabled
(`kernel.unprivileged_userns_clone=1` on Debian, the default;
`user.max_user_namespaces` > 0), and on Ubuntu 23.10+/24.04 nodes either
`kernel.apparmor_restrict_unprivileged_userns=0` or an AppArmor rule that
allows the user namespace.

## Clipboard

`DESKTOP_CLIPBOARD` decides which clipboard directions the VNC server allows:
browser to desktop (`to-desktop`, Xvnc `-AcceptCutText`) and desktop to
browser (`from-desktop`, `-SendCutText`); `both` allows both, `off` neither.
The browser never reads the local clipboard by itself: text reaches the desktop
only when the user puts it in noVNC's clipboard panel, and text copied inside
the desktop appears in that panel rather than on the local clipboard (noVNC
1.7.0 `app/ui.js`). Nothing is pasted by a page or by a window becoming
active, so a bot desktop should normally run with `DESKTOP_CLIPBOARD=both`:
pasting is already an explicit action in the panel, and there is nothing to
protect by turning either direction off.

## Notice banner

A TeknoirBot's desktop (virtual mode) is shared with its whole teamspace, so
whoever opens it must see that it is not their own computer.
`DESKTOP_NOTICE` puts a thin amber banner at the top of the noVNC page, above
the remote screen and noVNC's controls, and the banner is what the platform's
TeknoirBot controller passes for its bot:

```yaml
env:
  - name: DESKTOP_NOTICE
    value: "This is the computer of TeknoirBot scout, shared with teamspace teknoir-demo. Don't sign in to Teknoir or personal accounts here, and don't run tnctl login."
```

- One line of at most 300 characters, counted as characters (`å`, `ä` and `ö`
  cost one each). Text that is not valid UTF-8 is refused with exit 64, and so
  is a control character inside it (a tab, a newline, C1 controls such as
  U+0085, and U+2028/U+2029); only ASCII whitespace at either end is trimmed
  first, such as the newline a YAML block scalar adds, and a notice that is
  empty after trimming counts as unset. A value longer than 4096 bytes is not
  trimmed and is refused (exit 64), even when it is only whitespace: trimming
  in bash takes quadratic time. The rules are the same in every locale.
- The text is shown literally (`<b>` is text, not markup), the full text is in
  the tooltip when it does not fit, and the `×` closes the banner for that page
  load only.
- The banner takes its space from the page rather than covering it: noVNC's
  container and status line move down 24 px and the remote desktop is 24 px
  shorter while the banner shows, and it gets its full height back after `×`.
  A click anywhere on the banner (the `×` included) does not move keyboard
  focus, which stays on the VNC canvas.
- noVNC's status line (Connecting, Disconnected, connection errors) moves down
  with the page and opens just below the banner, so the banner and the
  connection feedback are both readable. The banner's z-index is 99, below
  noVNC's status line (100) and its fatal-error box (1000): the status slides
  in over it, and only the fatal-error box covers it.
- The entrypoint writes it to `/run/desktop/notice.json` before websockify
  starts, and writes `{"text": ""}` when the variable is unset or empty after
  trimming, which also replaces a notice from an earlier start: `/run/desktop`
  is an `emptyDir` that survives a container restart, and the page fetches the
  file on every load, so a missing file would be a 404 in the browser console.
  Only host mode has no file, so only there does the page get a 404. A desktop
  user can leave something at that path in the `emptyDir`: a symlink (to a
  file or a directory) is replaced by the notice file without being followed,
  and a directory stops the start (exit 1, `cannot move the notice into
  /run/desktop/notice.json`) instead of starting without a banner.
- Opening the desktop again while the pod is down (a link, the Backstage
  button or a new tab; a reload revalidates the page and shows the error) can
  serve `vnc.html` from the browser cache, because websockify sends no
  `Cache-Control`, and once the desktop is back noVNC connects without a page
  load (its own reconnect, or the Connect button). The script therefore
  fetches the notice again on each new connect, until one has been shown, so
  a desktop that came back gets its banner.
- Host mode ignores it and logs one line saying so: the host desktop is the
  device's own session, not a shared bot desktop.
- At build time the Dockerfile copies `rootfs/opt/novnc-extra/teknoir-notice.js`
  into the noVNC tree as `/opt/novnc/teknoir-notice.js`, adds its `<script>`
  tag to `vnc.html`, and symlinks `/opt/novnc/teknoir-notice.json` to
  `/run/desktop/notice.json` for websockify to serve. Only that one file is
  linked: the rest of `/run/desktop` (Xauthority, `vnc.sock`) stays unreachable
  from the page.

## Security model

There is **no VNC password** (`-SecurityTypes None`): a password in front of an
unauthenticated desktop that only one user can reach adds nothing, and it would
have to come from the environment of a pod that anyone with `pods/exec` in the
namespace can read.

`Xvnc` listens on a unix socket only (`-rfbport -1 -rfbunixpath …`), and the X
display itself has an MIT-MAGIC-COOKIE: reaching the X socket is not enough to
read the screen or type into the session.

- In `virtual` mode the socket is `/run/desktop/vnc.sock`, mode **0600**, owned
  by the container user.
- In `host` mode the host `Xvnc` publishes `/run/teknoir-desktop/vnc.sock`, mode
  **0660**, owned by the group `teknoir-desktop` (gid **64080** on every Teknoir
  device): a pod can only connect if its `supplementalGroups` contain 64080.
- The cookie is `/run/desktop/Xauthority` in virtual mode and
  `~teknoir/.teknoir-desktop.Xauthority` in host mode; host mode needs `xauth`
  and `dbus-x11` (see [Host mode](#host-mode-the-systemd-unit)).
- `Xvnc` runs with `-BlacklistTimeout 0`: every client of the unix socket has
  the same peer address, so TigerVNC's per-address blacklist would lock out
  every client, noVNC included. The readiness probe also completes the RFB
  handshake instead of only reading the greeting, so it never leaves a
  half-authenticated connection behind.

The only intended way in is the platform's **authenticated Tunneling proxy**
(the `wgs-` host: login and access check at the hub), plus a **NetworkPolicy**
that refuses ingress from every other pod (see `deploy/examples/`). The Service
has no authentication of its own, so without that policy any pod on the device
could open the desktop without logging in.

The container listens on `6080` **inside the pod network only**: the Service is
`ClusterIP`, and there is no `NodePort`, no `LoadBalancer`, no `Ingress`.
**Never expose 6080 on a node or on the LAN.** There is no authentication behind
that port beyond the unix socket's permissions and the cookie; a forwarded port
is a full remote desktop for anyone who can reach it.

**Host mode hands the browser the device's own desktop session** of user
`teknoir`, with everything that user can do on the device (comparable to SSH).
**Virtual mode** is a restricted pod: non-root (uid/gid 1000 `desktop`, no sudo,
no password), all capabilities dropped, no privilege escalation, the
`teknoir-desktop` Localhost seccomp profile, and Chromium with its renderer
sandbox. Its `/dev/shm` is a 1Gi memory `emptyDir`. Current Chromium allocates
its shared memory with `memfd_create` and leaves `/dev/shm` mostly unused; the
browser wrapper still adds `--disable-dev-shm-usage` when `/dev/shm` is under
512 MiB, for builds and code paths that fall back to it (the flag moves that
fallback to the `/tmp` `emptyDir`).

## Host mode: the systemd unit

`host/` holds the **host side** of host mode. It is installed on a Teknoir
device by an Ansible role (later work); this repository only documents it and
installs nothing.

- `host/teknoir-desktop.service` — a systemd **system** unit, `User=teknoir`,
  `Group=teknoir-desktop`, `RuntimeDirectory=teknoir-desktop` (mode 0750,
  `RuntimeDirectoryPreserve=yes`, so the directory the pod's `hostPath` mount
  pins survives unit restarts), `Restart=always`, `RestartSec=5`,
  `RestartPreventExitStatus=78`, `PrivateTmp=yes`. The user and group are
  configurable through a drop-in.
- `host/teknoir-desktop-session` — installed to
  `/usr/local/libexec/teknoir-desktop-session`, it starts
  `Xvnc :7 -geometry 1600x900 -depth 24 …` on
  `/run/teknoir-desktop/vnc.sock` (mode 0660; it prefers `Xtigervnc` and uses
  an `Xvnc` only if that binary is TigerVNC — RealVNC and TightVNC ship an
  `Xvnc` without `-rfbunixpath`), waits for the socket, `chgrp`s it to
  `TEKNOIR_DESKTOP_GROUP` (default `teknoir-desktop`), and runs the first
  desktop session it finds: `startxfce4`, `startlxqt`, `mate-session`, then
  `gnome-session --session=gnome-flashback-metacity`. It supervises `Xvnc` and
  the session and exits when either does (including a user logging out), and
  systemd starts the unit again. Missing packages make it exit 78 (EX_CONFIG)
  instead, so the unit stays failed rather than restarting every 5 s; it also
  needs the `xauth` package for the display's cookie and `dbus-x11` for the
  `dbus-launch` the session runs under.

The socket group must match the pod's `supplementalGroups`. Every Teknoir
device has the system group `teknoir-desktop` with the fixed gid **64080** (the
Ansible desktop playbook creates it), the unit runs with it as its primary group
(the `teknoir` user keeps its own groups as supplementary groups), and the pod
runs with `supplementalGroups: [64080]` (device-controller's DESKTOP config
`hostGroupID`). Mounting the *directory* needs the same group:
`RuntimeDirectory=teknoir-desktop` with mode 0750 belongs to the unit's `Group=`.

The pod mounts `/run/teknoir-desktop` with `hostPath` type `Directory`,
read-only. The container waits up to 30 s for the socket at startup, logs once
per 10 s while it is missing, and then serves anyway: a browser gets a connect
error until the unit is up, and the readiness probe stays false.

The host needs both `xauth` (Debian/Ubuntu package `xauth`) for the display's
cookie and `dbus-x11` (the `dbus-launch` the session starts under): the session
gives the X display its own MIT-MAGIC-COOKIE in
`~teknoir/.teknoir-desktop.Xauthority`, so reaching the X socket is not enough
to read the screen. Without either package the script exits 78 and names the
missing package, instead of failing with 127 and being restarted every 5 s.

## Examples

`deploy/examples/virtual.yaml` and `deploy/examples/host.yaml` are complete,
working examples: Namespace `teknoir-desktop`, a one-replica Deployment with
`strategy: Recreate`, and a `ClusterIP` Service on port 6080 named `http`.

Virtual mode mounts `emptyDir`s at `/run/desktop`, `/dev/shm` (memory-backed,
1Gi, for desktop programs that use POSIX shared memory; Chromium runs with
`--disable-dev-shm-usage` only when `/dev/shm` is under 512 MiB), `/home/desktop`
and `/tmp`; replacing the `/home/desktop` `emptyDir` with a PersistentVolumeClaim
makes the desktop's files survive a pod restart. Only one pod may mount that
volume at a time (`ReadWriteOnce`, `strategy: Recreate`): the wrapper removes
Chromium's `Singleton{Lock,Socket,Cookie}` from the profile when no Chromium of
the pod's user is running (a pod that stopped uncleanly leaves a lock naming
its old hostname). While a browser is running the files are kept, and Chromium
hands a new launch to that instance instead of starting a second browser on the
same profile.

Both examples also create a `NetworkPolicy` that refuses ingress from other
pods; virtual mode's pod runs with the Localhost seccomp profile (see
[Browser sandbox](#browser-sandbox)), and both run non-root with all
capabilities dropped, without a Service-account token (`automountServiceAccountToken:
false`) and without Service links.

These manifests are **documentation**. Another component (the TeknoirBot
controller) renders the real ones, and deployments pin the image by digest
rather than the `:main` tag used in the examples.

## Build and test

```sh
make test          # bash test/run.sh: the whole suite
make lint          # shellcheck + hadolint
make image         # docker buildx build --platform linux/amd64,linux/arm64
```

The test suite needs no docker and no root. It runs `shellcheck -x` over every
script, `hadolint` over the Dockerfile, validates the Chromium policy JSON and
the xfconf XML, compares the entrypoint's `DESKTOP_DRY_RUN=1` output against the
vectors in `test/vectors/` (the defaults of both modes, overrides, and the
validation errors with their exit codes), checks the `DESKTOP_NOTICE` rules and
the `notice.json` file it writes, runs `desktop-browser` with stub
`chromium`/`unshare`/`pgrep` binaries to check the argv it gets and when its
Singleton files are removed, checks the `index.html` redirect logic and
`teknoir-notice.js` against a stand-in page with `node`, and runs
`desktop-healthcheck` against a stand-in RFB server and a
stand-in web server, including a server that refuses the connection the way a
blacklisted Xvnc does.

The image is multi-arch (`linux/amd64`, `linux/arm64`). It is built only from
Debian packages plus the noarch noVNC tarball (checksum-pinned), so there is no
per-architecture download.

## Licences

| Component | Licence |
|---|---|
| noVNC 1.7.0 | MPL-2.0 |
| TigerVNC (Xvnc) | GPL-2.0 |
| websockify | LGPL-3.0 |
| this repository | Apache-2.0 (see `LICENSE`) |
