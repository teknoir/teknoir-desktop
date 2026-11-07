#!/usr/bin/env bash
#
# teknoir-desktop test suite.
#
# Needs no docker and no root: it checks the scripts, the Dockerfile, the
# config files, the manifests, the entrypoint's dry-run output and the health
# probe against stand-in servers. Run it with:
#
#   bash test/run.sh
#
# Prints "PASS <name>" / "FAIL <name>" per test and a summary; exits non-zero
# if anything failed.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

ENTRYPOINT="rootfs/usr/local/bin/desktop-entrypoint"
BROWSER="rootfs/usr/local/bin/desktop-browser"
HEALTHCHECK="rootfs/usr/local/bin/desktop-healthcheck"
INDEX="rootfs/opt/novnc-extra/index.html"

TMP="$(mktemp -d "${TMPDIR:-/tmp}/teknoir-desktop-test.XXXXXX")"
# Background servers the health-probe tests start.
HTTP_PID=""
RFB_PID=""
BAD_HTTP_PID=""
BAD_RFB_PID=""
REFUSE_PID=""
REFUSE_HTTP_PID=""

cleanup() {
  local pid
  for pid in "$HTTP_PID" "$RFB_PID" "$BAD_HTTP_PID" "$BAD_RFB_PID" \
    "$REFUSE_PID" "$REFUSE_HTTP_PID"; do
    if [ -n "$pid" ]; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
  rm -rf "$TMP"
}
trap cleanup EXIT

# The browser wrapper asks df how big /dev/shm is and only then passes
# --disable-dev-shm-usage. Stubbing df keeps the dry-run vectors the same on
# every machine (a container often has a 64 MiB /dev/shm); a second, small
# stub tests the flag itself.
mkdir -p "$TMP/bin" "$TMP/bin-smallshm"
printf '#!/bin/sh\necho " 1K-blocks"\necho " 2097152"\n' >"$TMP/bin/df"
printf '#!/bin/sh\necho " 1K-blocks"\necho " 65536"\n' >"$TMP/bin-smallshm/df"
chmod 0755 "$TMP/bin/df" "$TMP/bin-smallshm/df"
TEST_PATH="$TMP/bin:/usr/local/bin:/usr/bin:/bin"
SMALLSHM_PATH="$TMP/bin-smallshm:$TEST_PATH"

passed=0
failed=0
skipped=0

pass() {
  printf 'PASS %s\n' "$1"
  passed=$((passed + 1))
}

fail() {
  printf 'FAIL %s\n' "$1"
  if [ $# -gt 1 ]; then
    printf '     %s\n' "$2"
  fi
  failed=$((failed + 1))
}

skip() {
  printf 'SKIP %s: %s\n' "$1" "$2"
  skipped=$((skipped + 1))
}

# --- shellcheck -------------------------------------------------------------

test_shellcheck() {
  if ! command -v shellcheck >/dev/null 2>&1; then
    skip shellcheck "shellcheck is not on PATH"
    return
  fi

  # The same set the brief's command names, globs included: host/ also holds a
  # systemd unit, which carries a "shellcheck disable=all" comment of its own.
  local scripts=() f
  for f in rootfs/usr/local/bin/* host/* test/*.sh; do
    [ -f "$f" ] && scripts+=("$f")
  done

  if shellcheck -x "${scripts[@]}" >"$TMP/shellcheck.out" 2>&1; then
    pass shellcheck
  else
    fail shellcheck "$(head -40 "$TMP/shellcheck.out" | tr '\n' '|')"
  fi
}

# --- hadolint ---------------------------------------------------------------

test_hadolint() {
  if ! command -v hadolint >/dev/null 2>&1; then
    skip hadolint "hadolint is not on PATH"
    return
  fi

  if hadolint Dockerfile >"$TMP/hadolint.out" 2>&1; then
    pass hadolint
  else
    fail hadolint "$(head -20 "$TMP/hadolint.out" | tr '\n' '|')"
  fi
}

# --- config file syntax -----------------------------------------------------

test_chromium_policy_json() {
  if python3 -I -c '
import json, sys
with open("rootfs/etc/chromium/policies/managed/teknoir.json", encoding="utf-8") as fh:
    data = json.load(fh)
if not isinstance(data, dict) or not data:
    sys.exit("the policy is not a non-empty JSON object")
if data.get("CommandLineFlagSecurityWarningsEnabled") is not False:
    sys.exit("CommandLineFlagSecurityWarningsEnabled is not false")
' >"$TMP/json.out" 2>&1; then
    pass chromium-policy-json
  else
    fail chromium-policy-json "$(tr '\n' '|' <"$TMP/json.out")"
  fi
}

test_xfconf_xml() {
  if python3 -I -c '
import glob, sys
from xml.dom import minidom

files = sorted(glob.glob("rootfs/etc/xdg/xfce4/xfconf/xfce-perchannel-xml/*.xml"))
if not files:
    sys.exit("no xfconf files found")
for path in files:
    try:
        minidom.parse(path)
    except Exception as exc:  # noqa: BLE001 - report any parse failure
        sys.exit("%s: %s" % (path, exc))
' >"$TMP/xml.out" 2>&1; then
    pass xfconf-xml
  else
    fail xfconf-xml "$(tr '\n' '|' <"$TMP/xml.out")"
  fi
}

# --- the seccomp profile ----------------------------------------------------

test_seccomp_profile() {
  if python3 -I -c '
import json, sys

with open("deploy/seccomp/teknoir-desktop.json", encoding="utf-8") as fh:
    profile = json.load(fh)

problems = []

if profile.get("defaultAction") != "SCMP_ACT_ERRNO":
    problems.append("defaultAction is %r" % (profile.get("defaultAction"),))

arches = profile.get("architectures") or []
for want in ("SCMP_ARCH_X86_64", "SCMP_ARCH_AARCH64"):
    if want not in arches:
        problems.append("architecture %s missing" % want)

rules = profile.get("syscalls") or []
last = rules[-1] if rules else None
if last != {"names": ["chroot", "clone", "unshare"], "action": "SCMP_ACT_ALLOW"}:
    problems.append("last rule is not the sandbox rule: %r" % (last,))

forbidden = {"mount", "umount2", "setns", "bpf", "keyctl", "add_key",
             "kexec_load", "init_module"}
for rule in rules:
    if rule.get("action") != "SCMP_ACT_ALLOW" or rule.get("args"):
        continue
    bad = forbidden & set(rule.get("names") or [])
    if bad:
        problems.append("unconditional allow of %s" % ",".join(sorted(bad)))

clone3 = [r for r in rules if r.get("names") == ["clone3"]]
if (len(clone3) != 1 or clone3[0].get("action") != "SCMP_ACT_ERRNO"
        or clone3[0].get("errnoRet") != 38):
    problems.append("clone3 rule is not SCMP_ACT_ERRNO/38: %r" % (clone3,))

if problems:
    sys.exit("; ".join(problems))
' >"$TMP/seccomp.out" 2>&1; then
    pass seccomp-profile
  else
    fail seccomp-profile "$(tr '\n' '|' <"$TMP/seccomp.out")"
  fi
}

# --- the noVNC files --------------------------------------------------------

test_novnc_extra() {
  # mandatory.json pins the WebSocket target inside noVNC.
  if ! python3 -I -c '
import json, sys
with open("rootfs/opt/novnc-extra/mandatory.json", encoding="utf-8") as fh:
    data = json.load(fh)
if data.get("host") != "":
    sys.exit("host is %r, want the empty string" % (data.get("host"),))
if data.get("path") != "websockify":
    sys.exit("path is %r, want websockify" % (data.get("path"),))
' >"$TMP/mandatory.out" 2>&1; then
    fail novnc-mandatory-json "$(tr '\n' '|' <"$TMP/mandatory.out")"
    return
  fi
  pass novnc-mandatory-json

  # The image must copy it next to the client and drop the lite client, which
  # ignores mandatory.json.
  local problems="" want
  want='cp /opt/novnc-extra/mandatory.json /opt/novnc/mandatory.json'
  grep -qF "$want" Dockerfile || problems+="Dockerfile does not '$want'; "
  want='/opt/novnc/vnc_lite.html'
  grep -qF "$want" Dockerfile || problems+="Dockerfile does not remove $want; "
  if [ -z "$problems" ]; then
    pass dockerfile-novnc
  else
    fail dockerfile-novnc "$problems"
  fi
}

# Debian's /etc/chromium.d/dev-shm adds --disable-dev-shm-usage whenever
# /dev/shm is under 3.8 GB, which would override the wrapper's 512 MiB rule
# and send Chromium's shared memory to the disk-backed /tmp.
test_dockerfile_dev_shm() {
  if grep -qF 'rm -f /etc/chromium.d/dev-shm' Dockerfile; then
    pass dockerfile-drops-debian-dev-shm
  else
    fail dockerfile-drops-debian-dev-shm \
      "the Dockerfile does not remove /etc/chromium.d/dev-shm"
  fi
}

# --- entrypoint dry-run vectors ---------------------------------------------

run_vector() {
  local file="$1"
  local name
  name="entrypoint-vector-$(basename "$file" .txt)"

  local env_spec="" want_exit="" want_stderr="" want_out="" line
  local first=1
  while IFS= read -r line || [ -n "$line" ]; do
    if [ "$first" = 1 ]; then
      first=0
      case "$line" in
        "ENV: "*)
          env_spec="${line#ENV: }"
          continue
          ;;
        *)
          fail "$name" "first line must be 'ENV: K=V ...', got '$line'"
          return
          ;;
      esac
    fi
    case "$line" in
      "EXIT: "*) want_exit="${line#EXIT: }" ;;
      "STDERR: "*) want_stderr="${line#STDERR: }" ;;
      *)
        if [ -n "$want_out" ]; then
          want_out+=$'\n'
        fi
        want_out+="$line"
        ;;
    esac
  done <"$file"

  local -a envs=()
  read -r -a envs <<<"$env_spec"

  # A clean environment: nothing from the caller's shell may leak in. The
  # stubbed df keeps the browser line's --disable-dev-shm-usage decision
  # deterministic.
  env -i PATH="$TEST_PATH" HOME=/home/desktop \
    "${envs[@]}" \
    bash "$ENTRYPOINT" >"$TMP/vector.out" 2>"$TMP/vector.err"
  local rc=$?

  local got_out got_err
  got_out="$(cat "$TMP/vector.out")"
  got_err="$(cat "$TMP/vector.err")"

  local problems=""

  if [ -n "$want_exit" ]; then
    if [ "$rc" != "$want_exit" ]; then
      problems+="exit $rc, want $want_exit; "
    fi
  elif [ "$rc" != 0 ]; then
    problems+="exit $rc, want 0; "
  fi

  if [ -n "$want_stderr" ]; then
    if [ "$got_err" != "$want_stderr" ]; then
      problems+="stderr '$got_err', want '$want_stderr'; "
    fi
  elif [ -n "$got_err" ]; then
    problems+="unexpected stderr '$got_err'; "
  fi

  if [ -n "$want_out" ] && [ "$got_out" != "$want_out" ]; then
    problems+="stdout mismatch: got '$got_out'; "
  fi

  if [ -z "$problems" ]; then
    pass "$name"
  else
    fail "$name" "$problems"
  fi
}

test_entrypoint_vectors() {
  local file
  for file in test/vectors/*.txt; do
    [ -f "$file" ] || continue
    run_vector "$file"
  done
}

# --- browser wrapper --------------------------------------------------------

test_browser_wrapper() {
  local home="$TMP/wrapper-home" out rc err
  mkdir -p "$home"

  # auto (the default): the sandbox stays on, so no --no-sandbox, and nothing
  # is probed or started in a dry run.
  out="$(env -i PATH="$TEST_PATH" HOME="$home" DESKTOP_DRY_RUN=1 \
    bash "$BROWSER" --autostart 2>"$TMP/wrapper.err")"
  rc=$?
  err="$(cat "$TMP/wrapper.err")"
  if [ "$rc" = 0 ] &&
    [[ "$out" == "RUN: chromium "* ]] &&
    [[ "$out" != *"--no-sandbox"* ]] &&
    [[ "$out" == *"--user-data-dir=$home/.config/chromium-desktop"* ]] &&
    [[ "$out" == *" about:blank" ]]; then
    pass browser-wrapper-auto
  else
    fail browser-wrapper-auto "exit $rc, stdout '$out', stderr '$err'"
  fi

  # on: required, and the probe is skipped in a dry run, so also no
  # --no-sandbox.
  out="$(env -i PATH="$TEST_PATH" HOME="$home" DESKTOP_DRY_RUN=1 \
    DESKTOP_BROWSER_SANDBOX=on bash "$BROWSER" --autostart 2>&1)"
  rc=$?
  if [ "$rc" = 0 ] && [[ "$out" == "RUN: chromium "* ]] && [[ "$out" != *"--no-sandbox"* ]]; then
    pass browser-wrapper-on
  else
    fail browser-wrapper-on "exit $rc, output '$out'"
  fi

  # off: the renderer sandbox is turned off explicitly.
  out="$(env -i PATH="$TEST_PATH" HOME="$home" DESKTOP_DRY_RUN=1 \
    DESKTOP_BROWSER_SANDBOX=off bash "$BROWSER" --autostart 2>/dev/null)"
  rc=$?
  if [ "$rc" = 0 ] && [[ "$out" == *"--no-sandbox"* ]]; then
    pass browser-wrapper-off
  else
    fail browser-wrapper-off "exit $rc, output '$out'"
  fi

  # DESKTOP_BROWSER=false from the autostart: exit 0 and say nothing.
  out="$(env -i PATH="$TEST_PATH" HOME="$home" DESKTOP_DRY_RUN=1 \
    DESKTOP_BROWSER=false bash "$BROWSER" --autostart 2>&1)"
  rc=$?
  if [ "$rc" = 0 ] && [ -z "$out" ]; then
    pass browser-wrapper-disabled
  else
    fail browser-wrapper-disabled "exit $rc, output '$out'"
  fi

  # ... but from the application menu the user asked for a browser.
  out="$(env -i PATH="$TEST_PATH" HOME="$home" DESKTOP_DRY_RUN=1 \
    DESKTOP_BROWSER=false bash "$BROWSER" 2>&1)"
  rc=$?
  if [ "$rc" = 0 ] && [[ "$out" == "RUN: chromium "* ]]; then
    pass browser-wrapper-disabled-manual
  else
    fail browser-wrapper-disabled-manual "exit $rc, output '$out'"
  fi

  # An invalid sandbox value is a configuration error.
  out="$(env -i PATH="$TEST_PATH" HOME="$home" DESKTOP_DRY_RUN=1 \
    DESKTOP_BROWSER_SANDBOX=bogus bash "$BROWSER" 2>&1)"
  rc=$?
  if [ "$rc" = 64 ] && [[ "$out" == *"invalid DESKTOP_BROWSER_SANDBOX 'bogus'"* ]]; then
    pass browser-wrapper-invalid-sandbox
  else
    fail browser-wrapper-invalid-sandbox "exit $rc, output '$out'"
  fi

  # DESKTOP_BROWSER_FLAGS go in before the URL.
  out="$(env -i PATH="$TEST_PATH" HOME="$home" DESKTOP_DRY_RUN=1 \
    DESKTOP_BROWSER_FLAGS="--kiosk --lang=sv" DESKTOP_BROWSER_URL=https://example.com \
    bash "$BROWSER" 2>&1)"
  rc=$?
  if [ "$rc" = 0 ] && [[ "$out" == *"--kiosk --lang=sv https://example.com" ]]; then
    pass browser-wrapper-flags
  else
    fail browser-wrapper-flags "exit $rc, output '$out'"
  fi

  # --disable-dev-shm-usage only when /dev/shm is under 512 MiB.
  out="$(env -i PATH="$SMALLSHM_PATH" HOME="$home" DESKTOP_DRY_RUN=1 \
    bash "$BROWSER" 2>&1)"
  rc=$?
  if [ "$rc" = 0 ] && [[ "$out" == *"--disable-dev-shm-usage"* ]]; then
    pass browser-wrapper-small-shm
  else
    fail browser-wrapper-small-shm "exit $rc, output '$out'"
  fi
  out="$(env -i PATH="$TEST_PATH" HOME="$home" DESKTOP_DRY_RUN=1 \
    bash "$BROWSER" 2>&1)"
  if [[ "$out" == *"--disable-dev-shm-usage"* ]]; then
    fail browser-wrapper-big-shm "the flag is passed with a 2 GiB /dev/shm"
  else
    pass browser-wrapper-big-shm
  fi
}

# The path that really starts Chromium: stub chromium/unshare/df/pgrep record
# what the wrapper does, so the argv Chromium gets (not just the dry-run line)
# is checked.
test_browser_live() {
  local livebin="$TMP/live-bin" home="$TMP/live-home"
  local chromium_args="$TMP/chromium.args" profile="$TMP/live-home/.config/chromium-desktop"
  mkdir -p "$livebin" "$home"
  printf '#!/bin/sh\necho " 1K-blocks"\necho " 2097152"\n' >"$livebin/df"
  printf '#!/bin/sh\nexit 1\n' >"$livebin/pgrep"
  chmod 0755 "$livebin/df" "$livebin/pgrep"
  # shellcheck disable=SC2016 # the stub expands "$@" at run time, not now
  printf '#!/bin/sh\nprintf "%%s\\n" "$@" >"%s"\n' "$chromium_args" >"$livebin/chromium"
  printf '#!/bin/sh\nexit 0\n' >"$livebin/unshare"
  chmod 0755 "$livebin/chromium" "$livebin/unshare"
  local live_path="$livebin:$TEST_PATH"

  # 1. The sandbox probe succeeds: Chromium gets the flags and the URL, and
  #    never the word "chromium" (which it would open as a URL in a tab).
  rm -f "$chromium_args"
  env -i PATH="$live_path" HOME="$home" DESKTOP_BROWSER_URL=https://example.com \
    bash "$BROWSER" >"$TMP/live.out" 2>"$TMP/live.err"
  local rc=$? problems=""
  local -a got=()
  if [ -f "$chromium_args" ]; then
    mapfile -t got <"$chromium_args"
  fi
  if [ "$rc" != 0 ]; then
    problems+="exit $rc, want 0; "
  fi
  if [ "${#got[@]}" -eq 0 ]; then
    problems+="Chromium was not started (no argv recorded); "
  else
    if [ "${got[0]}" != --no-first-run ]; then
      problems+="first argument '${got[0]}', want --no-first-run; "
    fi
    if [ "${got[${#got[@]} - 1]}" != "https://example.com" ]; then
      problems+="last argument '${got[${#got[@]} - 1]}', want the URL; "
    fi
    if printf '%s\n' "${got[@]}" | grep -qx "chromium"; then
      problems+="a bare 'chromium' argument was passed (Chromium opens it as a URL); "
    fi
  fi
  if [ -z "$problems" ]; then
    pass browser-live-argv
  else
    fail browser-live-argv "$problems argv '$(tr '\n' ' ' <"$chromium_args" 2>/dev/null)'"
  fi

  # 2. The probe fails (auto): exit 78, a message, and no Chromium at all.
  rm -f "$chromium_args"
  printf '#!/bin/sh\nexit 1\n' >"$livebin/unshare"
  env -i PATH="$live_path" HOME="$home" DESKTOP_BROWSER_URL=https://example.com \
    bash "$BROWSER" >"$TMP/live.out" 2>"$TMP/live.err"
  rc=$?
  local err
  err="$(cat "$TMP/live.err")"
  if [ "$rc" = 78 ] && [ ! -e "$chromium_args" ] &&
    [[ "$err" == *"Chromium not started"* ]]; then
    pass browser-live-sandbox-blocked
  else
    fail browser-live-sandbox-blocked "exit $rc, chromium.args present: $([ -e "$chromium_args" ] && echo yes || echo no), stderr '$err'"
  fi

  # 3. off: the probe is skipped, --no-sandbox is passed and the warning goes
  #    to stderr (the unshare stub still exits 1).
  rm -f "$chromium_args"
  env -i PATH="$live_path" HOME="$home" DESKTOP_BROWSER_SANDBOX=off \
    DESKTOP_BROWSER_URL=https://example.com bash "$BROWSER" \
    >"$TMP/live.out" 2>"$TMP/live.err"
  rc=$?
  err="$(cat "$TMP/live.err")"
  if [ "$rc" = 0 ] && [[ "$err" == *"warning: the Chromium renderer sandbox is off"* ]] &&
    grep -qx -- "--no-sandbox" "$chromium_args" 2>/dev/null; then
    pass browser-live-sandbox-off
  else
    fail browser-live-sandbox-off "exit $rc, stderr '$err', argv '$(tr '\n' ' ' <"$chromium_args" 2>/dev/null)'"
  fi

  # 4. Chromium's Singleton files are removed only when no Chromium of this
  #    user is running. A running one must keep them (and hand the new request
  #    to itself), or a second browser would write the same profile.
  printf '#!/bin/sh\nexit 0\n' >"$livebin/unshare"
  chmod 0755 "$livebin/unshare"
  local f
  local -a files=("$profile/SingletonLock" "$profile/SingletonSocket" "$profile/SingletonCookie")
  mkdir -p "$profile"
  for f in "${files[@]}"; do
    printf 'oldpod-1\n' >"$f"
  done
  printf '#!/bin/sh\nexit 0\n' >"$livebin/pgrep"
  chmod 0755 "$livebin/pgrep"
  env -i PATH="$live_path" HOME="$home" bash "$BROWSER" \
    >"$TMP/live.out" 2>"$TMP/live.err"
  rc=$?
  problems=""
  if [ "$rc" != 0 ]; then
    problems+="exit $rc, want 0; "
  fi
  for f in "${files[@]}"; do
    [ -e "$f" ] || problems+="$(basename "$f") was removed while a Chromium was running; "
  done
  if [ -z "$problems" ]; then
    pass browser-singleton-kept
  else
    fail browser-singleton-kept "$problems"
  fi

  printf '#!/bin/sh\nexit 1\n' >"$livebin/pgrep"
  chmod 0755 "$livebin/pgrep"
  for f in "${files[@]}"; do
    printf 'oldpod-1\n' >"$f"
  done
  env -i PATH="$live_path" HOME="$home" bash "$BROWSER" \
    >"$TMP/live.out" 2>"$TMP/live.err"
  rc=$?
  problems=""
  if [ "$rc" != 0 ]; then
    problems+="exit $rc, want 0; "
  fi
  for f in "${files[@]}"; do
    [ -e "$f" ] && problems+="$(basename "$f") was not removed with no Chromium running; "
  done
  if [ -z "$problems" ]; then
    pass browser-singleton-stale-removed
  else
    fail browser-singleton-stale-removed "$problems"
  fi
}

# --- the desktop entries and the app menu -----------------------------------

test_desktop_entries() {
  local autostart="rootfs/etc/xdg/autostart/teknoir-browser.desktop"
  local menu="rootfs/usr/share/applications/teknoir-browser.desktop"
  local problems="" f

  for f in "$autostart" "$menu"; do
    if [ ! -f "$f" ]; then
      problems+="$f missing; "
      continue
    fi
    grep -q '^Type=Application$' "$f" || problems+="$f: no Type=Application; "
    grep -q '^Name=Web browser$' "$f" || problems+="$f: no Name=Web browser; "
    grep -qE '^Exec=/usr/local/bin/desktop-browser( |$)' "$f" ||
      problems+="$f: Exec does not run desktop-browser; "
  done
  grep -q '^Exec=/usr/local/bin/desktop-browser --autostart$' "$autostart" 2>/dev/null ||
    problems+="the autostart entry lacks --autostart; "
  grep -q '^X-GNOME-Autostart-enabled=true$' "$autostart" 2>/dev/null ||
    problems+="the autostart entry is not enabled; "
  grep -q '^NoDisplay=true$' "$autostart" 2>/dev/null ||
    problems+="the autostart entry is not hidden from the menu; "
  grep -q '^Categories=.*WebBrowser' "$menu" 2>/dev/null ||
    problems+="the menu entry is not in WebBrowser; "
  grep -q '^Icon=chromium$' "$menu" 2>/dev/null ||
    problems+="the menu entry has no chromium icon; "

  if [ -z "$problems" ]; then
    pass desktop-entries
  else
    fail desktop-entries "$problems"
  fi
}

# --- the manifests ----------------------------------------------------------

test_manifests() {
  if python3 -I -c '
import sys
import yaml


def load(path):
    with open(path, encoding="utf-8") as fh:
        return [d for d in yaml.safe_load_all(fh) if isinstance(d, dict)]


def only(docs, kind, path, problems):
    found = [d for d in docs if d.get("kind") == kind]
    if len(found) != 1:
        problems.append("%s: %d %s objects" % (path, len(found), kind))
        return None
    return found[0]


problems = []

for path, want in (("deploy/examples/virtual.yaml", "Localhost"),
                   ("deploy/examples/host.yaml", "RuntimeDefault")):
    docs = load(path)
    deployment = only(docs, "Deployment", path, problems)
    if deployment is not None:
        pod = deployment["spec"]["template"]["spec"]
        # No API token and no Service links in either mode: a page that
        # escapes the renderer, or a user in the terminal, must find no
        # credential in the pod. "is not False" makes a missing key fail too.
        for key in ("automountServiceAccountToken", "enableServiceLinks"):
            if pod.get(key) is not False:
                problems.append("%s: %s is %r, want false"
                                % (path, key, pod.get(key)))
        security = pod.get("securityContext") or {}
        profile = security.get("seccompProfile") or {}
        if profile.get("type") != want:
            problems.append("%s: seccompProfile type %r, want %r"
                            % (path, profile.get("type"), want))
        if want == "Localhost":
            if profile.get("localhostProfile") != "profiles/teknoir-desktop.json":
                problems.append("%s: localhostProfile %r"
                                % (path, profile.get("localhostProfile")))
        container = (pod.get("containers") or [{}])[0]
        caps = (container.get("securityContext") or {}).get("capabilities") or {}
        if caps.get("drop") != ["ALL"]:
            problems.append("%s: capabilities.drop is %r" % (path, caps.get("drop")))
        if security.get("runAsNonRoot") is not True:
            problems.append("%s: runAsNonRoot is not true" % path)

    policy = only(docs, "NetworkPolicy", path, problems)
    if policy is not None:
        spec = policy.get("spec") or {}
        if spec.get("policyTypes") != ["Ingress"]:
            problems.append("%s: NetworkPolicy policyTypes %r" % (path, spec.get("policyTypes")))
        if spec.get("ingress"):
            problems.append("%s: NetworkPolicy admits ingress rules" % path)
        if "podSelector" not in spec:
            problems.append("%s: NetworkPolicy has no podSelector" % path)

# Host mode: the pod only reads the host directory.
docs = load("deploy/examples/host.yaml")
deployment = only(docs, "Deployment", "deploy/examples/host.yaml", problems)
if deployment is not None:
    pod = deployment["spec"]["template"]["spec"]
    mounts = (pod.get("containers") or [{}])[0].get("volumeMounts") or []
    vnc = [m for m in mounts if m.get("name") == "vnc"]
    if len(vnc) != 1 or vnc[0].get("readOnly") is not True:
        problems.append("host.yaml: the vnc mount is not readOnly")
    volumes = [v for v in (pod.get("volumes") or []) if v.get("name") == "vnc"]
    if len(volumes) != 1 or (volumes[0].get("hostPath") or {}).get("path") != "/run/teknoir-desktop":
        problems.append("host.yaml: the vnc volume is not the hostPath /run/teknoir-desktop")

if problems:
    sys.exit("; ".join(problems))
' >"$TMP/manifests.out" 2>&1; then
    pass manifests
  else
    fail manifests "$(tr '\n' '|' <"$TMP/manifests.out")"
  fi
}

# --- the host unit ----------------------------------------------------------

test_host_unit() {
  local unit="host/teknoir-desktop.service" problems="" want
  for want in \
    'RuntimeDirectoryPreserve=yes' \
    'Restart=always' \
    'RestartPreventExitStatus=78' \
    'PrivateTmp=yes' \
    'RuntimeDirectory=teknoir-desktop' \
    'RuntimeDirectoryMode=0750' \
    'Group=teknoir-desktop'; do
    grep -qx "$want" "$unit" || problems+="missing $want; "
  done
  grep -qx 'Restart=on-failure' "$unit" && problems+="still Restart=on-failure; "
  grep -q '64080' "$unit" || problems+="the gid 64080 note is gone; "

  if [ -z "$problems" ]; then
    pass host-unit
  else
    fail host-unit "$problems"
  fi
}

# --- the host session script ------------------------------------------------

test_host_session() {
  local bindir="$TMP/session-bin" home="$TMP/session-home" rundir="$TMP/session-run"
  local out rc
  local bash_bin
  bash_bin="$(command -v bash)"
  mkdir -p "$bindir" "$home" "$rundir"
  # mkdir is the only command the script needs before it looks for a session;
  # a PATH with nothing else on it means no real session can start.
  ln -sf "$(command -v mkdir)" "$bindir/mkdir"

  # No desktop session: exit 78 (EX_CONFIG), and say what to install.
  out="$(env -i PATH="$bindir" HOME="$home" RUNTIME_DIRECTORY="$rundir" \
    "$bash_bin" host/teknoir-desktop-session 2>&1)"
  rc=$?
  if [ "$rc" = 78 ] && [[ "$out" == *"no desktop session found"*"install"* ]]; then
    pass host-session-no-session
  else
    fail host-session-no-session "exit $rc, output '$out'"
  fi

  # A session but no TigerVNC: also exit 78.
  printf '#!/bin/sh\nexit 0\n' >"$bindir/startxfce4"
  chmod 0755 "$bindir/startxfce4"
  out="$(env -i PATH="$bindir" HOME="$home" RUNTIME_DIRECTORY="$rundir" \
    "$bash_bin" host/teknoir-desktop-session 2>&1)"
  rc=$?
  if [ "$rc" = 78 ] && [[ "$out" == *"tigervnc-standalone-server"* ]]; then
    pass host-session-no-tigervnc
  else
    fail host-session-no-tigervnc "exit $rc, output '$out'"
  fi

  # Xtigervnc is preferred. The VNC stub never creates the socket, so the
  # script must notice that it died instead of waiting out the 15 s.
  #
  # The stubs behave like the real binaries: TigerVNC 1.15 (Debian 13) prints
  # nothing for -version, and -help carries the banner and the parameter list.
  # dbus-launch only runs once the socket is up; the stub just has to exist.
  local vncbin="$TMP/session-vnc-bin"
  mkdir -p "$vncbin"
  printf '#!/bin/sh\nexit 0\n' >"$vncbin/startxfce4"
  printf '#!/bin/sh\nexit 0\n' >"$vncbin/dbus-launch"
  cat >"$vncbin/Xtigervnc" <<'SH'
#!/bin/sh
case "${1:-}" in
  -version) exit 0 ;;
  -help)
    echo "use: X [:<display>] [option]"
    echo "Xvnc TigerVNC 1.15.0 - built 2026-07-03"
    echo "  rfbunixpath      - Unix socket to listen for RFB protocol"
    exit 0
    ;;
esac
printf '%s\n' "$@" >"${XVNC_ARGS:-/dev/null}"
exit 1
SH
  cat >"$vncbin/Xvnc" <<'SH'
#!/bin/sh
case "${1:-}" in
  -version) exit 0 ;;
  -help)
    echo "Xvnc RealVNC Enterprise Edition"
    echo "  -rfbport          - TCP port for RFB protocol"
    exit 0
    ;;
esac
exit 1
SH
  chmod 0755 "$vncbin/startxfce4" "$vncbin/Xtigervnc" "$vncbin/Xvnc" "$vncbin/dbus-launch"

  # The stub records its argv: the hardening flags must reach the X server.
  local xvnc_args="$TMP/xvnc.args"
  local want_log
  want_log="$(sed -n "s/^  -Log '\\(.*\\)'\$/\\1/p" host/teknoir-desktop-session)"
  rm -f "$xvnc_args"
  out="$(env -i PATH="$vncbin:/usr/bin:/bin" HOME="$home" RUNTIME_DIRECTORY="$rundir" \
    XVNC_ARGS="$xvnc_args" "$bash_bin" host/teknoir-desktop-session 2>&1)"
  rc=$?
  if [ "$rc" = 1 ] && [[ "$out" == *"starting Xtigervnc on display :7"* ]] &&
    [[ "$out" == *"exited before creating"* ]] &&
    [ "$(grep -A1 -x -- -BlacklistTimeout "$xvnc_args" | tail -n1)" = 0 ] &&
    grep -qx -- -rfbunixpath "$xvnc_args" &&
    [ "$(grep -A1 -x -- -SecurityTypes "$xvnc_args" | tail -n1)" = None ] &&
    [ -n "$want_log" ] &&
    [ "$(grep -A1 -x -- -Log "$xvnc_args" | tail -n1)" = "$want_log" ] &&
    [[ "$want_log" == *"SConnection:stderr:0"* ]]; then
    pass host-session-prefers-xtigervnc
  else
    fail host-session-prefers-xtigervnc "exit $rc, output '$out', argv '$(tr '\n' ' ' <"$xvnc_args" 2>/dev/null)'"
  fi

  # An Xvnc that is not TigerVNC (RealVNC, TightVNC) is ignored: its binary
  # lacks -rfbunixpath.
  local realvncbin="$TMP/session-realvnc-bin"
  mkdir -p "$realvncbin"
  printf '#!/bin/sh\nexit 0\n' >"$realvncbin/startxfce4"
  printf '#!/bin/sh\nexit 0\n' >"$realvncbin/dbus-launch"
  cat >"$realvncbin/Xvnc" <<'SH'
#!/bin/sh
case "${1:-}" in
  -version) exit 0 ;;
  -help)
    echo "Xvnc RealVNC Enterprise Edition"
    echo "  -rfbport          - TCP port for RFB protocol"
    exit 0
    ;;
esac
exit 1
SH
  chmod 0755 "$realvncbin/startxfce4" "$realvncbin/Xvnc" "$realvncbin/dbus-launch"

  out="$(env -i PATH="$realvncbin:/usr/bin:/bin" HOME="$home" RUNTIME_DIRECTORY="$rundir" \
    "$bash_bin" host/teknoir-desktop-session 2>&1)"
  rc=$?
  if [ "$rc" = 78 ] && [[ "$out" == *"ignoring Xvnc: not a TigerVNC server"* ]] &&
    [[ "$out" == *"tigervnc-standalone-server"* ]]; then
    pass host-session-ignores-realvnc
  else
    fail host-session-ignores-realvnc "exit $rc, output '$out'"
  fi

  # Fedora/RHEL ship TigerVNC as Xvnc only. Its -version is silent (as on
  # 1.15) and -help carries the banner and rfbunixpath, so it must be taken.
  local xvnconlybin="$TMP/session-xvnc-bin"
  mkdir -p "$xvnconlybin"
  printf '#!/bin/sh\nexit 0\n' >"$xvnconlybin/startxfce4"
  printf '#!/bin/sh\nexit 0\n' >"$xvnconlybin/dbus-launch"
  cat >"$xvnconlybin/Xvnc" <<'SH'
#!/bin/sh
case "${1:-}" in
  -version) exit 0 ;;
  -help)
    echo "use: X [:<display>] [option]"
    echo "Xvnc TigerVNC 1.15.0 - built 2026-07-03"
    echo "  rfbunixpath      - Unix socket to listen for RFB protocol"
    exit 0
    ;;
esac
exit 1
SH
  chmod 0755 "$xvnconlybin/startxfce4" "$xvnconlybin/Xvnc" "$xvnconlybin/dbus-launch"

  out="$(env -i PATH="$xvnconlybin:/usr/bin:/bin" HOME="$home" RUNTIME_DIRECTORY="$rundir" \
    "$bash_bin" host/teknoir-desktop-session 2>&1)"
  rc=$?
  if [ "$rc" = 1 ] && [[ "$out" == *"starting Xvnc on display :7"* ]]; then
    pass host-session-tigervnc-xvnc-only
  else
    fail host-session-tigervnc-xvnc-only "exit $rc, output '$out'"
  fi

  # A session and TigerVNC but no xauth: exit 78 (not the 127 that
  # Restart=always would retry every 5 s) and name the package.
  local noxauthbin="$TMP/session-noxauth-bin"
  mkdir -p "$noxauthbin"
  ln -sf "$(command -v mkdir)" "$noxauthbin/mkdir"
  cp "$vncbin/startxfce4" "$vncbin/Xtigervnc" "$vncbin/dbus-launch" "$noxauthbin/"
  out="$(env -i PATH="$noxauthbin" HOME="$home" RUNTIME_DIRECTORY="$rundir" \
    "$bash_bin" host/teknoir-desktop-session 2>&1)"
  rc=$?
  if [ "$rc" = 78 ] && [[ "$out" == *"install xauth"* ]]; then
    pass host-session-no-xauth
  else
    fail host-session-no-xauth "exit $rc, output '$out'"
  fi

  # The same without dbus-launch (xauth stubbed): exit 78, install dbus-x11.
  rm -f "$noxauthbin/dbus-launch"
  printf '#!/bin/sh\nexit 0\n' >"$noxauthbin/xauth"
  chmod 0755 "$noxauthbin/xauth"
  out="$(env -i PATH="$noxauthbin" HOME="$home" RUNTIME_DIRECTORY="$rundir" \
    "$bash_bin" host/teknoir-desktop-session 2>&1)"
  rc=$?
  if [ "$rc" = 78 ] && [[ "$out" == *"install dbus-x11"* ]]; then
    pass host-session-no-dbus-launch
  else
    fail host-session-no-dbus-launch "exit $rc, output '$out'"
  fi

  # The X display's cookie is created before Xvnc starts, mode 0600 and out of
  # RUNDIR.
  local xauth="$home/.teknoir-desktop.Xauthority"
  if [ -f "$xauth" ] && [ -s "$xauth" ] && [ "$(stat -c %a "$xauth")" = 600 ] &&
    [ ! -e "$rundir/.teknoir-desktop.Xauthority" ]; then
    pass host-session-xauthority
  else
    fail host-session-xauthority "no 0600 cookie at $xauth"
  fi
}

# --- index.html redirect ----------------------------------------------------

test_index_redirect() {
  if ! command -v node >/dev/null 2>&1; then
    skip index-redirect "node is not on PATH"
    return
  fi

  # Pull the inline script out of the page.
  if ! python3 -I - "$INDEX" "$TMP/index.js" <<'PY'
import re
import sys

source, dest = sys.argv[1], sys.argv[2]
with open(source, encoding="utf-8") as fh:
    html = fh.read()
match = re.search(r"<script>(.*?)</script>", html, re.S)
if not match:
    sys.exit("no inline <script> in %s" % source)
with open(dest, "w", encoding="utf-8") as fh:
    fh.write(match.group(1))
PY
  then
    fail index-redirect "could not extract the inline script"
    return
  fi

  if node - "$TMP/index.js" >"$TMP/index.out" 2>&1 <<'JS'
const fs = require("fs");
const vm = require("vm");

const code = fs.readFileSync(process.argv[2], "utf8");

function runTarget(search) {
  let target = null;
  const window = {
    location: {
      search: search,
      replace(value) {
        target = value;
      },
    },
  };
  const context = vm.createContext({ window, URLSearchParams });
  vm.runInContext(code, context, { timeout: 2000 });
  return target;
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

// The defaults fill in what the user did not pass.
const plain = new URL(runTarget(""), "http://desktop/").searchParams;
assert(plain.get("autoconnect") === "1", "autoconnect default missing");
assert(plain.get("reconnect") === "1", "reconnect default missing");
assert(plain.get("resize") === "remote", "resize default missing");
assert(plain.get("path") === "websockify", "path default missing");

// A parameter the user came with is kept.
const viewOnly = new URL(runTarget("?view_only=1"), "http://desktop/").searchParams;
assert(viewOnly.get("view_only") === "1", "view_only was dropped");

// ... and the user can override a default.
const scaled = new URL(runTarget("?resize=scale"), "http://desktop/").searchParams;
assert(scaled.get("resize") === "scale", "resize=scale was overwritten");
assert(scaled.get("autoconnect") === "1", "defaults lost when a param is given");

// The connection target cannot come from the URL: a link to the real desktop
// must not be able to point the client at another server.
const evil = new URL(
  runTarget("?host=evil.example&path=//evil.example/x&view_only=1"),
  "http://desktop/").searchParams;
assert(evil.get("path") === "websockify", "path from the URL was kept: " + evil.get("path"));
assert(!evil.has("host"), "host from the URL was kept");
assert(evil.get("view_only") === "1", "view_only was dropped");

console.log("ok");
JS
  then
    pass index-redirect
  else
    fail index-redirect "$(head -20 "$TMP/index.out" | tr '\n' '|')"
  fi
}

# --- healthcheck against stand-in servers -----------------------------------

free_port() {
  python3 -I -c '
import socket
sock = socket.socket()
sock.bind(("127.0.0.1", 0))
print(sock.getsockname()[1])
sock.close()
'
}

wait_for_socket() {
  local sock="$1" waited=0
  while [ ! -S "$sock" ] && [ "$waited" -lt 100 ]; do
    sleep 0.1
    waited=$((waited + 1))
  done
}

# A stand-in VNC server that speaks the RFB 3.8 None handshake the way Xvnc
# does with -SecurityTypes None: server version, client version, one security
# type (None), the client's pick, SecurityResult 0. The probe completes this,
# so the stand-in must accept it instead of blasting at a closed socket.
make_rfb_standin() {
  cat >"$TMP/rfb-standin.py" <<'PY'
import os
import socket
import sys


def recv_exact(conn, count):
    data = b""
    while len(data) < count:
        chunk = conn.recv(count - len(data))
        if not chunk:
            raise EOFError("connection closed")
        data += chunk
    return data


path = sys.argv[1]
if os.path.exists(path):
    os.unlink(path)
server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind(path)
server.listen(8)
while True:
    conn, _ = server.accept()
    try:
        conn.sendall(b"RFB 003.008\n")
        recv_exact(conn, 12)
        conn.sendall(b"\x01\x01")
        recv_exact(conn, 1)
        conn.sendall(b"\x00\x00\x00\x00")
    except Exception:  # noqa: BLE001 - a probe may close early
        pass
    finally:
        conn.close()
PY
}

test_healthcheck() {
  local sock="$TMP/vnc.sock"
  local webroot="$TMP/web"
  mkdir -p "$webroot"
  echo "<html>fake noVNC</html>" >"$webroot/vnc.html"

  local port
  port="$(free_port)"
  if [ -z "$port" ]; then
    fail healthcheck-ok "could not find a free port"
    return
  fi

  # A VNC stand-in that completes the RFB 3.8 None handshake.
  make_rfb_standin
  python3 -I "$TMP/rfb-standin.py" "$sock" >"$TMP/rfb.out" 2>&1 &
  RFB_PID=$!

  python3 -I -m http.server "$port" --bind 127.0.0.1 --directory "$webroot" \
    >"$TMP/http.out" 2>&1 &
  HTTP_PID=$!

  # Wait for both stand-ins (up to 10 s each).
  wait_for_socket "$sock"
  local waited=0
  while ! python3 -I -c '
import http.client
import sys
try:
    conn = http.client.HTTPConnection("127.0.0.1", int(sys.argv[1]), timeout=1)
    conn.request("GET", "/vnc.html")
    ok = conn.getresponse().status == 200
except OSError:
    ok = False
sys.exit(0 if ok else 1)
' "$port" 2>/dev/null && [ "$waited" -lt 100 ]; do
    sleep 0.1
    waited=$((waited + 1))
  done

  if DESKTOP_MODE=virtual DESKTOP_SOCKET="$sock" DESKTOP_PORT="$port" \
    bash "$HEALTHCHECK" >"$TMP/health.out" 2>&1; then
    pass healthcheck-ok
  else
    fail healthcheck-ok "$(tr '\n' '|' <"$TMP/health.out")"
    test_healthcheck_fail "$sock" "$port"
    return
  fi

  test_healthcheck_fail "$sock" "$port"
}

# With the VNC stand-in gone the probe must fail and name the socket.
test_healthcheck_fail() {
  local sock="$1" port="$2"

  kill "$RFB_PID" 2>/dev/null || true
  wait "$RFB_PID" 2>/dev/null || true
  RFB_PID=""

  local waited=0
  while [ -S "$sock" ] && [ "$waited" -lt 50 ]; do
    sleep 0.1
    waited=$((waited + 1))
  done
  # The stand-in unlinks nothing on SIGTERM; remove the stale socket so the
  # probe sees a connection failure rather than a dropped greeting.
  rm -f "$sock"

  local out rc
  out="$(DESKTOP_MODE=virtual DESKTOP_SOCKET="$sock" DESKTOP_PORT="$port" \
    bash "$HEALTHCHECK" 2>&1)"
  rc=$?

  if [ "$rc" = 0 ]; then
    fail healthcheck-fail "exit 0, want 1"
    return
  fi
  if [ "$rc" != 1 ]; then
    fail healthcheck-fail "exit $rc, want 1"
    return
  fi
  case "$out" in
    *"$sock"*)
      pass healthcheck-fail
      ;;
    *)
      fail healthcheck-fail "message does not name the socket: '$out'"
      ;;
  esac
}

# A web server that answers garbage: the probe must fail with one line naming
# the URL (an http.client.HTTPException, not a traceback).
test_healthcheck_bad_http() {
  local sock="$TMP/bad-vnc.sock" port out rc lines
  port="$(free_port)"
  if [ -z "$port" ]; then
    fail healthcheck-bad-http "could not find a free port"
    return
  fi

  make_rfb_standin
  python3 -I "$TMP/rfb-standin.py" "$sock" >/dev/null 2>&1 &
  BAD_RFB_PID=$!

  python3 -I - "$port" >/dev/null 2>&1 <<'PY' &
import socket
import sys

server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.1", int(sys.argv[1])))
server.listen(8)
while True:
    conn, _ = server.accept()
    try:
        conn.recv(1024)
        conn.sendall(b"garbage\r\n\r\n")
    finally:
        conn.close()
PY
  BAD_HTTP_PID=$!

  wait_for_socket "$sock"

  out="$(DESKTOP_MODE=virtual DESKTOP_SOCKET="$sock" DESKTOP_PORT="$port" \
    bash "$HEALTHCHECK" 2>&1)"
  rc=$?
  lines="$(printf '%s\n' "$out" | wc -l)"

  if [ "$rc" = 1 ] && [ "$lines" = 1 ] &&
    [[ "$out" == *"http://127.0.0.1:$port/vnc.html"* ]] &&
    [[ "$out" != *Traceback* ]]; then
    pass healthcheck-bad-http
  else
    fail healthcheck-bad-http "exit $rc, $lines lines, output '$out'"
  fi
}

# A blacklisted Xvnc refuses clients with "Too many security failures" instead
# of the normal greeting. The probe must fail (a failed readiness check) and
# name the socket, in one line -- not report ok on an unusable desktop.
test_healthcheck_blacklisted() {
  cat >"$TMP/rfb-refuse.py" <<'PY'
import os
import socket
import struct
import sys
import time

mode, path = sys.argv[1], sys.argv[2]
if os.path.exists(path):
    os.unlink(path)
server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind(path)
server.listen(8)
reason = b"Too many security failures"
while True:
    conn, _ = server.accept()
    try:
        if mode == "3.3":
            conn.sendall(b"RFB 003.003\n")
            conn.sendall(b"\x00\x00\x00\x00")
        else:
            conn.sendall(b"RFB 003.008\n")
            conn.recv(12)
            conn.sendall(b"\x00")  # no security types: refused
        conn.sendall(struct.pack(">I", len(reason)) + reason)
        time.sleep(0.2)
    except OSError:
        pass
    finally:
        conn.close()
PY

  local mode sock out rc lines port webroot="$TMP/refuse-web"
  mkdir -p "$webroot"
  echo "<html>fake noVNC</html>" >"$webroot/vnc.html"
  port="$(free_port)"
  if [ -z "$port" ]; then
    fail healthcheck-refused-3.3 "could not find a free port"
    return
  fi
  # The web side is up, so a failure below can only come from the VNC side.
  python3 -I -m http.server "$port" --bind 127.0.0.1 --directory "$webroot" \
    >"$TMP/refuse-http.out" 2>&1 &
  REFUSE_HTTP_PID=$!

  for mode in 3.3 3.8; do
    sock="$TMP/refuse-$mode.sock"
    python3 -I "$TMP/rfb-refuse.py" "$mode" "$sock" >/dev/null 2>&1 &
    REFUSE_PID=$!
    wait_for_socket "$sock"

    out="$(DESKTOP_MODE=virtual DESKTOP_SOCKET="$sock" DESKTOP_PORT="$port" \
      bash "$HEALTHCHECK" 2>&1)"
    rc=$?
    lines="$(printf '%s\n' "$out" | wc -l)"

    kill "$REFUSE_PID" 2>/dev/null || true
    wait "$REFUSE_PID" 2>/dev/null || true
    REFUSE_PID=""
    rm -f "$sock"

    # 3.3: Xvnc refuses before the greeting is negotiated. 3.8: it offers no
    # security type and sends "Too many security failures" as the reason; the
    # probe must surface that reason, not just fail.
    local name="healthcheck-refused-$mode" want=""
    [ "$mode" = 3.8 ] && want="Too many security failures"
    if [ "$rc" = 1 ] && [ "$lines" = 1 ] && [[ "$out" == *"$sock"* ]] &&
      [[ "$out" == *"$want"* ]] && [[ "$out" != *Traceback* ]]; then
      pass "$name"
    else
      fail "$name" "exit $rc, $lines lines, output '$out'"
    fi
  done

  kill "$REFUSE_HTTP_PID" 2>/dev/null || true
  wait "$REFUSE_HTTP_PID" 2>/dev/null || true
  REFUSE_HTTP_PID=""
}

# --- run --------------------------------------------------------------------

test_shellcheck
test_hadolint
test_chromium_policy_json
test_xfconf_xml
test_seccomp_profile
test_novnc_extra
test_dockerfile_dev_shm
test_entrypoint_vectors
test_browser_wrapper
test_browser_live
test_desktop_entries
test_manifests
test_host_unit
test_host_session
test_index_redirect
test_healthcheck
test_healthcheck_bad_http
test_healthcheck_blacklisted

printf '\n%d passed, %d failed, %d skipped\n' "$passed" "$failed" "$skipped"
if [ "$failed" -ne 0 ]; then
  exit 1
fi
