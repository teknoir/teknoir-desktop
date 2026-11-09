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
NOTICE_JS="rootfs/opt/novnc-extra/teknoir-notice.js"

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
  for f in rootfs/usr/local/bin/* rootfs-agent/usr/local/bin/* host/* test/*.sh; do
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

  # The notice banner script: it must exist and parse. Its behaviour is
  # test_notice_script below; this only catches a file that is not there.
  if [ ! -f "$NOTICE_JS" ]; then
    fail novnc-notice-script "$NOTICE_JS is missing"
  elif ! command -v node >/dev/null 2>&1; then
    skip novnc-notice-script "node is not on PATH"
  elif node --check "$NOTICE_JS" >"$TMP/notice-syntax.out" 2>&1; then
    pass novnc-notice-script
  else
    fail novnc-notice-script "$(tr '\n' '|' <"$TMP/notice-syntax.out")"
  fi

  # vnc.html declares no charset and websockify sends none, so Chrome decodes
  # this classic script as windows-1252: any non-ASCII byte is mojibake.
  if python3 -I -c 'import sys; open(sys.argv[1], "rb").read().decode("ascii")' "$NOTICE_JS" >"$TMP/notice-ascii.out" 2>&1; then
    pass novnc-notice-ascii
  else
    fail novnc-notice-ascii "$NOTICE_JS is not pure ASCII (use \\u escapes)"
  fi

  # The Dockerfile puts the script in the noVNC tree, loads it from vnc.html
  # before </head>, checks that the insert happened (the build fails when
  # </head> is not in the file), and symlinks the one notice file next to the
  # page. Exactly one file, never the directory: /run/desktop also holds
  # Xauthority and vnc.sock.
  problems=""
  want='cp /opt/novnc-extra/teknoir-notice.js /opt/novnc/teknoir-notice.js'
  grep -qF "$want" Dockerfile || problems+="Dockerfile does not '$want'; "
  want='ln -s /run/desktop/notice.json /opt/novnc/teknoir-notice.json'
  grep -qF "$want" Dockerfile || problems+="Dockerfile does not '$want'; "
  # Every ln in the Dockerfile, exactly: any other link (a /run/desktop
  # directory link however spelled, /run, a relative target, other flags)
  # fails here and has to be reviewed. COPY rootfs/ / keeps symlinks, so
  # rootfs/ must have none.
  local lns want_lns
  lns="$(grep -vE '^[[:space:]]*#' Dockerfile \
    | grep -E '(^|[[:space:];&|(/])ln([[:space:]]|$)' \
    | sed -E 's/^[[:space:]]*(&&[[:space:]]*)?//; s/[[:space:]]*\\$//')"
  want_lns=$'ln -s /run/desktop/notice.json /opt/novnc/teknoir-notice.json\nln -s /usr/bin/Xtigervnc /usr/local/bin/Xvnc'
  # ... and the agent stage's, the versioned terminal UI's /usr/local/bin entry.
  want_lns+=$'\nln -s /opt/claude/${CLAUDE_VERSION}/claude /usr/local/bin/claude'
  if [ "$lns" != "$want_lns" ]; then
    problems+="the Dockerfile's ln commands are not exactly the notice and Xvnc links: '$(printf '%s' "$lns" | tr '\n' ';')'; "
  fi
  if [ -n "$(find rootfs -type l -print -quit)" ]; then
    problems+="rootfs/ contains symlinks: $(find rootfs -type l | tr '\n' ' '); "
  fi
  # The script URL carries index.html's cache key "v": bumping v must also
  # change the script's URL, or a browser keeps running a cached old script
  # under a new vnc.html.
  local page_v
  page_v="$(sed -n 's/.*"v": "\([0-9][0-9]*\)".*/\1/p' rootfs/opt/novnc-extra/index.html)"
  [ -n "$page_v" ] || problems+="index.html has no \"v\" default; "
  # ... and both static URLs (the meta refresh and the Continue link) carry
  # the same number, so the page and the script tag cannot drift apart.
  local static_n static_v
  static_n="$(grep -o '&amp;v=[0-9][0-9]*' rootfs/opt/novnc-extra/index.html | wc -l)"
  static_v="$(grep -o '&amp;v=[0-9][0-9]*' rootfs/opt/novnc-extra/index.html | sort -u | tr '\n' ' ')"
  if [ "$static_n" != 2 ] || [ "$static_v" != "&amp;v=${page_v} " ]; then
    problems+="index.html's two static URLs do not both carry v=${page_v} (found '$static_v', $static_n of them); "
  fi
  want="s#</head>#<script src=\"teknoir-notice.js?v=${page_v}\" defer></script></head>#"
  grep -qF "$want" Dockerfile || problems+="Dockerfile does not insert the script tag with v=${page_v} before </head>; "
  want="grep -qF '<script src=\"teknoir-notice.js?v=${page_v}\" defer></script>' /opt/novnc/vnc.html"
  grep -qF "$want" Dockerfile || problems+="Dockerfile does not check the vnc.html insert; "
  local sed_line check_line
  sed_line="$(grep -nF 's#</head>#<script src="teknoir-notice.js?v=' Dockerfile | cut -d: -f1)"
  check_line="$(grep -nF "$want" Dockerfile | cut -d: -f1)"
  if [ -z "$sed_line" ] || [ -z "$check_line" ] || [ "$sed_line" -ge "$check_line" ]; then
    problems+="the vnc.html insert is not checked after the sed; "
  fi
  # The re-fetch on connect watches the noVNC_connected class, and three
  # comments rely on this build check: without it a noVNC upgrade that renames
  # the class silently kills the re-fetch.
  want="grep -qF 'classList.add(\"noVNC_connected\")' /opt/novnc/app/ui.js"
  grep -qF "$want" Dockerfile || problems+="Dockerfile does not check that noVNC still sets noVNC_connected; "
  if [ -z "$problems" ]; then
    pass dockerfile-notice
  else
    fail dockerfile-notice "$problems"
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

# --- the shared-desktop notice ----------------------------------------------

# The locale's name as locale -a prints it on this host: glibc says "C.utf8"
# and "en_US.utf8" for C.UTF-8 and en_US.UTF-8.
locale_available() {
  local want
  want="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | tr -d '-')"
  locale -a 2>/dev/null | tr '[:upper:]' '[:lower:]' | tr -d '-' | grep -qx "$want"
}

# The notice (README "Notice banner") is one line in the dry-run output. The
# vector error-notice-control.txt carries a raw ESC byte; an "ENV: K=V ..."
# line is split with read -a on spaces, tabs and newlines, so those (and
# spaces inside a notice) are tested here instead.
test_notice() {
  local out err rc line dir="$TMP/notice-dry"
  mkdir -p "$dir"

  # Unset: nothing is added (the virtual-defaults vector already pins the rest
  # of the output byte for byte).
  out="$(env -i PATH="$TEST_PATH" HOME=/home/desktop DESKTOP_DRY_RUN=1 \
    bash "$ENTRYPOINT" 2>/dev/null)"
  rc=$?
  local unset_out="$out"
  if [ "$rc" = 0 ] && ! printf '%s\n' "$out" | grep -q '^notice:'; then
    pass notice-unset
  else
    fail notice-unset "a notice line appeared without DESKTOP_NOTICE"
  fi

  # Trimmed, non-ASCII kept as characters, markup kept literally.
  out="$(env -i PATH="$TEST_PATH" HOME=/home/desktop DESKTOP_DRY_RUN=1 \
    DESKTOP_NOTICE='  Hej då, scout <b>bot</b>  ' bash "$ENTRYPOINT" 2>/dev/null)"
  line="$(printf '%s\n' "$out" | sed -n 's/^notice: //p')"
  if [ "$(printf '%s\n' "$out" | grep -c '^notice: ')" = 1 ] &&
    [ "$line" = '{"text": "Hej då, scout <b>bot</b>"}' ] &&
    [ "$(printf '%s\n' "$out" | sed '$d')" = "$unset_out" ] &&
    [ "$(printf '%s\n' "$out" | tail -n 1)" = 'notice: {"text": "Hej då, scout <b>bot</b>"}' ]; then
    pass notice-dry-run-trimmed
  else
    fail notice-dry-run-trimmed "notice line '$line'"
  fi

  # 300 characters, each one two bytes in UTF-8: accepted, so the count is of
  # characters and not of bytes.
  local text300 text301
  text300="$(printf 'å%.0s' {1..300})"
  text301="${text300}å"
  out="$(env -i PATH="$TEST_PATH" HOME=/home/desktop DESKTOP_DRY_RUN=1 \
    DESKTOP_NOTICE="$text300" bash "$ENTRYPOINT" 2>/dev/null)"
  line="$(printf '%s\n' "$out" | sed -n 's/^notice: //p')"
  if [ "$(printf '%s' "$text300" | wc -c)" -gt 300 ] &&
    python3 -I -c '
import json, sys
sys.exit(0 if json.loads(sys.argv[1])["text"] == sys.argv[2] else 1)
' "$line" "$text300" 2>/dev/null; then
    pass notice-length-300
  else
    fail notice-length-300 "the 300-character notice was not printed"
  fi

  out="$(env -i PATH="$TEST_PATH" HOME=/home/desktop DESKTOP_DRY_RUN=1 \
    DESKTOP_NOTICE="$text301" bash "$ENTRYPOINT" 2>"$dir/err")"
  rc=$?
  err="$(cat "$dir/err")"
  if [ "$rc" = 64 ] && [ "$err" = "desktop-entrypoint: invalid DESKTOP_NOTICE (at most 300 characters)" ]; then
    pass notice-length-301
  else
    fail notice-length-301 "exit $rc, stderr '$err'"
  fi

  # Control characters inside are refused, not only the whitespace ones: the
  # rule is nothing below U+0020 and no U+007F, plus the C1 controls and
  # U+2028/U+2029. The stderr is compared exactly, as in the vectors.
  local name value
  local -a ctl_names=(tab newline cr soh esc del)
  local -a ctl_values=($'a\tb' $'a\nb' $'a\rb' $'a\x01b' $'a\x1bb' $'a\x7fb')
  local i
  for i in "${!ctl_names[@]}"; do
    name="${ctl_names[$i]}"
    value="${ctl_values[$i]}"
    out="$(env -i PATH="$TEST_PATH" HOME=/home/desktop DESKTOP_DRY_RUN=1 \
      DESKTOP_NOTICE="$value" bash "$ENTRYPOINT" 2>"$dir/err")"
    rc=$?
    err="$(cat "$dir/err")"
    if [ "$rc" = 64 ] &&
      [ "$err" = "desktop-entrypoint: invalid DESKTOP_NOTICE (no control characters)" ]; then
      pass "notice-control-$name"
    else
      fail "notice-control-$name" "exit $rc, stderr '$err'"
    fi
  done

  # Values the C locale and a UTF-8 locale treat differently: C1 controls,
  # U+2028, invalid UTF-8 and a leading U+2028 (which a locale-sensitive trim
  # would remove). Each one must be refused the same way in both locales.
  local -a ref_names=(del soh c1 u2028 lead-u2028 not-utf8)
  local -a ref_values=($'a\x7fb' $'a\x01b' $'a\xc2\x85b' $'a\xe2\x80\xa8b' $'\xe2\x80\xa8ab' $'a\xffb')
  local -a ref_wants=(
    "no control characters" "no control characters" "no control characters"
    "no control characters" "no control characters" "not UTF-8"
  )
  local loc
  for loc in none C.UTF-8; do
    if [ "$loc" != none ] && ! locale_available "$loc"; then
      skip "notice-refused-all-$loc" "locale $loc is not installed on this host"
      continue
    fi
    for i in "${!ref_names[@]}"; do
      name="${ref_names[$i]}"
      value="${ref_values[$i]}"
      if [ "$loc" = none ]; then
        out="$(env -i PATH="$TEST_PATH" HOME=/home/desktop DESKTOP_DRY_RUN=1 \
          DESKTOP_NOTICE="$value" bash "$ENTRYPOINT" 2>"$dir/err")"
      else
        out="$(env -i PATH="$TEST_PATH" HOME=/home/desktop DESKTOP_DRY_RUN=1 \
          LC_ALL="$loc" DESKTOP_NOTICE="$value" bash "$ENTRYPOINT" 2>"$dir/err")"
      fi
      rc=$?
      err="$(cat "$dir/err")"
      if [ "$rc" = 64 ] &&
        [ "$err" = "desktop-entrypoint: invalid DESKTOP_NOTICE (${ref_wants[$i]})" ]; then
        pass "notice-refused-$name-$loc"
      else
        fail "notice-refused-$name-$loc" "exit $rc, stderr '$err'"
      fi
    done
  done

  # A very long value is refused at once: bash's pattern trim is quadratic,
  # and 100000 trailing spaces would hold the start for over a minute.
  local long
  long="a$(printf '%*s' 100000 '')"
  out="$(timeout 10 env -i PATH="$TEST_PATH" HOME=/home/desktop DESKTOP_DRY_RUN=1 \
    DESKTOP_NOTICE="$long" bash "$ENTRYPOINT" 2>"$dir/err")"
  rc=$?
  err="$(cat "$dir/err")"
  if [ "$rc" = 64 ] && [ "$err" = "desktop-entrypoint: invalid DESKTOP_NOTICE (at most 300 characters)" ]; then
    pass notice-long-refused-fast
  else
    fail notice-long-refused-fast "exit $rc (124 = timed out), stderr '$err'"
  fi

  # The bound is exact, as the README says: 4096 bytes are still trimmed,
  # 4097 bytes are refused untrimmed.
  local at_bound
  at_bound="a$(printf '%*s' 4095 '')"
  out="$(env -i PATH="$TEST_PATH" HOME=/home/desktop DESKTOP_DRY_RUN=1 \
    DESKTOP_NOTICE="$at_bound" bash "$ENTRYPOINT" 2>"$dir/err")"
  rc=$?
  if [ "$rc" = 0 ] && [ "$(printf '%s\n' "$out" | grep '^notice:')" = 'notice: {"text": "a"}' ]; then
    pass notice-bound-4096-trimmed
  else
    fail notice-bound-4096-trimmed "exit $rc, stderr '$(cat "$dir/err")'"
  fi
  out="$(env -i PATH="$TEST_PATH" HOME=/home/desktop DESKTOP_DRY_RUN=1 \
    DESKTOP_NOTICE="$at_bound " bash "$ENTRYPOINT" 2>"$dir/err")"
  rc=$?
  err="$(cat "$dir/err")"
  if [ "$rc" = 64 ] && [ "$err" = "desktop-entrypoint: invalid DESKTOP_NOTICE (at most 300 characters)" ]; then
    pass notice-bound-4097-refused
  else
    fail notice-bound-4097-refused "exit $rc, stderr '$err'"
  fi

  # Whitespace only counts as unset, not as a one-space notice.
  out="$(env -i PATH="$TEST_PATH" HOME=/home/desktop DESKTOP_DRY_RUN=1 \
    DESKTOP_NOTICE='    ' bash "$ENTRYPOINT" 2>/dev/null)"
  rc=$?
  if [ "$rc" = 0 ] && ! printf '%s\n' "$out" | grep -q '^notice:'; then
    pass notice-whitespace-unset
  else
    fail notice-whitespace-unset "exit $rc, output '$out'"
  fi

  # Host mode has no notice file; it says so once and carries on.
  out="$(env -i PATH="$TEST_PATH" HOME=/home/desktop DESKTOP_DRY_RUN=1 \
    DESKTOP_MODE=host DESKTOP_NOTICE='shared desktop' bash "$ENTRYPOINT" 2>"$dir/err")"
  rc=$?
  err="$(cat "$dir/err")"
  if [ "$rc" = 0 ] && [ "$(printf '%s\n' "$err" | grep -c 'DESKTOP_NOTICE is ignored in host mode')" = 1 ] &&
    ! printf '%s\n' "$out" | grep -q '^notice:'; then
    pass notice-host-ignored
  else
    fail notice-host-ignored "exit $rc, stderr '$err', stdout '$out'"
  fi

  # Host mode does not validate what it ignores: a tab or 301 characters are
  # not an error there.
  for name in tab long; do
    if [ "$name" = tab ]; then value=$'a\tb'; else value="$text301"; fi
    out="$(env -i PATH="$TEST_PATH" HOME=/home/desktop DESKTOP_DRY_RUN=1 \
      DESKTOP_MODE=host DESKTOP_NOTICE="$value" bash "$ENTRYPOINT" 2>"$dir/err")"
    rc=$?
    err="$(cat "$dir/err")"
    if [ "$rc" = 0 ] && [ "$err" = "desktop-entrypoint: DESKTOP_NOTICE is ignored in host mode" ] &&
      ! printf '%s\n' "$out" | grep -q '^notice:'; then
      pass "notice-host-invalid-ignored-$name"
    else
      fail "notice-host-invalid-ignored-$name" "exit $rc, stderr '$err', stdout '$out'"
    fi
  done
}

# One notice dry run under one locale. NAME is the test name, WANT is
# "unset", "json:<text>" (one notice line holding that text) or
# "refused:<message>" (exit 64 and that reason on stderr).
notice_locale_case() {
  local name="$1" want="$2" value="$3" loc="$4" out rc err line
  if [ "$loc" = none ]; then
    out="$(env -i PATH="$TEST_PATH" HOME=/home/desktop DESKTOP_DRY_RUN=1 \
      DESKTOP_NOTICE="$value" bash "$ENTRYPOINT" 2>"$TMP/notice-locale.err")"
  else
    out="$(env -i PATH="$TEST_PATH" HOME=/home/desktop DESKTOP_DRY_RUN=1 \
      LC_ALL="$loc" DESKTOP_NOTICE="$value" bash "$ENTRYPOINT" 2>"$TMP/notice-locale.err")"
  fi
  rc=$?
  err="$(cat "$TMP/notice-locale.err")"
  case "$want" in
    unset)
      if [ "$rc" = 0 ] && ! printf '%s\n' "$out" | grep -q '^notice:'; then
        pass "$name"
      else
        fail "$name" "exit $rc, a notice line appeared: '$out'"
      fi
      ;;
    json:*)
      line="$(printf '%s\n' "$out" | sed -n 's/^notice: //p')"
      if [ "$(printf '%s\n' "$out" | grep -c '^notice: ')" = 1 ] &&
        python3 -I -c '
import json, sys
sys.exit(0 if json.loads(sys.argv[1])["text"] == sys.argv[2] else 1)
' "$line" "${want#json:}" 2>/dev/null; then
        pass "$name"
      else
        fail "$name" "exit $rc, notice line '$line'"
      fi
      ;;
    refused:*)
      if [ "$rc" = 64 ] &&
        [ "$err" = "desktop-entrypoint: invalid DESKTOP_NOTICE (${want#refused:})" ]; then
        pass "$name"
      else
        fail "$name" "exit $rc, stderr '$err'"
      fi
      ;;
  esac
}

# The notice rules are the same in every locale, and that is not automatic: a
# bash [[:space:]]/[[:cntrl:]] test follows the locale, and the image runs
# en_US.UTF-8 while the suite runs under env -i (C). C.UTF-8 has the same
# character classes as the image's en_US.UTF-8. A locale this host does not
# have is skipped, not failed.
test_notice_locale() {
  local loc text300 text301
  text300="$(printf 'å%.0s' {1..300})"
  text301="${text300}å"
  for loc in none C.UTF-8 en_US.UTF-8; do
    if [ "$loc" != none ] && ! locale_available "$loc"; then
      skip "notice-locale-$loc" "locale $loc is not installed on this host"
      continue
    fi
    notice_locale_case "notice-locale-trim-$loc" "json:Hej då" '  Hej då  ' "$loc"
    notice_locale_case "notice-locale-length-300-$loc" "json:$text300" "$text300" "$loc"
    notice_locale_case "notice-locale-length-301-$loc" "refused:at most 300 characters" "$text301" "$loc"
    notice_locale_case "notice-locale-tab-$loc" "refused:no control characters" $'a\tb' "$loc"
    notice_locale_case "notice-locale-del-$loc" "refused:no control characters" $'a\x7fb' "$loc"
    notice_locale_case "notice-locale-nel-$loc" "refused:no control characters" $'a\xc2\x85b' "$loc"
    notice_locale_case "notice-locale-u0080-$loc" "refused:no control characters" $'a\xc2\x80b' "$loc"
    notice_locale_case "notice-locale-u2028-$loc" "refused:no control characters" $'a\xe2\x80\xa8b' "$loc"
    notice_locale_case "notice-locale-u2029-$loc" "refused:no control characters" $'a\xe2\x80\xa9b' "$loc"
    notice_locale_case "notice-locale-not-utf8-$loc" "refused:not UTF-8" $'a\xffb' "$loc"
    # The trim is ASCII only: U+3000 is not whitespace here, so it stays.
    notice_locale_case "notice-locale-lead-u3000-$loc" "json:"$'\xe3\x80\x80'"hello" $'\xe3\x80\x80hello' "$loc"
    notice_locale_case "notice-locale-only-u3000-$loc" "json:"$'\xe3\x80\x80\xe3\x80\x80' $'\xe3\x80\x80\xe3\x80\x80' "$loc"
    notice_locale_case "notice-locale-blank-unset-$loc" unset $' \t ' "$loc"
  done
}

# The real write path, without a dry run. The entrypoint writes the notice at
# the head of the virtual start section, then runs mkdir -p /tmp/.X11-unix and
# reads the X cookie with od. Stubs stop it there: od exits 97, mkdir only
# records its arguments in $stop/calls, and rm records its arguments and
# deletes only paths inside $dir, so the run creates, changes or deletes
# nothing outside $dir (not the host's /tmp/.X11-unix, an X lock or socket).
# The first three runs must end with exit 97 and exactly the one mkdir call. A
# host with /run/desktop is skipped anyway: the shell's own redirections (the
# Xauthority write) cannot be stubbed if a change ever moves them before od.
test_notice_file() {
  local dir="$TMP/notice-run" file="$TMP/notice-run/notice.json" rc inode
  local stop="$TMP/bin-stop"
  local stop_path="$stop:$TEST_PATH"
  if [ -e /run/desktop ]; then
    skip notice-file "/run/desktop exists here, and a run that got past the od stub would write its Xauthority"
    return
  fi
  mkdir -p "$dir" "$stop"
  printf '#!/bin/sh\nexit 97\n' >"$stop/od"
  cat >"$stop/mkdir" <<'SH'
#!/bin/sh
printf 'mkdir %s\n' "$*" >>"$(dirname "$0")/calls"
SH
  cat >"$stop/rm" <<SH
#!/bin/sh
printf 'rm %s\n' "\$*" >>"\$(dirname "\$0")/calls"
# Record only, except a path inside this test's own notice dir: write_notice
# removes its temp file there when the move fails, and the result must be
# visible. Nothing outside that dir (the host's X lock or socket) is ever
# removed by this stub: only one path component directly inside $dir.
for arg in "\$@"; do
  case "\$arg" in
    "$dir"/*/* | "$dir"/. | "$dir"/..) ;;
    "$dir"/?*) /bin/rm -f -- "\$arg" ;;
  esac
done
SH
  chmod 0755 "$stop/od" "$stop/mkdir" "$stop/rm"
  local want_calls="mkdir -p /tmp/.X11-unix"

  : >"$stop/calls"
  : >"$TMP/notice-run.out"

  env -i PATH="$stop_path" HOME=/home/desktop DESKTOP_NOTICE='Hej då, "scout"' \
    DESKTOP_NOTICE_FILE="$file" bash "$ENTRYPOINT" >/dev/null 2>"$TMP/notice-run.err"
  rc=$?
  if [ "$rc" = 97 ] && [ "$(cat "$stop/calls")" = "$want_calls" ] && python3 -I -c '
import json, sys
with open(sys.argv[1], encoding="utf-8") as fh:
    data = json.load(fh)
if data != {"text": "Hej då, \"scout\""}:
    sys.exit("content is %r" % (data,))
' "$file" >"$TMP/notice-run.out" 2>&1 &&
    [ "$(cat "$file")" = '{"text": "Hej då, \"scout\""}' ] &&
    [ "$(stat -c %a "$file")" = 644 ]; then
    pass notice-file-written
  else
    fail notice-file-written "exit $rc, calls '$(tr '\n' ';' <"$stop/calls")': $(tr '\n' '|' <"$TMP/notice-run.out") $(tr '\n' '|' <"$TMP/notice-run.err")"
  fi

  # A start with another notice replaces the file by a rename (a new inode),
  # never by rewriting it in place, and leaves no temp file next to it: the
  # temp file exists before the rename unlinks the old one, so the inode
  # always changes.
  inode="$(stat -c %i "$file" 2>/dev/null)"
  : >"$stop/calls"
  env -i PATH="$stop_path" HOME=/home/desktop DESKTOP_NOTICE='second' \
    DESKTOP_NOTICE_FILE="$file" bash "$ENTRYPOINT" >/dev/null 2>&1
  rc=$?
  if [ "$rc" = 97 ] && [ "$(cat "$stop/calls")" = "$want_calls" ] && [ -n "$inode" ] && [ "$(stat -c %i "$file" 2>/dev/null)" != "$inode" ] &&
    [ "$(cat "$file" 2>/dev/null)" = '{"text": "second"}' ] &&
    [ "$(find "$dir" -mindepth 1 -maxdepth 1 | wc -l)" = 1 ]; then
    pass notice-file-replaced
  else
    fail notice-file-replaced "exit $rc, calls '$(tr '\n' ';' <"$stop/calls")', inode $inode -> $(stat -c %i "$file" 2>/dev/null), content '$(cat "$file" 2>/dev/null)', files: $(find "$dir" -mindepth 1 | tr '\n' ' ')"
  fi

  # Unset on the next start (the emptyDir survives a container restart): the
  # file is written as {"text": ""} instead, so the page never gets a 404, and
  # no temp file is left behind.
  : >"$stop/calls"
  env -i PATH="$stop_path" HOME=/home/desktop \
    DESKTOP_NOTICE_FILE="$file" bash "$ENTRYPOINT" >/dev/null 2>"$TMP/notice-unset.err"
  rc=$?
  if [ "$rc" = 97 ] && [ "$(cat "$stop/calls")" = "$want_calls" ] && [ -f "$file" ] && [ "$(cat "$file")" = '{"text": ""}' ] &&
    [ "$(stat -c %a "$file")" = 644 ] &&
    [ "$(find "$dir" -mindepth 1 -maxdepth 1 | wc -l)" = 1 ]; then
    pass notice-file-cleared
  else
    fail notice-file-cleared "exit $rc, calls '$(tr '\n' ';' <"$stop/calls")', content '$(cat "$file" 2>/dev/null)', files: $(find "$dir" -mindepth 1 -maxdepth 1 -print | tr '\n' ' ')"
  fi

  # The emptyDir survives a restart, so the notice path may hold anything a
  # desktop user left there. A symlink to a directory is replaced, never
  # followed (plain mv -f would move the file into that directory and the page
  # would get a 404); a directory is refused loudly instead of swallowing the
  # file.
  local elsewhere="$TMP/notice-elsewhere"
  rm -f "$file"
  mkdir -p "$elsewhere"
  ln -s "$elsewhere" "$file"
  env -i PATH="$stop_path" HOME=/home/desktop DESKTOP_NOTICE='third' \
    DESKTOP_NOTICE_FILE="$file" bash "$ENTRYPOINT" >/dev/null 2>&1
  rc=$?
  if [ "$rc" = 97 ] && [ -f "$file" ] && [ ! -L "$file" ] &&
    [ "$(cat "$file")" = '{"text": "third"}' ] &&
    [ -z "$(find "$elsewhere" -mindepth 1 -print -quit)" ]; then
    pass notice-file-symlink-replaced
  else
    fail notice-file-symlink-replaced "exit $rc, $(find "$dir" "$elsewhere" -printf '%p %y; ')"
  fi
  rm -f "$file"
  mkdir "$file"
  env -i PATH="$stop_path" HOME=/home/desktop DESKTOP_NOTICE='fourth' \
    DESKTOP_NOTICE_FILE="$file" bash "$ENTRYPOINT" >/dev/null 2>"$TMP/notice-dir.err"
  rc=$?
  if [ "$rc" = 1 ] && grep -qF "cannot move the notice into $file" "$TMP/notice-dir.err" &&
    [ -z "$(find "$file" -mindepth 1 -print -quit)" ] &&
    [ "$(find "$dir" -mindepth 1 -maxdepth 1 | wc -l)" = 1 ]; then
    pass notice-file-dir-refused
  else
    fail notice-file-dir-refused "exit $rc, $(tr '\n' '|' <"$TMP/notice-dir.err") $(find "$dir" | tr '\n' ' ')"
  fi
  rm -rf "$file"

  # Host mode writes no file, even with a notice set. A stand-in socket ends
  # the wait for the host desktop at once, and a stub websockify that exits 97
  # ends the run there. The timeout turns a bypassed stub (a noexec $TMP on a
  # host that has websockify) into a failure instead of a hang.
  local hdir="$TMP/notice-host" hsock="$TMP/notice-host.sock"
  mkdir -p "$hdir"
  printf '#!/bin/sh\nexit 97\n' >"$stop/websockify"
  chmod 0755 "$stop/websockify"
  python3 -I -c 'import socket, sys; socket.socket(socket.AF_UNIX).bind(sys.argv[1])' "$hsock"
  timeout 30 env -i PATH="$stop_path" HOME=/home/desktop DESKTOP_MODE=host DESKTOP_SOCKET="$hsock" \
    DESKTOP_NOTICE='shared desktop' DESKTOP_NOTICE_FILE="$hdir/notice.json" \
    bash "$ENTRYPOINT" >/dev/null 2>"$TMP/notice-host.err"
  rc=$?
  if [ "$rc" = 97 ] && [ -z "$(find "$hdir" -mindepth 1 -print -quit)" ]; then
    pass notice-file-host-none
  else
    fail notice-file-host-none "exit $rc, files: $(find "$hdir" -mindepth 1 | tr '\n' ' ')"
  fi
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
// The cache key: websockify sends no Cache-Control, so a browser may hold an
// older vnc.html for a while. It has to be in the URL noVNC loads.
// Which number is test_novnc_extra's job: it checks that the defaults, the
// two static URLs and the Dockerfile script tag carry the same one.
assert(/^[0-9]+$/.test(plain.get("v") || ""), "cache key missing: " + plain.get("v"));

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

# --- the notice banner script -----------------------------------------------

# teknoir-notice.js runs in the real vnc.html, so it is checked here against a
# minimal fake document and fetch: the notice becomes a banner of text (never
# elements), nothing is logged, nothing leaks into the global scope, no HTML is
# parsed and focus never moves, and any odd file means no banner at all.
test_notice_script() {
  if ! command -v node >/dev/null 2>&1; then
    skip notice-script "node is not on PATH"
    return
  fi

  if node - "$NOTICE_JS" >"$TMP/notice-script.out" 2>&1 <<'JS'
const fs = require("fs");
const vm = require("vm");

const code = fs.readFileSync(process.argv[2], "utf8");

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

const failures = [];
process.on("unhandledRejection", (reason) => {
  failures.push("unhandled rejection: " + reason);
});

// Just enough DOM for the script: elements with children, attributes, style
// and listeners, a head, and a body with the page's own elements already in
// it. HTML writes are recorded and not performed, so an innerHTML call cannot
// hide as a silent no-op, and focus() is recorded so a focus grab is visible.
function makeDocument() {
  const created = [];
  const htmlWrites = [];
  const focused = [];
  function makeEl(tag) {
    return {
      set innerHTML(value) { htmlWrites.push(["innerHTML", value]); },
      get innerHTML() { return ""; },
      set outerHTML(value) { htmlWrites.push(["outerHTML", value]); },
      insertAdjacentHTML(where, value) { htmlWrites.push(["insertAdjacentHTML", where, value]); },
      focus() { focused.push(this); },
      get firstChild() { return this.children[0] || null; },
      get lastChild() { return this.children[this.children.length - 1] || null; },
      tagName: tag.toUpperCase(),
      children: [],
      style: { cssText: "" },
      attributes: {},
      id: "",
      title: "",
      textContent: "",
      parentNode: null,
      listeners: {},
      setAttribute(name, value) {
        this.attributes[name] = String(value);
      },
      getAttribute(name) {
        return this.attributes[name];
      },
      appendChild(child) {
        child.parentNode = this;
        this.children.push(child);
        return child;
      },
      insertBefore(child, ref) {
        child.parentNode = this;
        const at = this.children.indexOf(ref);
        if (at < 0) {
          this.children.push(child);
        } else {
          this.children.splice(at, 0, child);
        }
        return child;
      },
      removeChild(child) {
        const at = this.children.indexOf(child);
        if (at >= 0) {
          this.children.splice(at, 1);
        }
        child.parentNode = null;
        return child;
      },
      addEventListener(type, fn) {
        (this.listeners[type] = this.listeners[type] || []).push(fn);
      },
      dispatch(type, event) {
        (this.listeners[type] || []).forEach((fn) => fn(event));
      },
      click() {
        (this.listeners.click || []).forEach((fn) => fn({}));
      },
    };
  }

  const head = makeEl("head");
  const body = makeEl("body");
  body.appendChild(makeEl("div")); // the page's own UI

  function find(el, id) {
    if (el.id === id) {
      return el;
    }
    for (const child of el.children) {
      const hit = find(child, id);
      if (hit) {
        return hit;
      }
    }
    return null;
  }

  return {
    head,
    body,
    created,
    htmlWrites,
    focused,
    write(value) { htmlWrites.push(["write", value]); },
    writeln(value) { htmlWrites.push(["writeln", value]); },
    createElement(tag) {
      const el = makeEl(tag);
      created.push(el);
      return el;
    },
    getElementById(id) {
      return find(body, id);
    },
  };
}

// The script must not need anything beyond document, fetch and console: a
// missing global would show up as an error, not as a passed test.
function run(fetchImpl) {
  const doc = makeDocument();
  const logs = [];
  const spy = {
    log(...args) { logs.push(["log", ...args]); },
    info(...args) { logs.push(["info", ...args]); },
    warn(...args) { logs.push(["warn", ...args]); },
    error(...args) { logs.push(["error", ...args]); },
    debug(...args) { logs.push(["debug", ...args]); },
  };
  // The page runs the banner insert inside an animation frame (see below);
  // there is no frame loop here, so the callback runs as soon as it is
  // queued.
  const context = vm.createContext({
    document: doc,
    fetch: fetchImpl,
    console: spy,
    requestAnimationFrame: (fn) => {
      fn();
      return 0;
    },
  });
  const before = Object.keys(context).sort().join(",");
  vm.runInContext(code, context, { timeout: 2000 });
  const after = Object.keys(context).sort().join(",");
  assert(before === after, "the script leaked a global: " + after);
  return { doc, logs };
}

const tick = () => new Promise((resolve) => setTimeout(resolve, 20));
const json = (value) => () => Promise.resolve(value);

(async function () {
  // A 200 with text: one banner, the text as text, at the top of the body,
  // with a style that makes room for it and a close button that is an ASCII
  // escape.
  {
    let seen = null;
    const { doc, logs } = run((url, options) => {
      seen = { url, options };
      return Promise.resolve({
        ok: true,
        status: 200,
        json: json({ text: "<img src=x onerror=alert(1)>" }),
      });
    });
    await tick();

    assert(seen, "fetch was not called");
    assert(seen.url === "teknoir-notice.json", "fetched '" + seen.url + "'");
    assert(seen.options.cache === "no-store", "cache is not no-store");
    assert(seen.options.credentials === "same-origin", "credentials is not same-origin");

    const banner = doc.getElementById("teknoir_notice");
    assert(banner, "no banner for a 200 with text");
    assert(doc.body.children[0] === banner, "the banner is not the first child of body");
    assert(banner.getAttribute("role") === "status", "role is not status");
    assert(banner.title === "<img src=x onerror=alert(1)>", "title is not the notice");

    const label = doc.getElementById("teknoir_notice_text");
    assert(label, "the banner has no text element");
    assert(label.textContent === "<img src=x onerror=alert(1)>",
      "textContent is '" + label.textContent + "'");
    assert(!doc.created.some((el) => el.tagName === "IMG"),
      "an element was created from the markup");
    assert(doc.created.length === 4, doc.created.length + " elements created, want 4");

    // The banner is fixed and 24px high, so the page has to make room for it:
    // one <style> in <head> moves noVNC's container and status line down 24px
    // and shortens the container by the same 24px.
    const rooms = doc.head.children.filter((el) => el.tagName === "STYLE");
    assert(rooms.length === 1, rooms.length + " styles in head, want 1");
    // Compared exactly, spaces included: calc() needs the spaces around "-"
    // (the browser drops calc(100%-24px) as invalid, and the container keeps
    // its full height under the banner), and a later rule could undo a move.
    const room = rooms[0].textContent;
    assert(room === "#noVNC_container{position:relative;top:24px;height:calc(100% - 24px)}" +
      "#noVNC_status{top:24px}",
      "the style that makes room for the banner is '" + room + "'");
    assert(/(^|;)height:24px;/.test(banner.style.cssText) &&
      /(^|;)line-height:24px(;|$)/.test(banner.style.cssText),
      "the banner is not 24px high, the room the style makes: " + banner.style.cssText);
    // The bar and the room the style makes must be the same number, or the
    // banner covers the remote screen (taller bar) or leaves a gap (taller
    // room).
    const barRoom = /(^|;)height:([0-9]+)px;/.exec(banner.style.cssText);
    const pageRoom = /top:([0-9]+)px;height:calc\(100% - ([0-9]+)px\)/.exec(room);
    assert(barRoom && pageRoom && barRoom[2] === pageRoom[1] &&
      pageRoom[1] === pageRoom[2],
      "the banner height and the room the style makes differ: " +
        banner.style.cssText + " / " + rooms[0].textContent);

    // Below noVNC's status line (100) and fatal-error box (1000): the status
    // slides in over the banner, and a fatal error covers the whole page.
    assert(banner.style.cssText.includes("z-index:99;"),
      "the banner z-index is not 99: " + banner.style.cssText);
    assert(!banner.style.cssText.includes("2147483647"),
      "the banner uses the maximum z-index");

    const close = doc.created.find((el) => el.tagName === "BUTTON");
    assert(close, "no close button");
    assert(close.getAttribute("aria-label") === "Hide notice", "the close button has no label");
    assert(close.getAttribute("tabindex") === "-1", "the close button is in the tab order");
    // noVNC's input.css gives every <button> min-width:8em (128 px), bold
    // text and a 6 px radius: without the reset the x is a 128 px invisible
    // hit area that also cuts the text. It is a 24x24 target, like the bar.
    assert(/(^|;)min-width:0;/.test(close.style.cssText),
      "the close button keeps noVNC's button min-width: " + close.style.cssText);
    assert(/(^|;)width:24px;/.test(close.style.cssText) &&
      /(^|;)height:24px;/.test(close.style.cssText) &&
      /(^|;)font-weight:normal(;|$)/.test(close.style.cssText) &&
      /(^|;)border-radius:0(;|$)/.test(close.style.cssText),
      "the close button is not a 24x24 plain target: " + close.style.cssText);
    // The escape, not the literal: the page and the script are served without
    // a charset, so a raw byte would be mojibake. novnc-notice-ascii pins it.
    assert(close.textContent === "\u00d7",
      "the close button text is '" + close.textContent + "'");
    assert(logs.length === 0, "the script logged: " + JSON.stringify(logs));
    assert(doc.htmlWrites.length === 0, "HTML was written: " + JSON.stringify(doc.htmlWrites));
    assert(doc.focused.length === 0, "the script moved the focus");

    // A press anywhere on the banner (the x included) is cancelled, so the
    // click never moves keyboard focus off the VNC canvas.
    let prevented = 0;
    const event = { preventDefault() { prevented += 1; } };
    assert((banner.listeners.mousedown || []).length === 1,
      (banner.listeners.mousedown || []).length + " mousedown listeners on the banner, want 1");
    banner.dispatch("mousedown", event);
    assert((close.listeners.mousedown || []).length === 1,
      (close.listeners.mousedown || []).length + " mousedown listeners on the close button, want 1");
    close.dispatch("mousedown", event);
    assert(prevented === 2, "a mousedown on the banner would take focus from the VNC canvas");

    close.click();
    assert(!doc.getElementById("teknoir_notice"), "the close button did not hide the banner");
    assert(!doc.body.children.includes(banner), "the banner is still in the page");
    assert(doc.head.children.length === 0, "the room style is still in the page");
    // Closing is a click on the page: it must not move keyboard focus off the
    // canvas either, and nothing may take focus by itself.
    assert(doc.focused.length === 0, "closing the banner moved the focus");
    assert(!doc.created.some((el) => el.autofocus || "autofocus" in el.attributes),
      "an element has autofocus");
  }

  // With requestAnimationFrame the banner is inserted inside a frame
  // callback, not straight from the fetch: noVNC records its expected screen
  // size in a frame callback queued earlier, which must run first. The room
  // style is what shrinks noVNC's container, so it must wait for the frame
  // too. A connect while the frame is still pending (a background tab runs
  // no frames) must neither fetch again nor queue a second banner.
  {
    const frames = [];
    const doc = makeDocument();
    const classes = new Set();
    let observer = null;
    doc.documentElement = { classList: { contains: (c) => classes.has(c) } };
    class FakeObserver {
      constructor(fn) { this.fn = fn; observer = this; }
      observe() {}
    }
    let fetches = 0;
    const context = vm.createContext({
      document: doc,
      fetch: () => {
        fetches += 1;
        return Promise.resolve({ ok: true, status: 200, json: json({ text: "shared" }) });
      },
      console: {},
      MutationObserver: FakeObserver,
      requestAnimationFrame: (fn) => { frames.push(fn); return frames.length; },
    });
    vm.runInContext(code, context, { timeout: 2000 });
    await tick();
    assert(!doc.getElementById("teknoir_notice"), "the banner was inserted outside an animation frame");
    assert(doc.head.children.length === 0 && doc.created.length === 0,
      "the banner or its room style was built outside an animation frame");
    assert(frames.length === 1, frames.length + " frame callbacks queued, want 1");
    classes.add("noVNC_connected");
    observer.fn([]);
    await tick();
    assert(fetches === 1 && frames.length === 1,
      "a connect while the frame was pending fetched " + fetches + " times and queued " +
        frames.length + " frames, want 1 and 1");
    frames.shift()();
    assert(doc.body.children.filter((el) => el.id === "teknoir_notice").length === 1 &&
      doc.head.children.length === 1,
      "the frame callback did not insert exactly one banner and one style");
  }

  // A browser without requestAnimationFrame gets the banner straight away: the
  // fallback must insert it, not drop it.
  {
    const doc = makeDocument();
    const context = vm.createContext({
      document: doc,
      fetch: () => Promise.resolve({ ok: true, status: 200, json: json({ text: "shared" }) }),
      console: {},
    });
    vm.runInContext(code, context, { timeout: 2000 });
    await tick();
    assert(doc.getElementById("teknoir_notice"), "no banner without requestAnimationFrame");
  }

  // Two fetches can answer before the frame that inserts the banner (the
  // first one is still pending when noVNC connects). The banner is decided
  // before that frame, so there is still one banner and one style.
  {
    const frames = [];
    const doc = makeDocument();
    const classes = new Set();
    doc.documentElement = { classList: { contains: (c) => classes.has(c) } };
    let observer = null;
    class FakeObserver {
      constructor(fn) { this.fn = fn; observer = this; }
      observe() {}
    }
    const answers = [];
    const context = vm.createContext({
      document: doc,
      fetch: () => new Promise((resolve) => answers.push(resolve)),
      console: {},
      MutationObserver: FakeObserver,
      requestAnimationFrame: (fn) => { frames.push(fn); return frames.length; },
    });
    vm.runInContext(code, context, { timeout: 2000 });
    classes.add("noVNC_connected");
    observer.fn([]);
    assert(answers.length === 2, answers.length + " fetches before the first answer, want 2");
    answers.forEach((resolve) => resolve({ ok: true, status: 200, json: json({ text: "shared" }) }));
    await tick();
    frames.splice(0).forEach((fn) => fn());
    const banners = doc.body.children.filter((el) => el.id === "teknoir_notice");
    assert(banners.length === 1 && doc.head.children.length === 1,
      banners.length + " banners and " + doc.head.children.length +
        " styles for two answers in one frame, want 1 and 1");
  }

  // Anything wrong means no banner, no elements and nothing logged.
  const broken = [
    ["404", () => Promise.resolve({ ok: false, status: 404, json: json({ text: "not for a 404" }) })],
    ["500", () => Promise.resolve({ ok: false, status: 500, json: json({ text: "not for a 500" }) })],
    ["a network error", () => Promise.reject(new Error("offline"))],
    ["invalid JSON", () => Promise.resolve({ ok: true, status: 200, json: () => Promise.reject(new SyntaxError("bad")) })],
    ["a number as text", () => Promise.resolve({ ok: true, status: 200, json: json({ text: 5 }) })],
    ["blank text", () => Promise.resolve({ ok: true, status: 200, json: json({ text: "   " }) })],
    ["no text", () => Promise.resolve({ ok: true, status: 200, json: json({}) })],
    ["JSON null", () => Promise.resolve({ ok: true, status: 200, json: json(null) })],
  ];
  for (const [name, impl] of broken) {
    const { doc, logs } = run(impl);
    await tick();
    assert(!doc.getElementById("teknoir_notice"), "a banner appeared for " + name);
    assert(doc.created.length === 0, "an element was created for " + name);
    assert(logs.length === 0, "the script logged for " + name + ": " + JSON.stringify(logs));
    assert(doc.htmlWrites.length === 0, "HTML was written for " + name);
  }

  // A failed fetch is tried again whenever noVNC connects (the class
  // noVNC_connected appears on <html>), until a banner has been shown.
  function runObserved(responses) {
    const doc = makeDocument();
    const classes = new Set();
    let observer = null;
    doc.documentElement = {
      classList: { contains: (c) => classes.has(c) },
    };
    class FakeObserver {
      constructor(fn) { this.fn = fn; observer = this; }
      observe(target, options) { this.target = target; this.options = options; }
    }
    const calls = [];
    const fetchImpl = (url) => {
      calls.push(url);
      return responses.length ? responses.shift()() : Promise.reject(new Error("no more"));
    };
    const logs = [];
    const spy = {
      log(...args) { logs.push(["log", ...args]); },
      info(...args) { logs.push(["info", ...args]); },
      warn(...args) { logs.push(["warn", ...args]); },
      error(...args) { logs.push(["error", ...args]); },
      debug(...args) { logs.push(["debug", ...args]); },
    };
    const context = vm.createContext({
      document: doc,
      fetch: fetchImpl,
      console: spy,
      MutationObserver: FakeObserver,
    });
    vm.runInContext(code, context, { timeout: 2000 });
    const set = (on) => {
      if (on) {
        classes.add("noVNC_connected");
      } else {
        classes.delete("noVNC_connected");
      }
      observer.fn([]);
    };
    return { doc, calls, logs, set, observer: () => observer };
  }
  const okText = (text) => () => Promise.resolve({ ok: true, status: 200, json: json({ text }) });
  const status = (code) => () => Promise.resolve({ ok: false, status: code, json: json({}) });
  {
    const r = runObserved([status(503), okText("shared"), okText("again")]);
    await tick();
    assert(r.observer(), "no class observer");
    // noVNC 1.7.0 sets noVNC_connected on <html> (app/ui.js updateVisualState):
    // an observer on any other node would never fire.
    assert(r.observer().target === r.doc.documentElement,
      "the observer does not watch <html>, where noVNC sets noVNC_connected");
    assert(r.observer().options.attributeFilter[0] === "class", "the observer watches something else");
    assert(!r.doc.getElementById("teknoir_notice"), "a banner appeared for a 503");
    r.set(true);
    await tick();
    assert(r.calls.length === 2, "connect after a 503 fetched " + r.calls.length + " times, want 2");
    assert(r.doc.getElementById("teknoir_notice"), "no banner after the connect");
    r.doc.created.find((el) => el.tagName === "BUTTON").click();
    r.set(false);
    r.set(true);
    await tick();
    assert(r.calls.length === 2, "a reconnect after a shown banner fetched again");
    assert(!r.doc.getElementById("teknoir_notice"), "a closed banner came back on reconnect");
    assert(r.logs.length === 0, "logged: " + JSON.stringify(r.logs));
  }
  {
    // Class changes that are not a new connect do not fetch.
    const r = runObserved([status(404), status(404), status(404)]);
    await tick();
    r.set(true);
    await tick();
    r.observer().fn([]);
    await tick();
    assert(r.calls.length === 2, "class churn while connected fetched " + r.calls.length + " times, want 2");
    assert(!r.doc.getElementById("teknoir_notice"), "a banner appeared for a 404");
    assert(r.logs.length === 0, "logged: " + JSON.stringify(r.logs));
  }

  // Top-level let/const/class are global names too, but not properties of the
  // global object: a second run in the same context throws on them.
  {
    const context = vm.createContext({
      document: makeDocument(),
      fetch: () => new Promise(() => {}),
      console: {},
    });
    vm.runInContext(code, context, { timeout: 2000 });
    try {
      vm.runInContext(code, context, { timeout: 2000 });
    } catch (err) {
      throw new Error("the script declares a top-level name: " + err.message);
    }
  }

  assert(failures.length === 0, failures.join("; "));
  console.log("ok");
})().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
JS
  then
    pass notice-script
  else
    fail notice-script "$(head -20 "$TMP/notice-script.out" | tr '\n' '|')"
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

# --- the agent image --------------------------------------------------------

AGENT="rootfs-agent/usr/local/bin/teknoirbot-agent"
# Fixture data, not a credential: no key of this shape exists anywhere.
AGENT_KEY='tbk1.teknoir-demo.scout.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
AGENT_API='https://tb-api.teknoir.cloud:8085/api/device/bot/v1'

# The terminal UI, tnctl and curl as stubs. None of the three can run here (one
# is a vendored binary in the image, the other two talk to the platform), and
# each records what the launcher gave it. The token is recorded as set/unset
# only, never by value, so a leaked key would show up in the argv log instead.
agent_stubs() {
  local dir="$TMP/agent-bin"
  mkdir -p "$dir"
  cat >"$dir/claude" <<'SH'
#!/bin/sh
{
  printf 'CWD %s\n' "$PWD"
  for arg in "$@"; do printf 'ARG %s\n' "$arg"; done
  printf 'BASE_URL %s\n' "${ANTHROPIC_BASE_URL-<unset>}"
  if [ -n "${ANTHROPIC_AUTH_TOKEN+x}" ]; then
    printf 'AUTH_TOKEN set\n'
  else
    printf 'AUTH_TOKEN unset\n'
  fi
  printf 'MODEL %s\n' "${ANTHROPIC_MODEL-<unset>}"
  printf 'CONFIG_DIR %s\n' "${CLAUDE_CONFIG_DIR-<unset>}"
  printf 'NONESSENTIAL %s\n' "${CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC-<unset>}"
  printf 'AUTOUPDATER %s\n' "${DISABLE_AUTOUPDATER-<unset>}"
  if [ -n "${ANTHROPIC_API_KEY+x}" ]; then
    printf 'API_KEY set\n'
  else
    printf 'API_KEY unset\n'
  fi
  if [ -n "${CLAUDE_CONFIG_DIR-}" ] && [ -d "${CLAUDE_CONFIG_DIR-}" ]; then
    printf 'SESSION %s\n' "$(stat -c %a "$CLAUDE_CONFIG_DIR")"
  else
    printf 'SESSION none\n'
  fi
} >>"$CLAUDE_LOG"
exit "${CLAUDE_EXIT:-0}"
SH
  cat >"$dir/tnctl" <<'SH'
#!/bin/sh
if [ "${TNCTL_FAIL:-0}" = 1 ]; then
  printf 'Error: the bot API answered 401 for this key\n' >&2
  exit 1
fi
printf '%s\n' '{"mode":"bot","bot":{"namespace":"teknoir-demo","name":"scout","unit":"field-team","access":"creator"},"creator":{"email":"claude-agent@teknoir.cloud"},"domain":"teknoir.cloud"}'
SH
  # The real curl with -w '\n%{http_code}': the body, a newline, the status.
  cat >"$dir/curl" <<'SH'
#!/bin/sh
{
  printf 'CURL'
  for arg in "$@"; do printf ' %s' "$arg"; done
  printf '\n'
} >>"$CURL_LOG"
printf '%s\n%s' "$CURL_BODY" "$CURL_STATUS"
exit "${CURL_EXIT:-0}"
SH
  chmod 0755 "$dir/claude" "$dir/tnctl" "$dir/curl"
}

# The per-case variables, back to the state of a bot that is fully set up: a
# key, the bot API's URL, an available model, a tnctl that answers, and an
# own-account volume that exists.
agent_reset() {
  AGENT_DIR="$TMP/agent/$1"
  AGENT_HOME="$AGENT_DIR/home"
  AGENT_WORK="$AGENT_DIR/work"
  AGENT_OWN_DIR="$AGENT_DIR/own"
  AGENT_KEY_PATH="$AGENT_DIR/key"
  AGENT_OUT="$AGENT_DIR/out"
  AGENT_ERR="$AGENT_DIR/err"
  AGENT_CLAUDE_LOG="$AGENT_DIR/claude.log"
  AGENT_CURL_LOG="$AGENT_DIR/curl.log"
  AGENT_STDIN=""
  AGENT_ARGS=()
  AGENT_EXTRA=()
  AGENT_API_SET="$AGENT_API"
  AGENT_TNCTL_FAIL=0
  AGENT_CURL_BODY='{"available": true, "model": "claude-sonnet-5-5"}'
  AGENT_CURL_STATUS=200
  AGENT_CURL_EXIT=0
  AGENT_CLAUDE_EXIT=0
  mkdir -p "$AGENT_HOME" "$AGENT_WORK" "$AGENT_OWN_DIR"
  printf '%s\n' "$AGENT_KEY" >"$AGENT_KEY_PATH"
  chmod 0600 "$AGENT_KEY_PATH"
}

# One run of the launcher: a clean environment (nothing of this suite's
# leaks in), the stubs first on PATH, and a here-string on stdin. Sets
# AGENT_RC; leaves stdout and stderr in $AGENT_OUT and $AGENT_ERR.
agent_run() {
  : >"$AGENT_CLAUDE_LOG"
  : >"$AGENT_CURL_LOG"
  env -i \
    PATH="$TMP/agent-bin:$TEST_PATH" \
    HOME="$AGENT_HOME" \
    TEKNOIRBOT_WORK_DIR="$AGENT_WORK" \
    TEKNOIRBOT_OWN_DIR="$AGENT_OWN_DIR" \
    TEKNOIRBOT_API="$AGENT_API_SET" \
    TEKNOIR_DOMAIN=teknoir.cloud \
    TEKNOIRBOT_NAMESPACE=teknoir-demo \
    TEKNOIRBOT_NAME=scout \
    TNCTL_BOT_KEY_FILE="$AGENT_KEY_PATH" \
    TEKNOIRBOT_CLAUDE="$TMP/agent-bin/claude" \
    TEKNOIRBOT_TNCTL="$TMP/agent-bin/tnctl" \
    TEKNOIRBOT_CURL="$TMP/agent-bin/curl" \
    CLAUDE_LOG="$AGENT_CLAUDE_LOG" \
    CURL_LOG="$AGENT_CURL_LOG" \
    CLAUDE_EXIT="$AGENT_CLAUDE_EXIT" \
    CURL_BODY="$AGENT_CURL_BODY" \
    CURL_STATUS="$AGENT_CURL_STATUS" \
    CURL_EXIT="$AGENT_CURL_EXIT" \
    TNCTL_FAIL="$AGENT_TNCTL_FAIL" \
    "${AGENT_EXTRA[@]}" \
    bash "$AGENT" "${AGENT_ARGS[@]}" >"$AGENT_OUT" 2>"$AGENT_ERR" <<<"${AGENT_STDIN}"
  AGENT_RC=$?
}

# The value the claude stub recorded under one key ("BASE_URL https://…").
agent_value() {
  sed -n "s/^$1 //p" "$AGENT_CLAUDE_LOG" | head -n 1
}

# The own-account session: a 0700 directory on the memory volume, there while
# the terminal UI runs and gone after it. Leaves the problems in PROBLEMS.
agent_own_account_problems() {
  local session
  session="$(agent_value CONFIG_DIR)"
  case "$session" in
    "$AGENT_OWN_DIR"/s.*) ;;
    *) PROBLEMS+="the config directory is '$session', want one under $AGENT_OWN_DIR; " ;;
  esac
  [ "$(agent_value SESSION)" = 700 ] || PROBLEMS+="the session directory is not 0700 ('$(agent_value SESSION)'); "
  [ "$(agent_value BASE_URL)" = '<unset>' ] || PROBLEMS+="a base URL was set in own-account mode; "
  [ "$(agent_value AUTH_TOKEN)" = unset ] || PROBLEMS+="a platform token was set in own-account mode; "
  [ "$(agent_value MODEL)" = '<unset>' ] || PROBLEMS+="a model was set in own-account mode; "
  if [ -n "$(find "$AGENT_OWN_DIR" -mindepth 1 -print -quit)" ]; then
    PROBLEMS+="the login was left behind in $AGENT_OWN_DIR; "
  fi
}

test_agent_launcher() {
  local problems projects

  # 1. The model is available: the terminal UI runs as the bot, with the
  #    platform's proxy in front of it and the desktop user's own variables
  #    gone.
  agent_reset key-model
  mkdir -p "$AGENT_DIR/leaked-config"
  AGENT_EXTRA=(
    'ANTHROPIC_API_KEY=sk-ant-api03-from-the-desktop-user'
    'ANTHROPIC_AUTH_TOKEN=from-the-desktop-user'
    'ANTHROPIC_BASE_URL=https://leaked.example'
    'ANTHROPIC_MODEL=leaked-model'
    "CLAUDE_CONFIG_DIR=$AGENT_DIR/leaked-config"
  )
  agent_run
  problems=""
  [ "$AGENT_RC" = 0 ] || problems+="exit $AGENT_RC, want 0; "
  [ "$(grep -m1 '^ARG ' "$AGENT_CLAUDE_LOG")" = 'ARG --append-system-prompt' ] ||
    problems+="the first argument is not --append-system-prompt; "
  grep -qxF -- 'ARG --continue' "$AGENT_CLAUDE_LOG" && problems+="--continue without a conversation to continue; "
  grep -qF 'teknoir-demo/scout' "$AGENT_CLAUDE_LOG" || problems+="the system prompt does not name the bot; "
  [ "$(agent_value BASE_URL)" = "$AGENT_API/model" ] || problems+="base URL '$(agent_value BASE_URL)'; "
  [ "$(agent_value AUTH_TOKEN)" = set ] || problems+="no auth token; "
  [ "$(agent_value MODEL)" = claude-sonnet-5-5 ] || problems+="model '$(agent_value MODEL)'; "
  [ "$(agent_value NONESSENTIAL)" = 1 ] || problems+="nonessential traffic is not off; "
  [ "$(agent_value AUTOUPDATER)" = 1 ] || problems+="the autoupdater is not off; "
  [ "$(agent_value CONFIG_DIR)" = '<unset>' ] || problems+="CLAUDE_CONFIG_DIR survived ('$(agent_value CONFIG_DIR)'); "
  [ "$(agent_value API_KEY)" = unset ] || problems+="ANTHROPIC_API_KEY survived; "
  [ "$(agent_value CWD)" = "$AGENT_WORK" ] || problems+="cwd '$(agent_value CWD)', want $AGENT_WORK; "
  [ "$(agent_value SESSION)" = none ] || problems+="a config directory was made in platform mode; "
  grep -qF -- '-H @' "$AGENT_CURL_LOG" || problems+="the status call did not read the key from a header file; "
  grep -qF 'TeknoirBot agent, powered by Claude: bot teknoir-demo/scout, model claude-sonnet-5-5.' "$AGENT_OUT" ||
    problems+="the start line is '$(head -n 1 "$AGENT_OUT")'; "
  if [ -z "$problems" ]; then
    pass agent-platform
  else
    fail agent-platform "$problems"
  fi

  # 2. A conversation for this directory exists: --continue comes first.
  agent_reset continue
  projects="$AGENT_HOME/.claude/projects/${AGENT_WORK//\//-}"
  mkdir -p "$projects"
  : >"$projects/session.jsonl"
  agent_run
  if [ "$AGENT_RC" = 0 ] && [ "$(grep -m1 '^ARG ' "$AGENT_CLAUDE_LOG")" = 'ARG --continue' ] &&
    grep -qF 'teknoir-demo/scout' "$AGENT_CLAUDE_LOG"; then
    pass agent-continue
  else
    fail agent-continue "exit $AGENT_RC, first argument '$(grep -m1 '^ARG ' "$AGENT_CLAUDE_LOG")'"
  fi

  # 3. The platform model is down and the user says yes: a login of their own,
  #    in memory, gone when the terminal is. claude's exit status is the
  #    launcher's.
  agent_reset own-from-503
  AGENT_CURL_BODY='{"available": false, "reason": "the monthly budget is spent"}'
  AGENT_CURL_STATUS=503
  AGENT_STDIN=y
  AGENT_CLAUDE_EXIT=7
  agent_run
  PROBLEMS=""
  [ "$AGENT_RC" = 7 ] || PROBLEMS+="exit $AGENT_RC, want the terminal UI's 7; "
  grep -qF 'The platform model is not available: the monthly budget is spent.' "$AGENT_OUT" ||
    PROBLEMS+="the reason was not printed: '$(head -n 3 "$AGENT_OUT")'; "
  grep -qF 'Starting with your own Anthropic account.' "$AGENT_OUT" || PROBLEMS+="own-account mode did not start; "
  agent_own_account_problems
  if [ -z "$PROBLEMS" ]; then
    pass agent-own-after-503
  else
    fail agent-own-after-503 "$PROBLEMS"
  fi

  # 4. ... and no: nothing starts at all.
  agent_reset no-own-from-503
  AGENT_CURL_BODY='{"available": false, "reason": "the monthly budget is spent"}'
  AGENT_CURL_STATUS=503
  AGENT_STDIN=n
  agent_run
  if [ "$AGENT_RC" = 0 ] && [ ! -s "$AGENT_CLAUDE_LOG" ] &&
    grep -qF 'Nothing started.' "$AGENT_OUT"; then
    pass agent-nothing-started
  else
    fail agent-nothing-started "exit $AGENT_RC, claude log '$(tr '\n' '|' <"$AGENT_CLAUDE_LOG")', output '$(cat "$AGENT_OUT")'"
  fi

  # 5. No key: a bot made before the agent. It says so and starts with the
  #    user's own account instead.
  agent_reset no-key
  AGENT_KEY_PATH="$AGENT_DIR/no-such-key"
  agent_run
  PROBLEMS=""
  [ "$AGENT_RC" = 0 ] || PROBLEMS+="exit $AGENT_RC, want 0; "
  grep -qF "This bot's computer has no platform key" "$AGENT_OUT" || PROBLEMS+="the missing key was not named; "
  [ ! -s "$AGENT_CURL_LOG" ] || PROBLEMS+="the model status was called without a key; "
  agent_own_account_problems
  if [ -z "$PROBLEMS" ]; then
    pass agent-no-key
  else
    fail agent-no-key "$PROBLEMS"
  fi

  # 6. No bot API either (the pod did not set it): the same path.
  agent_reset no-api
  AGENT_API_SET=""
  agent_run
  if [ "$AGENT_RC" = 0 ] && grep -qF "This bot's computer has no platform key" "$AGENT_OUT" &&
    [ ! -s "$AGENT_CURL_LOG" ] && [ "$(agent_value SESSION)" = 700 ]; then
    pass agent-no-api
  else
    fail agent-no-api "exit $AGENT_RC, output '$(tr '\n' '|' <"$AGENT_OUT")', session '$(agent_value SESSION)'"
  fi

  # 7. --own-account with everything in place: no platform call at all.
  agent_reset own-option
  AGENT_ARGS=(--own-account)
  agent_run
  PROBLEMS=""
  [ "$AGENT_RC" = 0 ] || PROBLEMS+="exit $AGENT_RC, want 0; "
  [ ! -s "$AGENT_CURL_LOG" ] || PROBLEMS+="the model status was called; "
  [ "$(agent_value SESSION)" = 700 ] || PROBLEMS+="own-account mode did not start; "
  if grep -q 'has no platform key' "$AGENT_OUT"; then
    PROBLEMS+="it complained about a key that is there; "
  fi
  if grep -q '^ARG ' "$AGENT_CLAUDE_LOG"; then
    PROBLEMS+="the terminal UI got arguments in own-account mode; "
  fi
  if [ -z "$PROBLEMS" ]; then
    pass agent-own-option
  else
    fail agent-own-option "$PROBLEMS"
  fi

  # 8. No memory volume: own-account mode refuses instead of writing the login
  #    to the home volume.
  agent_reset no-own-dir
  AGENT_ARGS=(--own-account)
  AGENT_OWN_DIR="$AGENT_DIR/missing-volume"
  agent_run
  if [ "$AGENT_RC" = 1 ] && [ ! -s "$AGENT_CLAUDE_LOG" ] &&
    grep -qF 'needs the memory volume' "$AGENT_ERR"; then
    pass agent-own-needs-volume
  else
    fail agent-own-needs-volume "exit $AGENT_RC, stderr '$(cat "$AGENT_ERR")'"
  fi

  # 9. tnctl cannot say who the bot is: the agent still starts, with what the
  #    pod says and without the bot's own facts.
  agent_reset whoami-fails
  AGENT_TNCTL_FAIL=1
  agent_run
  PROBLEMS=""
  [ "$AGENT_RC" = 0 ] || PROBLEMS+="exit $AGENT_RC, want 0; "
  grep -qF 'tnctl whoami failed: Error: the bot API answered 401 for this key' "$AGENT_ERR" ||
    PROBLEMS+="the whoami failure was not printed; "
  if grep -qF 'You are the TeknoirBot agent of bot' "$AGENT_CLAUDE_LOG"; then
    PROBLEMS+="the prompt claims the bot's facts anyway; "
  fi
  [ "$(agent_value MODEL)" = claude-sonnet-5-5 ] || PROBLEMS+="the agent did not start on the platform model; "
  if [ -z "$PROBLEMS" ]; then
    pass agent-whoami-fails
  else
    fail agent-whoami-fails "$PROBLEMS"
  fi

  # 10. The key reaches no command line. Every stub log and the launcher's own
  #     output, in every case run above; and the header file that held it is
  #     gone once the terminal UI has started (the exec would skip the trap).
  local hits
  hits="$(find "$TMP/agent" -type f \( -name '*.log' -o -name out -o -name err \) \
    -exec grep -lF "$AGENT_KEY" {} + 2>/dev/null || true)"
  if [ -n "$hits" ]; then
    fail agent-key-never-leaks "the key is in: $(printf '%s' "$hits" | tr '\n' ' ')"
  elif [ -n "$(find "$TMP/agent/key-model" -name headers -print -quit)" ]; then
    fail agent-key-never-leaks "the request header file survived the exec"
  else
    pass agent-key-never-leaks
  fi

  # 11. An unknown option is a usage error, not a start.
  agent_reset unknown-option
  AGENT_ARGS=(--bogus)
  agent_run
  if [ "$AGENT_RC" = 2 ] && [ ! -s "$AGENT_CLAUDE_LOG" ] &&
    grep -qF 'usage: teknoirbot-agent' "$AGENT_ERR"; then
    pass agent-unknown-option
  else
    fail agent-unknown-option "exit $AGENT_RC, stderr '$(tr '\n' '|' <"$AGENT_ERR")'"
  fi
}

# The managed settings are the whole of the agent's permissions, and the only
# place the guard hook is registered: root-owned, so uid 1000 can neither
# change them nor unregister the hook.
test_agent_managed_config() {
  local problems="" f
  for f in rootfs-agent/etc/claude-code/managed-settings.json \
    rootfs-agent/etc/claude-code/managed-mcp.json; do
    if [ ! -f "$f" ]; then
      problems+="$f missing; "
    elif ! python3 -I -m json.tool "$f" >/dev/null 2>&1; then
      problems+="$f is not valid JSON; "
    fi
  done

  if [ -z "$problems" ] && ! python3 -I -c '
import json
import sys

with open("rootfs-agent/etc/claude-code/managed-settings.json", encoding="utf-8") as fh:
    settings = json.load(fh)
with open("rootfs-agent/etc/claude-code/managed-mcp.json", encoding="utf-8") as fh:
    mcp = json.load(fh)

problems = []
permissions = settings.get("permissions") or {}
if permissions.get("defaultMode") != "acceptEdits":
    problems.append("permissions.defaultMode is %r" % (permissions.get("defaultMode"),))
if permissions.get("disableBypassPermissionsMode") != "disable":
    problems.append("disableBypassPermissionsMode is %r"
                    % (permissions.get("disableBypassPermissionsMode"),))
deny = permissions.get("deny") or []
for want in ("Bash(tnctl login:*)", "Read(//run/teknoirbot/**)"):
    if want not in deny:
        problems.append("deny misses %s" % want)

hooks = (settings.get("hooks") or {}).get("PreToolUse") or []
if len(hooks) != 1:
    problems.append("%d PreToolUse hooks, want 1" % len(hooks))
else:
    if hooks[0].get("matcher") != "Bash|mcp__teknoir__.*":
        problems.append("the matcher is %r" % (hooks[0].get("matcher"),))
    commands = [h.get("command") for h in hooks[0].get("hooks") or []]
    if commands != ["/etc/claude-code/.claude/hooks/teknoir-guard"]:
        problems.append("the hook commands are %r" % (commands,))

server = (mcp.get("mcpServers") or {}).get("teknoir") or {}
if server.get("command") != "tnctl" or server.get("args") != ["mcp"]:
    problems.append("the teknoir MCP server is %r" % (server,))

if problems:
    sys.exit("; ".join(problems))
' >"$TMP/agent-config.out" 2>&1; then
    problems+="$(tr '\n' '|' <"$TMP/agent-config.out")"
  fi

  if [ -z "$problems" ]; then
    pass agent-managed-config
  else
    fail agent-managed-config "$problems"
  fi
}

test_agent_dockerfile() {
  local problems="" var stage
  for stage in desktop tnctl agent; do
    grep -qE "^FROM .* AS ${stage}$" Dockerfile || problems+="no stage named $stage; "
  done
  grep -qxF 'FROM desktop AS agent' Dockerfile || problems+="the agent stage is not built on desktop; "
  # Each pinned download is verified before it is used.
  for var in CLAUDE_SHA256 KUBECTL_SHA256 BUILDKIT_SHA256; do
    grep -qE "\\$\\{${var}\\}.*sha256sum -c -" Dockerfile ||
      problems+="the ${var} checksum is not verified with sha256sum -c; "
  done
  grep -qF 'tnctl agent install --agent claude --managed /etc/claude-code/.claude' Dockerfile ||
    problems+="the agent kit is not installed by tnctl; "
  grep -qF 'tnctl agent list --managed /etc/claude-code/.claude --check' Dockerfile ||
    problems+="the agent kit is not checked with --check; "
  # The product name is never ours to use: the image says "TeknoirBot agent,
  # powered by Claude".
  if grep -rlF 'Claude Code' "$AGENT" rootfs-agent/etc/xdg/autostart/*.desktop \
    rootfs-agent/usr/share/applications/*.desktop >/dev/null 2>&1; then
    problems+="the string 'Claude Code' is in $(grep -rlF 'Claude Code' "$AGENT" rootfs-agent/etc/xdg/autostart/*.desktop rootfs-agent/usr/share/applications/*.desktop | tr '\n' ' '); "
  fi
  if [ -z "$problems" ]; then
    pass agent-dockerfile
  else
    fail agent-dockerfile "$problems"
  fi
}

test_agent_desktop_entries() {
  local files=(
    rootfs-agent/etc/xdg/autostart/teknoirbot-agent.desktop
    rootfs-agent/usr/share/applications/teknoirbot-agent.desktop
    rootfs-agent/usr/share/applications/teknoirbot-agent-own.desktop
  )
  if ! command -v desktop-file-validate >/dev/null 2>&1; then
    skip agent-desktop-entries "desktop-file-validate is not on PATH"
    return
  fi
  if desktop-file-validate "${files[@]}" >"$TMP/agent-desktop.out" 2>&1; then
    pass agent-desktop-entries
  else
    fail agent-desktop-entries "$(head -20 "$TMP/agent-desktop.out" | tr '\n' '|')"
  fi
}

agent_stubs

# --- run --------------------------------------------------------------------

test_shellcheck
test_hadolint
test_chromium_policy_json
test_xfconf_xml
test_seccomp_profile
test_novnc_extra
test_dockerfile_dev_shm
test_entrypoint_vectors
test_notice
test_notice_locale
test_notice_file
test_browser_wrapper
test_browser_live
test_desktop_entries
test_manifests
test_host_unit
test_host_session
test_index_redirect
test_notice_script
test_healthcheck
test_healthcheck_bad_http
test_healthcheck_blacklisted
test_agent_launcher
test_agent_managed_config
test_agent_dockerfile
test_agent_desktop_entries

printf '\n%d passed, %d failed, %d skipped\n' "$passed" "$failed" "$skipped"
if [ "$failed" -ne 0 ]; then
  exit 1
fi
