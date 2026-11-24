#!/usr/bin/env python3
"""Write the host-mode bundle that the teknoir/ansible desktop playbook vendors.

Host mode only serves noVNC for the device's own desktop session, so the theme
of that session is not part of the image: the ansible desktop playbook
installs these files on the device at fixed paths, and the session script
themes the remote session from them. This tool copies them, with the fonts the
Dockerfile pins and the image's own files, into one directory the ansible
repository can vendor as playbooks/files/teknoir-desktop:

    teknoir-desktop-session          /usr/local/libexec/teknoir-desktop-session
    teknoir-desktop.service          /etc/systemd/system/teknoir-desktop.service
    theme/themes/Teknoir/**          /usr/share/themes/Teknoir/**
    theme/teknoir-mark.svg           /usr/share/teknoir/teknoir-mark.svg
    theme/fonts/**                   /usr/local/share/fonts/teknoir/**
    theme/xdg/**                     /usr/local/share/teknoir-desktop/xdg/**
    theme/desktop-theme-migrate      /usr/local/libexec/teknoir-desktop-theme-migrate
    SOURCE, SHA256SUMS               who built it, and the bytes

Nothing image-only goes in: no power-manager or screensaver channel, no
/etc/gtk-3.0/settings.ini, no /etc/fonts/local.conf, and nothing under
/etc/xdg. Two files under theme/xdg are not verbatim copies of the image's,
because the devices run XFCE 4.14 and 4.16 where the image runs 4.20:
xfce4/terminal/terminalrc is generated from the xfce4-terminal channel for
xfce4-terminal 0.8 (Ubuntu 20.04/22.04), which reads that file instead of the
channel, and xfce4/panel/default.xml gains the pre-4.18 digital-format key of
the clock plugin. The xfconf channel file itself stays as the image has it,
for xfce4-terminal 1.x on newer devices.

Only what git publishes goes in: every source file is taken from
`git ls-files --cached --others --exclude-standard`, so an editor's *~ or *.swp
that the .gitignore covers is never copied into a device's bundle. The output
is deterministic: the same tree gives the same bytes.

Exit status: 0 on success, 2 on a usage or configuration error (a dirty tree, a
foreign entry in --out, a malformed Dockerfile, a source file git would not
publish) and on an I/O error while creating the temporary directory or
building the bundle (an unwritable parent, a full disk), 1 when a font's
sha256 does not match the pin. A failed run leaves the previous bundle in
--out as it was; if restoring it fails, the backup directory next to --out is
kept and its path is printed.
"""

import argparse
import hashlib
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import urllib.request
import xml.etree.ElementTree as ET

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO_NAME = "teknoir/teknoir-desktop"

# Repository paths the bundle is built from (all repo-relative).
THEME_DIR = "rootfs/usr/share/themes/Teknoir"
XFCONF_DIR = "rootfs/etc/xdg/xfce4/xfconf/xfce-perchannel-xml"
PANEL_DEFAULT = "rootfs/etc/xdg/xfce4/panel/default.xml"
TERMINAL_CHANNEL = XFCONF_DIR + "/xfce4-terminal.xml"

# Everything --out may contain, and everything a run replaces.
MANAGED = (
    "teknoir-desktop-session",
    "teknoir-desktop.service",
    "theme",
    "SOURCE",
    "SHA256SUMS",
)

# Directories this run could not remove: one it could not delete, or the
# backup of the previous bundle, kept because restoring it did not fully work.
# Printed once on the way out, so the old bytes are never lost track of.
LEFTOVERS = []

# The four font files, and the Dockerfile ARG that pins each one's bytes.
FONT_SHA_ARG = {
    "HankenGrotesk-VF.ttf": "HANKEN_GROTESK_SHA256",
    "HankenGrotesk-OFL.txt": "HANKEN_GROTESK_OFL_SHA256",
    "JetBrainsMono-VF.ttf": "JETBRAINS_MONO_SHA256",
    "JetBrainsMono-OFL.txt": "JETBRAINS_MONO_OFL_SHA256",
}

# The xfconf channels the host session reads. xfce4-power-manager and
# xfce4-screensaver stay image-only.
XDG_CHANNELS = ("xsettings", "xfwm4", "xfce4-terminal", "xfce4-desktop")

ARG_RE = re.compile(r"^ARG[ \t]+([A-Za-z_][A-Za-z0-9_]*)=([^\s]+)[ \t]*$", re.M)
ADD_RE = re.compile(
    r"^ADD[ \t]+(https://raw\.githubusercontent\.com/google/fonts/"
    r"\$\{GOOGLE_FONTS_COMMIT\}/\S+)[ \t]+/tmp/fonts/([^/\s]+)[ \t]*$",
    re.M,
)


def die(message, status=2):
    sys.stderr.write("host-bundle: %s\n" % message)
    raise SystemExit(status)


# --- the Dockerfile's font pins ---------------------------------------------


def parse_fonts(text):
    """The four (basename, url, sha256) tuples the Dockerfile adds.

    Exactly one ARG per value and one ADD per font: a duplicate would mean
    the bundle takes one value and the image another.
    """
    args = {}
    for name, value in ARG_RE.findall(text):
        args.setdefault(name, []).append(value)
    for name in ["GOOGLE_FONTS_COMMIT"] + list(FONT_SHA_ARG.values()):
        values = args.get(name, [])
        if not values:
            die("the Dockerfile has no ARG %s=<value>" % name)
        if len(values) > 1:
            die("the Dockerfile sets ARG %s= %d times" % (name, len(values)))
    commit = args["GOOGLE_FONTS_COMMIT"][0]

    adds = ADD_RE.findall(text)
    if len(adds) != len(FONT_SHA_ARG):
        die(
            "the Dockerfile has %d google/fonts ADD line(s), want %d"
            % (len(adds), len(FONT_SHA_ARG))
        )
    fonts = []
    seen = set()
    for url, name in adds:
        if name in seen:
            die("the Dockerfile adds /tmp/fonts/%s twice" % name)
        seen.add(name)
        if name not in FONT_SHA_ARG:
            die("unexpected font ADD destination /tmp/fonts/%s" % name)
        sha = args[FONT_SHA_ARG[name]][0]
        fonts.append((name, url.replace("${GOOGLE_FONTS_COMMIT}", commit), sha))
    missing = set(FONT_SHA_ARG) - seen
    if missing:
        die("the Dockerfile has no ADD line for %s" % ", ".join(sorted(missing)))
    fonts.sort()
    return fonts


def load_fonts(fonts, fonts_from):
    """Read or download each font and check it against the pinned sha256."""
    data = {}
    for name, url, expected in fonts:
        if fonts_from:
            source = os.path.join(fonts_from, name)
            try:
                with open(source, "rb") as fh:
                    blob = fh.read()
            except OSError as exc:
                die("cannot read %s: %s" % (source, exc), 1)
            origin = source
        else:
            try:
                with urllib.request.urlopen(url, timeout=60) as response:
                    blob = response.read()
            except Exception as exc:  # URLError, HTTPError, timeout, ...
                die("cannot download %s: %s" % (url, exc), 1)
            origin = url
        actual = hashlib.sha256(blob).hexdigest()
        if actual != expected:
            die(
                "%s: sha256 %s, the Dockerfile pins %s (from %s)"
                % (name, actual, expected, origin),
                1,
            )
        data[name] = blob
    return data


# --- the repository's state -------------------------------------------------


def git(*args):
    try:
        return subprocess.run(
            ["git"] + list(args),
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as exc:
        die("cannot run git: %s" % exc)


def repo_state(allow_dirty):
    """The HEAD commit, and whether host/, rootfs/, Dockerfile or tools/ is dirty."""
    head = git("rev-parse", "HEAD")
    if head.returncode != 0:
        die(
            "git rev-parse HEAD failed: %s"
            % head.stderr.decode("utf-8", "replace").strip()
        )
    commit = head.stdout.decode("utf-8", "replace").strip()

    status = git(
        "status", "--porcelain", "--", "host", "rootfs", "Dockerfile", "tools"
    )
    if status.returncode != 0:
        die(
            "git status failed: %s"
            % status.stderr.decode("utf-8", "replace").strip()
        )
    lines = [
        line
        for line in status.stdout.decode("utf-8", "replace").splitlines()
        if line.strip()
    ]
    if lines and not allow_dirty:
        paths = []
        for line in lines:
            path = line[3:]
            if " -> " in path:  # a rename shows both names
                path = path.split(" -> ", 1)[1]
            paths.append(path)
        die(
            "the working tree is dirty: %s (commit it, or pass --allow-dirty)"
            % ", ".join(sorted(paths))
        )
    return commit, bool(lines)


def git_files(path):
    """The files under `path` that git publishes: tracked, or new and not ignored.

    The bundle is the git tree, not the checkout. An editor's *~ or *.swp is
    covered by the .gitignore, so git never publishes it and the bundle must
    not carry it to a device either; `--exclude-standard` is what leaves it
    out. Files that are gone from disk (a tracked file deleted under
    --allow-dirty) are dropped here too, so nothing below trips over them.
    """
    result = git(
        "ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", path
    )
    if result.returncode != 0:
        die(
            "cannot list %s with git: %s"
            % (path, result.stderr.decode("utf-8", "replace").strip())
        )
    return [
        name
        for name in result.stdout.decode("utf-8", "surrogateescape").split("\0")
        if name and os.path.isfile(os.path.join(REPO_ROOT, name))
    ]


# --- writing the bundle -----------------------------------------------------


def make_dir(path):
    # Create the whole chain ourselves: os.makedirs would leave the parents at
    # the umask's mode (0775 under the usual 0002), and every directory of the
    # bundle is 0755.
    if os.path.isdir(path):
        os.chmod(path, 0o755)
        return
    parent = os.path.dirname(path)
    if parent and parent != path:
        make_dir(parent)
    os.mkdir(path)
    os.chmod(path, 0o755)


def write_file(path, data, mode):
    make_dir(os.path.dirname(path))
    with open(path, "wb") as fh:
        fh.write(data)
    os.chmod(path, mode)


def copy_file(source, dest, mode):
    make_dir(os.path.dirname(dest))
    shutil.copyfile(source, dest)
    os.chmod(dest, mode)


def copy_source_file(source, dest, mode):
    """Copy one repository file git publishes; a missing or ignored one is fatal."""
    if source not in git_files(source):
        die("%s is not a file git publishes (ignored, or not on disk)" % source)
    copy_file(os.path.join(REPO_ROOT, source), dest, mode)


def copy_source_tree(source, dest):
    """Copy the files git publishes under the repository directory `source`."""
    names = git_files(source)
    if not names:
        die("no files git publishes under %s" % source)
    make_dir(dest)
    for name in names:
        rel = os.path.relpath(name, source)
        copy_file(os.path.join(REPO_ROOT, name), os.path.join(dest, rel), 0o644)


def discard(path):
    """Remove a directory this tool made; if that fails, remember it for the exit."""
    shutil.rmtree(path, ignore_errors=True)
    if os.path.lexists(path):
        LEFTOVERS.append(path)


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def terminal_config(source):
    """The terminalrc bytes for xfce4-terminal 0.8, from the xfconf channel file.

    xfce4-terminal 1.x (the image) reads the xfce4-terminal xfconf channel;
    0.8 (Ubuntu 20.04's 0.8.9 and 22.04's 0.8.10) reads a GKeyFile at
    ~/.config/xfce4/terminal/terminalrc and at the same path below each
    XDG_CONFIG_DIRS entry. The same settings, keyed the other way: one
    Key=Value line per top-level property of the channel, in file order, the
    dash-case property name in CamelCase. Only the simple types 0.8 knows can
    be written this way; a nested group or an array is a configuration error.
    """
    try:
        root = ET.parse(source).getroot()
    except (ET.ParseError, OSError) as exc:
        die("cannot read %s: %s" % (source, exc))
    lines = ["[Configuration]"]
    for prop in root.findall("property"):
        name = prop.get("name") or ""
        kind = prop.get("type") or ""
        value = prop.get("value")
        if len(prop):
            die(
                "%s: property %s holds settings of its own, which terminalrc "
                "cannot express" % (source, name)
            )
        if value is None:
            die("%s: property %s has no value" % (source, name))
        if kind == "bool":
            if value not in ("true", "false"):
                die("%s: property %s is a bool of %r" % (source, name, value))
            value = "TRUE" if value == "true" else "FALSE"
        elif kind in ("int", "uint"):
            try:
                value = "%d" % int(value)
            except ValueError:
                die("%s: property %s is not a number: %r" % (source, name, value))
        elif kind != "string":
            die(
                "%s: property %s has type %r, which terminalrc cannot express"
                % (source, name, kind)
            )
        key = "".join(part.capitalize() for part in name.split("-"))
        lines.append("%s=%s" % (key, value))
    return ("\n".join(lines) + "\n").encode("utf-8")


# The clock plugin of the image's panel layout, and the 4.18+ key it writes.
CLOCK_RE = re.compile(r'<property name="plugin-[0-9]+" type="string" value="clock">')
CLOCK_FORMAT = '<property name="digital-time-format"'
CLOCK_DIGITAL_FORMAT = (
    '<property name="digital-format" type="string" value="%H:%M"/>'
)


def panel_xml(source):
    """The bundle's default.xml: the image's, plus the pre-4.18 clock key.

    xfce4-panel 4.14 and 4.16 know only the clock's digital-format; the image
    (4.20) writes digital-layout and digital-time-format. The old key is
    inserted as text, right after digital-time-format and at the same
    indentation, so every other byte of the file stays exactly the image's.
    """
    try:
        with open(source, "rb") as fh:
            text = fh.read().decode("utf-8")
    except (OSError, UnicodeError) as exc:
        die("cannot read %s: %s" % (source, exc))
    lines = text.splitlines(keepends=True)
    clocks = [index for index, line in enumerate(lines) if CLOCK_RE.search(line)]
    if len(clocks) != 1:
        die("%s: found %d clock plugins, want 1" % (source, len(clocks)))
    formats = [index for index, line in enumerate(lines) if CLOCK_FORMAT in line]
    if len(formats) != 1:
        die(
            "%s: found %d digital-time-format properties, want 1"
            % (source, len(formats))
        )
    clock, fmt = clocks[0], formats[0]
    clock_indent = len(lines[clock]) - len(lines[clock].lstrip())
    end = None
    for index in range(clock + 1, len(lines)):
        stripped = lines[index].lstrip()
        if len(lines[index]) - len(stripped) <= clock_indent:
            end = index
            break
    if end is None or not clock < fmt < end:
        die("%s: digital-time-format is not inside the clock plugin" % source)
    indent = lines[fmt][: len(lines[fmt]) - len(lines[fmt].lstrip())]
    # The inserted line needs a newline of its own unless the one it follows
    # already ends with one.
    lead = "" if lines[fmt].endswith("\n") else "\n"
    lines.insert(fmt + 1, lead + indent + CLOCK_DIGITAL_FORMAT + "\n")
    return "".join(lines).encode("utf-8")


def build(stage, fonts, commit, dirty):
    """Write the whole bundle under `stage`; returns the file count."""
    copy_source_file(
        "host/teknoir-desktop-session",
        os.path.join(stage, "teknoir-desktop-session"),
        0o755,
    )
    copy_source_file(
        "host/teknoir-desktop.service",
        os.path.join(stage, "teknoir-desktop.service"),
        0o644,
    )
    copy_source_tree(THEME_DIR, os.path.join(stage, "theme", "themes", "Teknoir"))
    copy_source_file(
        "rootfs/usr/share/teknoir/teknoir-mark.svg",
        os.path.join(stage, "theme", "teknoir-mark.svg"),
        0o644,
    )
    for name in sorted(fonts):
        write_file(os.path.join(stage, "theme", "fonts", name), fonts[name], 0o644)
    for channel in XDG_CHANNELS:
        copy_source_file(
            XFCONF_DIR + "/" + channel + ".xml",
            os.path.join(
                stage, "theme", "xdg", "xfce4", "xfconf", "xfce-perchannel-xml",
                channel + ".xml",
            ),
            0o644,
        )
    # xfce4-terminal 0.8's own file, and the pre-4.18 clock key: see the two
    # helpers. They come from the channel file and default.xml copied above.
    write_file(
        os.path.join(stage, "theme", "xdg", "xfce4", "terminal", "terminalrc"),
        terminal_config(os.path.join(REPO_ROOT, TERMINAL_CHANNEL)),
        0o644,
    )
    write_file(
        os.path.join(stage, "theme", "xdg", "xfce4", "panel", "default.xml"),
        panel_xml(os.path.join(REPO_ROOT, PANEL_DEFAULT)),
        0o644,
    )
    copy_source_file(
        "rootfs/usr/local/bin/desktop-theme-migrate",
        os.path.join(stage, "theme", "desktop-theme-migrate"),
        0o755,
    )

    source = "repo: %s\ncommit: %s\n" % (REPO_NAME, commit)
    if dirty:
        source += "dirty: true\n"
    write_file(os.path.join(stage, "SOURCE"), source.encode("utf-8"), 0o644)

    sums = []
    for root, _dirs, files in os.walk(stage):
        for name in files:
            path = os.path.join(root, name)
            rel = os.path.relpath(path, stage).replace(os.sep, "/")
            if rel == "SHA256SUMS":
                continue
            sums.append((rel, sha256_file(path)))
    sums.sort()
    write_file(
        os.path.join(stage, "SHA256SUMS"),
        "".join("%s  %s\n" % (digest, rel) for rel, digest in sums).encode("utf-8"),
        0o644,
    )
    return len(sums) + 1


def check_out(out):
    """Refuse an --out we may not own, before anything is written."""
    real_out = os.path.realpath(out)
    for name in ("rootfs", "host"):
        base = os.path.realpath(os.path.join(REPO_ROOT, name))
        if real_out == base or real_out.startswith(base + os.sep):
            die("--out must not be inside %s" % base)
    parent = os.path.dirname(out)
    if not os.path.isdir(parent):
        die("the parent of --out is not a directory: %s" % parent)
    if os.path.lexists(out):
        if os.path.islink(out) or not os.path.isdir(out):
            die("--out exists and is not a directory: %s" % out)
        foreign = sorted(set(os.listdir(out)) - set(MANAGED))
        if foreign:
            die(
                "%s holds entries this tool does not manage: %s"
                % (out, ", ".join(foreign))
            )


def replace_out(out, stage):
    """Move the managed entries of `stage` into `out`, the old ones aside first.

    The old entries are parked in a directory next to --out (same filesystem,
    so the renames are cheap and atomic). SIGINT, SIGTERM and SIGHUP are
    blocked from the first rename until the replace has fully settled, so one
    of them cannot land between a rename and the bookkeeping that records it;
    the previous mask is restored in a finally, which delivers any pending
    signal then, when --out is consistent again.

    Any failure - an OSError, Ctrl-C, a SystemExit - moves back out the entries
    that already went in, then moves the parked old entries home again, so the
    previous bundle is whole and the run can simply be repeated. The backup is
    never deleted recursively: after a successful restore it is empty and is
    removed with rmdir, and anything still inside it (an entry whose restore
    failed) keeps the directory, which is named in LEFTOVERS and on the way
    out - the old bytes then still exist, in a place the message names.
    """
    parent = os.path.dirname(out)
    backup = tempfile.mkdtemp(prefix=".host-bundle-old.", dir=parent)
    moved_out = []  # old entries now in the backup
    moved_in = []  # new entries now in --out

    # Test-only fault hook: HOST_BUNDLE_TEST_FAIL_AT=<n> raises
    # KeyboardInterrupt right before the n-th rename below, standing in for a
    # Ctrl-C in the middle of the replace. Never set on a real run.
    fail_at = None
    if "HOST_BUNDLE_TEST_FAIL_AT" in os.environ:
        try:
            fail_at = int(os.environ["HOST_BUNDLE_TEST_FAIL_AT"])
        except ValueError:
            die("HOST_BUNDLE_TEST_FAIL_AT must be a number")
    renames = [0]

    def rename(source, dest):
        renames[0] += 1
        if fail_at is not None and renames[0] == fail_at:
            raise KeyboardInterrupt("HOST_BUNDLE_TEST_FAIL_AT=%s" % fail_at)
        os.replace(source, dest)

    # A signal that lands between a rename and its append would leave that
    # entry untracked, and a rollback that "succeeds" would then remove the
    # backup with the old entry still in it. Block the three signals that stop
    # or interrupt a run for the whole replace; the finally restores the
    # previous mask, and only then is a pending one delivered, when --out has
    # been settled one way or the other.
    old_mask = signal.pthread_sigmask(
        signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM, signal.SIGHUP}
    )
    try:
        try:
            for name in MANAGED:
                current = os.path.join(out, name)
                if os.path.lexists(current):
                    rename(current, os.path.join(backup, name))
                    moved_out.append(name)
            for name in MANAGED:
                incoming = os.path.join(stage, name)
                if os.path.lexists(incoming):
                    rename(incoming, os.path.join(out, name))
                    moved_in.append(name)
        except BaseException as exc:
            # Until the backup is gone it may hold old entries: name it in
            # LEFTOVERS first, so a second interrupt or a crash during the
            # rollback below still reports it, and drop it again only once it
            # has been removed.
            LEFTOVERS.append(backup)
            for name in moved_in:
                current = os.path.join(out, name)
                try:
                    if os.path.isdir(current) and not os.path.islink(current):
                        shutil.rmtree(current)
                    else:
                        os.unlink(current)
                except OSError:
                    pass
            for name in moved_out:
                try:
                    os.replace(os.path.join(backup, name), os.path.join(out, name))
                except OSError:
                    pass
            # Never rmtree the backup: a rollback that put every entry back
            # left it empty, so rmdir succeeds and the old bundle is home; an
            # entry whose restore failed keeps it, and its path stays in
            # LEFTOVERS for the message on the way out.
            try:
                os.rmdir(backup)
            except OSError:
                pass
            else:
                LEFTOVERS.remove(backup)
            if isinstance(exc, OSError):
                die("cannot replace the bundle in %s: %s" % (out, exc))
            # A KeyboardInterrupt or SystemExit is the caller's to handle; the
            # old bundle is back, so it may be re-raised as it is.
            raise
        # Every rename went through: what the backup holds is the previous
        # bundle's entries, which nothing needs any more.
        discard(backup)
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)


def main(argv):
    parser = argparse.ArgumentParser(
        prog="host-bundle.py",
        description="Write the host-mode bundle the ansible desktop playbook "
        "vendors: the session script and unit, and the theme files it installs "
        "on the device (see the module docstring for the target paths).",
    )
    parser.add_argument(
        "--out",
        required=True,
        metavar="DIR",
        help="the bundle directory; it may hold nothing but this tool's entries, "
        "and is replaced in place on a re-run",
    )
    parser.add_argument(
        "--fonts-from",
        metavar="DIR",
        help="read the four font files from DIR/<name> instead of downloading "
        "them (offline use and tests); their sha256 is still checked",
    )
    parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="bundle an unclean host/, rootfs/, Dockerfile or tools/ and record "
        "dirty: true in SOURCE",
    )
    parser.add_argument(
        "--dockerfile",
        metavar="PATH",
        help="the Dockerfile to take the font pins from (tests only; default: "
        "the repository's Dockerfile)",
    )
    args = parser.parse_args(argv)

    out = os.path.abspath(args.out)
    dockerfile = (
        os.path.abspath(args.dockerfile)
        if args.dockerfile
        else os.path.join(REPO_ROOT, "Dockerfile")
    )
    check_out(out)
    try:
        with open(dockerfile, encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        die("cannot read %s: %s" % (dockerfile, exc))
    fonts = parse_fonts(text)
    commit, dirty = repo_state(args.allow_dirty)
    data = load_fonts(fonts, os.path.abspath(args.fonts_from) if args.fonts_from else None)

    # Build next to --out, so the moves into it are renames on one filesystem.
    # A parent the tool cannot write, or a disk that fills up while the stage
    # is built, is a configuration error like the rest: exit 2 and one message,
    # never a traceback with exit 1 (which is the font mismatch's).
    parent = os.path.dirname(out)
    try:
        tmp = tempfile.mkdtemp(prefix=".host-bundle.", dir=parent)
    except OSError as exc:
        die("cannot create a temporary directory in %s: %s" % (parent, exc))
    try:
        try:
            stage = os.path.join(tmp, "bundle")
            make_dir(stage)
            count = build(stage, data, commit, dirty)
            if not os.path.isdir(out):
                os.mkdir(out)
                os.chmod(out, 0o755)
            replace_out(out, stage)
        except OSError as exc:
            die("cannot build the bundle next to %s: %s" % (out, exc))
    finally:
        discard(tmp)

    sys.stdout.write(
        "host bundle: %d files, commit %s%s -> %s\n"
        % (count, commit[:8], ", dirty" if dirty else "", args.out)
    )


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    finally:
        # Anything this run left behind - the backup of the previous bundle
        # when even the restore failed, a temporary directory that could not
        # be removed - is named on the way out, error or not.
        for path in LEFTOVERS:
            sys.stderr.write("host-bundle: left behind: %s\n" % path)
