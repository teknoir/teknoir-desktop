#!/usr/bin/env python3
"""Generate the xfwm4 theme "Teknoir" from the Backstage nextgen tokens.

Why a generator and not forty hand-written XPMs: every file here is one of
four shapes painted in one of a handful of colours, and those colours have to
agree with `themerc` and with the GTK theme two directories up. Hand-writing
the files means forty places to change a token and forty chances for the
literal in a colour line to drift from the key it stands for. Here the shapes
and the tokens are code: `make theme` writes the files, and `make theme-check`
fails when the committed files and this script disagree.

The theme is deliberately flat:

- The title bar is a 1 px border row over a solid fill. Active is #141414 and
  inactive is #000000, so focus reads as a change of surface, not of hue: no
  colour is spent on chrome, and a window that loses focus does not change its
  content colours (gtk.css keeps those identical; the title bar alone says who
  has focus).
- The frame is five 1x1 files in the border colour, so a window is a 1 px line
  (#3D3D3D active, #2A2A2A inactive) on the black desktop. Thin borders are
  hard to grab by mouse, but Alt+right-drag still resizes, and a bot desktop
  rarely resizes by hand.
- The buttons are 1 px glyphs at a neutral brightness. Colour is reserved for
  status, so even close on hover stays neutral (#F2F1EE, not red).
- There is no menu button. `button_layout=|HMC` keeps hide, maximize and close
  only; a right-click on the title bar or Alt+Space opens the same window menu,
  and the nextgen chrome stays minimal.

Two XPM details matter because xfwm4 has its own parser (`parserc.c`), not
libXpm:

- A comment would be a parse error there, so `/* XPM */` is the only comment
  any file may contain.
- Each colour line carries a symbolic name *and* a literal fallback, such as
  `"a c #141414 s active_color_1"`. xfwm4 substitutes the symbolic name with
  the value from `themerc`; the literal is that same value, so a viewer that
  ignores symbols still shows the theme, and the `xfwm4-theme` test can prove
  the two never diverge.

Sizes and shape follow the design: a title file is 1x30, a border row over 29
fill rows. A top-left or top-right file is 1x30 of the border colour only,
every pixel: xfwm4 draws those two corners over the title bar's full height,
so a corner that copied the title left the window's side line missing beside
the title and an inactive title merged into the black around it. The four
edges and the bottom corners are 1x1, and every button is 30x30 with the glyph
in a 10x10 box at x 10..19, y 10..19. Adding them up: 10 title + 4 top + 10
edge + 16 button files, plus `themerc` and `README`, is 42 files.

Usage:
    tools/gen-xfwm4-theme.py --out DIR     write every file into DIR
    tools/gen-xfwm4-theme.py --check DIR   exit 1 if DIR differs from the output

The output is deterministic: same code, same bytes, in any locale, so
`--check` is a stable CI gate.
"""

import argparse
import os
import shutil
import sys
import tempfile

# The tokens, by the xfwm4 colour key that reads them. These are the values
# from the dark theme of plugins/backstage-plugin-teknoir-fleet/src/theme/
# tokens.css and the two derivatives the desktop needs.
COLOURS = {
    "active_text_color": "#F2F1EE",      # text
    "inactive_text_color": "#8C8C8C",    # muted
    "active_text_color_2": "#C7C5BF",    # text-2
    "inactive_text_color_2": "#8C8C8C",  # muted
    "active_color_1": "#141414",         # surface
    "inactive_color_1": "#000000",       # bg
    "active_border_color": "#3D3D3D",    # line-2
    "inactive_border_color": "#2A2A2A",  # line
    "active_hilight_1": "#1C1C1C",       # surface-2, the hover fill
    "inactive_hilight_1": "#1C1C1C",
    "active_mid_1": "#2A2A2A",           # line, the pressed fill
    "inactive_mid_1": "#2A2A2A",
}

# The keys `themerc` carries, in the order xfwm4's own default theme lists
# them: layout first, then offsets, then colours. The frame has no shadow and
# no compositor, so every shadow key is zero or off.
THEMERC = [
    ("button_layout", "|HMC"),
    ("button_offset", "0"),
    ("button_spacing", "0"),
    ("full_width_title", "true"),
    ("title_alignment", "left"),
    ("title_horizontal_offset", "10"),
    ("title_vertical_offset_active", "0"),
    ("title_vertical_offset_inactive", "0"),
    ("title_shadow_active", "false"),
    ("title_shadow_inactive", "false"),
    ("frame_border_top", "1"),
    ("maximized_offset", "1"),
    ("show_app_icon", "false"),
    ("shadow_opacity", "0"),
    ("shadow_delta_x", "0"),
    ("shadow_delta_y", "0"),
    ("shadow_delta_width", "0"),
    ("shadow_delta_height", "0"),
    ("active_text_color", COLOURS["active_text_color"]),
    ("inactive_text_color", COLOURS["inactive_text_color"]),
    ("active_text_color_2", COLOURS["active_text_color_2"]),
    ("inactive_text_color_2", COLOURS["inactive_text_color_2"]),
    ("active_color_1", COLOURS["active_color_1"]),
    ("inactive_color_1", COLOURS["inactive_color_1"]),
    ("active_border_color", COLOURS["active_border_color"]),
    ("inactive_border_color", COLOURS["inactive_border_color"]),
    ("active_hilight_1", COLOURS["active_hilight_1"]),
    ("inactive_hilight_1", COLOURS["inactive_hilight_1"]),
    ("active_mid_1", COLOURS["active_mid_1"]),
    ("inactive_mid_1", COLOURS["inactive_mid_1"]),
]

# Buttons: the three colour keys each state paints with, in the order border,
# fill, glyph. A prelight or pressed button always belongs to the focused
# window here (the pointer is over it), so it uses the active keys.
BUTTON_KEYS = {
    "active": ("active_border_color", "active_color_1", "active_text_color_2"),
    "inactive": ("inactive_border_color", "inactive_color_1", "inactive_text_color"),
    "prelight": ("active_border_color", "active_hilight_1", "active_text_color"),
    "pressed": ("active_border_color", "active_mid_1", "active_text_color"),
}

BUTTON_KINDS = ("close", "maximize", "hide", "maximize-toggled")
BUTTON_STATES = ("active", "inactive", "prelight", "pressed")

# One character per pixel: a dot is the fill, a plus the border, an at-sign
# the glyph. One char per pixel is enough for every file here, so cpp is 1.
FILL = "."
BORDER = "+"
GLYPH = "@"


def glyph(kind):
    """Return the set of (x, y) pixels of a button glyph.

    All glyphs live in the 10x10 box at x 10..19, y 10..19. They are 1 px
    strokes so that the same shape is legible at 30x30 on any scaling.
    """
    pixels = set()
    if kind == "close":
        # Two diagonals of the box; they meet in the middle.
        for i in range(10):
            pixels.add((10 + i, 10 + i))
            pixels.add((19 - i, 10 + i))
    elif kind == "maximize":
        # The outline of the 10x10 box.
        for x in range(10, 20):
            pixels.add((x, 10))
            pixels.add((x, 19))
        for y in range(10, 20):
            pixels.add((10, y))
            pixels.add((19, y))
    elif kind == "hide":
        # A single line near the bottom of the box.
        for x in range(10, 20):
            pixels.add((x, 18))
    elif kind == "maximize-toggled":
        # Restore: a small back square, then the front square over it.
        # The back square is drawn first (x 12..19, y 10..17); the front
        # square (x 10..17, y 12..19) then refills its own interior with the
        # fill colour, so the parts of the back square underneath vanish and
        # the two squares read as separate panes.
        for x in range(12, 20):
            pixels.add((x, 10))
            pixels.add((x, 17))
        for y in range(10, 18):
            pixels.add((12, y))
            pixels.add((19, y))
        # Drop anything inside the front square's interior (x 11..16,
        # y 13..18): that is the fill refill.
        pixels = {
            (x, y) for (x, y) in pixels
            if not (11 <= x <= 16 and 13 <= y <= 18)
        }
        # Then draw the front square's outline.
        for x in range(10, 18):
            pixels.add((x, 12))
            pixels.add((x, 19))
        for y in range(12, 20):
            pixels.add((10, y))
            pixels.add((17, y))
    else:  # pragma: no cover - the kinds above are the only callers
        raise ValueError("unknown glyph %r" % (kind,))
    return pixels


def xpm_identifier(filename):
    """The C symbol of an XPM file: `title-1-active.xpm` -> `title_1_active_xpm`.

    XPM3 wants a C identifier; the file name is the only natural one, with
    dashes (and the extension's dot) replaced by underscores.
    """
    stem = filename[:-4] if filename.endswith(".xpm") else filename
    return stem.replace("-", "_") + "_xpm"


def xpm_text(filename, width, height, rows, symbols):
    """Render one XPM3 file.

    `rows` are strings of pixel characters; `symbols` maps each pixel
    character to an xfwm4 colour key. `/* XPM */` is the only comment: xfwm4's
    parser would reject any other.
    """
    for row in rows:
        if len(row) != width:
            raise ValueError("%s: row %r is %d wide, want %d"
                             % (filename, row, len(row), width))
    if len(rows) != height:
        raise ValueError("%s: %d rows, want %d" % (filename, len(rows), height))

    lines = [
        "/* XPM */",
        "static char * %s[] = {" % xpm_identifier(filename),
        '"%d %d %d 1",' % (width, height, len(symbols)),
    ]
    for char, key in symbols:
        # Tab after the pixel character, as in the XPM3 examples, then
        # `c <literal>` for parsers that ignore symbols and `s <key>` for
        # xfwm4. The literal is the key's own themerc value, never a second
        # opinion about the colour.
        lines.append('"%s\tc %s s %s",' % (char, COLOURS[key], key))
    for row in rows:
        lines.append('"%s",' % row)
    lines.append("};")
    return "\n".join(lines) + "\n"


def bar_rows():
    """A 1x30 title file: the border row, then 29 fill rows.

    Width is 1, so every row is one character. Kept in one function so the
    shape of every 1x30 title file is defined once.
    """
    return [BORDER] + [FILL] * 29


def corner_rows():
    """A 1x30 top-left or top-right file: the border colour on every pixel.

    This was once a copy of the title bar, which left the side line missing
    for the title's whole height. xfwm4 stacks the corner file against the
    title, so the frame reads as a broken line beside the title, and an
    inactive title (#000000) merged into the black outside it. One colour,
    one symbol, and the line runs unbroken from the top edge down.
    """
    return [BORDER] * 30


def button_rows(kind, state):
    """A 30x30 button: border row 0, fill rows 1..29, the glyph on top."""
    grid = [[FILL for _ in range(30)] for _ in range(30)]
    for x in range(30):
        grid[0][x] = BORDER
    for x, y in glyph(kind):
        grid[y][x] = GLYPH
    return ["".join(row) for row in grid]


def build():
    """Return {filename: content} for the whole theme."""
    files = {}

    for state in ("active", "inactive"):
        border_key = state + "_border_color"
        fill_key = state + "_color_1"
        symbols = [(BORDER, border_key), (FILL, fill_key)]
        rows = bar_rows()
        # title-1..5 are the same 1x30 bar; xfwm4 wants one file per slot, and
        # they differ only in name.
        for n in range(1, 6):
            name = "title-%d-%s.xpm" % (n, state)
            files[name] = xpm_text(name, 1, 30, rows, symbols)
        # The top corners are the border colour for the title's full height,
        # not a copy of the bar: the side line has to run past the title.
        for corner in ("top-left", "top-right"):
            name = "%s-%s.xpm" % (corner, state)
            files[name] = xpm_text(name, 1, 30, corner_rows(),
                                   [(BORDER, border_key)])
        # The frame: one 1x1 file per edge, all in the border colour.
        for edge in ("left", "right", "bottom", "bottom-left", "bottom-right"):
            name = "%s-%s.xpm" % (edge, state)
            files[name] = xpm_text(name, 1, 1, [BORDER], [(BORDER, border_key)])

    for kind in BUTTON_KINDS:
        for state in BUTTON_STATES:
            name = "%s-%s.xpm" % (kind, state)
            border_key, fill_key, glyph_key = BUTTON_KEYS[state]
            symbols = [(BORDER, border_key), (FILL, fill_key), (GLYPH, glyph_key)]
            files[name] = xpm_text(name, 30, 30, button_rows(kind, state), symbols)

    files["themerc"] = (
        "# Generated by tools/gen-xfwm4-theme.py; run `make theme`; do not edit by hand.\n"
        "#\n"
        "# The layout keys come first, then the colours. Every XPM's colour line\n"
        "# carries the same value as its literal fallback, so a colour changed here\n"
        "# is all a colour change needs.\n"
        + "".join("%s=%s\n" % (key, value) for key, value in THEMERC)
    )

    files["README"] = (
        "Generated by tools/gen-xfwm4-theme.py; run `make theme`; do not edit by hand.\n"
        "\n"
        "A flat title bar: one border row over a solid fill, #141414 when the\n"
        "window has focus and #000000 when it does not, so focus reads as a change\n"
        "of surface and the chrome spends no colour. The buttons are 1 px glyphs on\n"
        "that fill, the frame is a 1 px line, and there is no menu button:\n"
        "right-click the title bar or press Alt+Space for the window menu. Resize\n"
        "with Alt+right-drag, since the 1 px border is hard to grab. The two top\n"
        "corners are border colour all the way down, so the side line is unbroken\n"
        "beside the title.\n"
    )

    return files


def write_tree(outdir, files):
    os.makedirs(outdir, exist_ok=True)
    for name, content in files.items():
        with open(os.path.join(outdir, name), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(content)


def cmd_out(outdir):
    files = build()
    write_tree(outdir, files)
    # A file this generator no longer writes (a shape dropped from the theme)
    # would stay behind and --check would report it as extra, which `make
    # theme` could never fix. Remove it here, and say which, so the removal is
    # visible rather than a silent delete. Only regular files: a directory in
    # the output is not a stale theme file.
    for name in sorted(os.listdir(outdir)):
        path = os.path.join(outdir, name)
        if name not in files and os.path.isfile(path):
            os.unlink(path)
            print("removed %s" % name)
    print("wrote %d files to %s" % (len(files), outdir))
    return 0


def cmd_check(outdir):
    """Regenerate into a temporary directory and compare name by name."""
    files = build()
    if not os.path.isdir(outdir):
        print("missing: %s is not a directory" % outdir)
        return 1

    tmpdir = tempfile.mkdtemp(prefix="teknoir-xfwm4-")
    problems = []
    try:
        write_tree(tmpdir, files)
        for name in sorted(files):
            path = os.path.join(outdir, name)
            if not os.path.isfile(path):
                problems.append("missing: %s" % name)
                continue
            with open(path, "rb") as have, open(os.path.join(tmpdir, name), "rb") as want:
                if have.read() != want.read():
                    problems.append("differs: %s" % name)
        for name in sorted(os.listdir(outdir)):
            if name not in files:
                problems.append("extra: %s" % name)
    finally:
        shutil.rmtree(tmpdir)

    if problems:
        print("\n".join(problems))
        print("run `make theme` to regenerate")
        return 1
    print("up to date: %d files" % len(files))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="Generate the xfwm4 theme Teknoir.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--out", metavar="DIR", help="write every file into DIR")
    group.add_argument("--check", metavar="DIR",
                       help="exit 1 unless DIR matches this generator's output")
    args = parser.parse_args(argv)
    if args.out is not None:
        return cmd_out(args.out)
    return cmd_check(args.check)


if __name__ == "__main__":
    sys.exit(main())
