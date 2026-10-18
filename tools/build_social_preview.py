"""Build docs/images/social-preview.png, the GitHub social preview.

The image is the README's first screen as a 1280 by 640 card: the
figlet wordmark from docs/images/wordmark.svg, in its dark-theme
fill on GitHub's dark ground, and the README's tagline under it,
character for character. Both are read from those two files, so the
card cannot drift from the README by hand: change the tagline there,
run this, and upload the result in the repository settings (Settings,
General, Social preview), which has no API.

    pip install Pillow
    python tools/build_social_preview.py

Pillow is the one dependency, and it is this script's alone: the
tools that ship (loxodonta.py, supervisor.py, receiver.py,
verifier.py) stay on the standard library. The fonts are the first
found of each list below; on Windows that is Consolas and Segoe UI,
which the first card (#133) was drawn in. The placement numbers were
measured from that card, so a rebuild lands where it did. Text is
drawn at four times the size and scaled down, which smooths the
edges. The file carries the critical chunks only:
no text, no timestamp, no colour profile.
"""

import os
import sys
import xml.etree.ElementTree as ET

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:
    sys.exit("this script needs Pillow: pip install Pillow")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
README = os.path.join(ROOT, "README.md")
WORDMARK = os.path.join(ROOT, "docs", "images", "wordmark.svg")
OUT = os.path.join(ROOT, "docs", "images", "social-preview.png")

WIDTH, HEIGHT = 1280, 640
BACKGROUND = "#0d1117"    # GitHub's dark ground
WORDMARK_FILL = "#5eead4"  # the wordmark's dark-theme fill
TAGLINE_FILL = "#c9d1d9"   # GitHub's dark-theme text

# Measured from the first card: where the ink starts, not the glyph box.
WORDMARK_SIZE = 21         # px; the lines are 23.75 px apart
WORDMARK_PITCH = 23.75
WORDMARK_INK_LEFT, WORDMARK_INK_TOP = 140, 212
TAGLINE_SIZE = 40
TAGLINE_INK_TOP = 401      # centred on the width
SCALE = 4                  # drawn at this multiple, then scaled down

MONO_FONTS = ["C:/Windows/Fonts/consola.ttf",
              "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
              "/System/Library/Fonts/Menlo.ttc"]
TEXT_FONTS = ["C:/Windows/Fonts/segoeui.ttf",
              "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
              "/System/Library/Fonts/Helvetica.ttc"]


def first_font(paths, size):
    for path in paths:
        if os.path.isfile(path):
            return ImageFont.truetype(path, size * SCALE)
    sys.exit("no font found; tried " + ", ".join(paths))


def wordmark_lines():
    tree = ET.parse(WORDMARK)
    ns = "{http://www.w3.org/2000/svg}"
    return [node.text for node in tree.getroot().iter(ns + "text")]


def tagline():
    with open(README, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line.startswith("**") and line.endswith("**"):
                return line[2:-2]
    sys.exit("no bold tagline line found in README.md")


def ink(lines, font, pitch, stroke=0):
    """A mask of the lines drawn at (0, 0), cropped to its ink."""
    canvas = Image.new("L", (WIDTH * SCALE, HEIGHT * SCALE), 0)
    draw = ImageDraw.Draw(canvas)
    for n, line in enumerate(lines):
        draw.text((0, round(n * pitch * SCALE)), line, font=font, fill=255,
                  stroke_width=stroke, stroke_fill=255)
    return canvas.crop(canvas.getbbox())


def main():
    big = Image.new("RGB", (WIDTH * SCALE, HEIGHT * SCALE), BACKGROUND)

    # A quarter pixel of stroke: the weight the first card's renderer
    # gave the mark, which a plain draw lands a little under.
    mark = ink(wordmark_lines(), first_font(MONO_FONTS, WORDMARK_SIZE),
               WORDMARK_PITCH, stroke=1)
    big.paste(WORDMARK_FILL,
              (WORDMARK_INK_LEFT * SCALE, WORDMARK_INK_TOP * SCALE), mark)

    line = ink([tagline()], first_font(TEXT_FONTS, TAGLINE_SIZE), 0)
    left = (WIDTH * SCALE - line.width) // 2
    big.paste(TAGLINE_FILL, (left, TAGLINE_INK_TOP * SCALE), line)

    card = big.resize((WIDTH, HEIGHT), Image.LANCZOS)
    card.save(OUT, "PNG")
    print("wrote", os.path.relpath(OUT, ROOT), "with the tagline:",
          tagline())


if __name__ == "__main__":
    main()
