#!/usr/bin/env python3
"""Render a recorded trace as a terminal window a report can print.

Usage: render_trace.py <output-file> <png-path> <title> <command>

The body comes from <output-file>, one line per line. The command is drawn as
the shell prompt would show it. No harness metadata is drawn: the provenance
lives in the capture link.
"""
import sys
from PIL import Image, ImageDraw, ImageFont

WIDTH = 1000
BAR = 34
PAD = 18
LINE = 19
FONT_CANDIDATES = (
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    "/usr/share/fonts/dejavu/DejaVuSansMono.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
    "/System/Library/Fonts/Menlo.ttc",
    "/Library/Fonts/Courier New.ttf",
    "C:\\Windows\\Fonts\\consola.ttf",
    "C:\\Windows\\Fonts\\cour.ttf",
    "DejaVuSansMono.ttf",
    "LiberationMono-Regular.ttf",
    "Consolas",
    "Courier New",
)
FONT_BOLD_CANDIDATES = (
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf",
    "/usr/share/fonts/dejavu/DejaVuSansMono-Bold.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationMono-Bold.ttf",
    "/System/Library/Fonts/Menlo.ttc",
    "/Library/Fonts/Courier New Bold.ttf",
    "C:\\Windows\\Fonts\\consolab.ttf",
    "C:\\Windows\\Fonts\\courbd.ttf",
    "DejaVuSansMono-Bold.ttf",
    "LiberationMono-Bold.ttf",
    "Consolas Bold",
    "Courier New Bold",
    *FONT_CANDIDATES,
)
BG = (30, 30, 30)
BAR_BG = (45, 45, 45)
TEXT = (201, 209, 217)
PROMPT = (121, 192, 255)
ARROW = (126, 231, 135)
COMMAND = (230, 237, 243)
TITLE = (176, 176, 176)


def load_font(candidates, size):
    for candidate in candidates:
        try:
            return ImageFont.truetype(candidate, size)
        except OSError:
            continue
    try:
        return ImageFont.load_default(size=size)
    except TypeError:
        return ImageFont.load_default()


def main():
    if len(sys.argv) < 5:
        print(
            "Usage: render_trace.py <output-file> <png-path> <title> <command>",
            file=sys.stderr,
        )
        sys.exit(2)
    source, dest, title, command = sys.argv[1:5]
    with open(source, encoding="utf-8", errors="replace") as handle:
        body = handle.read().rstrip("\n").split("\n")
    font = load_font(FONT_CANDIDATES, 14)
    bold = load_font(FONT_BOLD_CANDIDATES, 14)
    small = load_font(FONT_CANDIDATES, 12)
    measure = ImageDraw.Draw(Image.new("RGB", (1, 1)))

    def wrap(text, f, width):
        if not text:
            return [""]
        out, line = [], ""
        for word in text.split(" "):
            candidate = word if not line else line + " " + word
            if measure.textlength(candidate, font=f) <= width:
                line = candidate
            else:
                if line:
                    out.append(line)
                while measure.textlength(word, font=f) > width:
                    cut = len(word)
                    while cut > 1 and measure.textlength(word[:cut], font=f) > width:
                        cut -= 1
                    out.append(word[:cut])
                    word = word[cut:]
                line = word
        if line:
            out.append(line)
        return out

    prompt = "~"
    arrow = "\u203a"
    head = measure.textlength(prompt + " " + arrow + " ", font=bold)
    wrapped_command = wrap(command, bold, WIDTH - PAD * 2 - head)
    rows = []
    for index, part in enumerate(wrapped_command):
        rows.append((part, COMMAND, bold, head if index == 0 else PAD))
    rows.append(("", TEXT, font, PAD))
    for line in body:
        for part in wrap(line, font, WIDTH - PAD * 2):
            rows.append((part, TEXT, font, PAD))

    height = BAR + PAD * 2 + LINE * len(rows)
    image = Image.new("RGB", (WIDTH, height), BG)
    draw = ImageDraw.Draw(image)
    draw.rectangle([0, 0, WIDTH, BAR], fill=BAR_BG)
    for index, colour in enumerate(((255, 95, 86), (255, 189, 46), (39, 201, 63))):
        centre = PAD + 6 + index * 20
        draw.ellipse([centre - 6, BAR // 2 - 6, centre + 6, BAR // 2 + 6], fill=colour)
    try:
        draw.text((WIDTH // 2, BAR // 2), title[:60], font=small, fill=TITLE, anchor="mm")
    except ValueError:
        draw.text((PAD + 64, max(0, (BAR - 12) // 2)), title[:60], font=small, fill=TITLE)

    y = BAR + PAD
    draw.text((PAD, y), prompt, font=bold, fill=PROMPT)
    draw.text((PAD + measure.textlength(prompt + " ", font=bold), y), arrow, font=bold, fill=ARROW)
    for text, colour, face, offset in rows:
        draw.text((offset, y), text, font=face, fill=colour)
        y += LINE

    mask = Image.new("L", (WIDTH, height), 0)
    ImageDraw.Draw(mask).rounded_rectangle([0, 0, WIDTH - 1, height - 1], radius=10, fill=255)
    image.putalpha(mask)
    image.save(dest, "PNG")


if __name__ == "__main__":
    main()
