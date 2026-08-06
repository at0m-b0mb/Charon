#!/usr/bin/env python3
"""Draw Charon's banner and logo with Pillow.

Everything is generated — no binary design assets in the repo, so the artwork
can be regenerated at any size and stays in step with the palette the app
actually uses (imported from ``charon.ui.theme``, not copied).

    .venv/bin/python scripts/make_banner.py
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

from PIL import Image, ImageChops, ImageDraw, ImageFilter, ImageFont

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from charon.ui.theme import DARK  # noqa: E402
from charon.version import __version__  # noqa: E402

OUT = ROOT / "assets"


def rgb(value: str) -> tuple:
    value = value.lstrip("#")
    return tuple(int(value[i:i + 2], 16) for i in (0, 2, 4))


# Read from the application's own palette rather than copied beside it, so the
# artwork cannot drift away from what the program actually looks like.
INK = rgb(DARK.text)
MUTED = rgb(DARK.text_muted)
ACCENT = rgb(DARK.accent)
GREEN = rgb(DARK.secure)
TEAL = (45, 212, 191)      # one step warmer than the accent, for the hull

# The banner runs a little deeper than the app's own background: it is seen as
# an image on a web page, not as a window sitting behind content.
BG_TOP = (10, 15, 33)
BG_BOTTOM = (16, 28, 57)

FONT_CANDIDATES = {
    "display": [
        "/System/Library/Fonts/Supplemental/Futura.ttc",
        "/System/Library/Fonts/Avenir Next.ttc",
        "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "C:/Windows/Fonts/segoeuib.ttf",
    ],
    "body": [
        "/System/Library/Fonts/HelveticaNeue.ttc",
        "/System/Library/Fonts/Supplemental/Arial.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "C:/Windows/Fonts/segoeui.ttf",
    ],
    "mono": [
        "/System/Library/Fonts/Menlo.ttc",
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "C:/Windows/Fonts/consola.ttf",
    ],
}


def font(kind: str, size: int, index: int = 0) -> ImageFont.FreeTypeFont:
    for path in FONT_CANDIDATES[kind]:
        if Path(path).exists():
            try:
                return ImageFont.truetype(path, size, index=index)
            except OSError:
                continue
    return ImageFont.load_default(size)


def lerp(a, b, t):
    return tuple(int(round(x + (y - x) * t)) for x, y in zip(a, b))


def gradient(size: tuple[int, int], top, bottom) -> Image.Image:
    w, h = size
    base = Image.new("RGB", (1, h))
    px = base.load()
    for y in range(h):
        px[0, y] = lerp(top, bottom, y / max(1, h - 1))
    return base.resize((w, h), Image.BILINEAR)


def glow(size, centre, radius, colour, strength=1.0) -> Image.Image:
    """A soft radial light: an oversized blurred disc, meant to be *added*.

    It must not be alpha-composited — the layer is fully opaque, so compositing
    it would replace the gradient underneath with black instead of lighting it.
    """
    layer = Image.new("RGB", size, (0, 0, 0))
    draw = ImageDraw.Draw(layer)
    cx, cy = centre
    draw.ellipse([cx - radius, cy - radius, cx + radius, cy + radius],
                 fill=tuple(int(c * strength) for c in colour))
    return layer.filter(ImageFilter.GaussianBlur(radius * 0.55))


def draw_river(draw: ImageDraw.ImageDraw, w: int, y0: int, y1: int, seed: int = 7) -> None:
    """The Styx, as a data stream: horizontal light-trails of varying length.

    Charon ferries things across a river, and a file transfer is a stream of
    packets — the same picture serves both readings.
    """
    rng = random.Random(seed)
    for _ in range(140):
        y = rng.uniform(y0, y1)
        depth = (y - y0) / max(1.0, y1 - y0)          # 0 = far bank, 1 = near
        length = rng.uniform(40, 300) * (0.5 + depth)
        x = rng.uniform(-120, w)
        alpha = int((22 + 90 * depth) * rng.uniform(0.35, 1.0))
        colour = lerp(ACCENT, TEAL, rng.random())
        draw.line([(x, y), (x + length, y)], fill=colour + (alpha,),
                  width=1 if depth < 0.6 else 2)


def draw_mark(img: Image.Image, cx: int, cy: int, size: int) -> None:
    """The emblem: a shield, a ferry, and a locked box as cargo.

    Three shapes and no more.  An earlier version added a mast and a punting
    pole and the whole thing turned to noise at favicon size — the mark has to
    survive being 32 pixels wide, so every stroke has to earn its place.
    """
    layer = Image.new("RGBA", img.size, (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    s = size

    # --- shield: square shoulders, softly tapered point -------------------
    shield = [
        (cx - s * 0.40, cy - s * 0.44),
        (cx + s * 0.40, cy - s * 0.44),
        (cx + s * 0.40, cy + s * 0.02),
        (cx + s * 0.22, cy + s * 0.34),
        (cx, cy + s * 0.48),
        (cx - s * 0.22, cy + s * 0.34),
        (cx - s * 0.40, cy + s * 0.02),
    ]
    d.polygon(shield, fill=ACCENT + (24,))
    d.line(shield + [shield[0]], fill=ACCENT + (225,), width=4, joint="curve")

    # --- cargo: a padlock riding on the deck ------------------------------
    lw, lh = s * 0.22, s * 0.17
    lx, ly = cx - lw / 2, cy - s * 0.20
    d.arc([lx + lw * 0.16, ly - lh * 1.00, lx + lw * 0.84, ly + lh * 0.30],
          start=180, end=360, fill=GREEN + (240,), width=max(3, int(s * 0.020)))
    d.rounded_rectangle([lx, ly, lx + lw, ly + lh], radius=max(2, int(s * 0.022)),
                        fill=GREEN + (55,), outline=GREEN + (245,),
                        width=max(3, int(s * 0.020)))

    # --- hull -------------------------------------------------------------
    hull = [
        (cx - s * 0.26, cy + s * 0.04),
        (cx + s * 0.26, cy + s * 0.04),
        (cx + s * 0.14, cy + s * 0.19),
        (cx - s * 0.14, cy + s * 0.19),
    ]
    d.polygon(hull, fill=TEAL + (65,))
    d.line(hull + [hull[0]], fill=TEAL + (240,), width=max(3, int(s * 0.020)),
           joint="curve")

    # --- wake: two short lines, the direction of travel -------------------
    for i, half in enumerate((0.20, 0.12)):
        y = cy + s * (0.27 + i * 0.06)
        d.line([(cx - s * half, y), (cx + s * half, y)],
               fill=ACCENT + (120 - i * 45,), width=max(2, int(s * 0.014)))

    img.alpha_composite(layer)


def pill(draw: ImageDraw.ImageDraw, x: int, y: int, text: str, colour) -> int:
    f = font("body", 19)
    pad_x, pad_y = 15, 9
    box = draw.textbbox((0, 0), text, font=f)
    w, h = box[2] - box[0], box[3] - box[1]
    draw.rounded_rectangle([x, y, x + w + pad_x * 2, y + h + pad_y * 2],
                           radius=(h + pad_y * 2) // 2,
                           fill=colour + (26,), outline=colour + (130,), width=2)
    draw.text((x + pad_x, y + pad_y - box[1]), text, font=f, fill=colour + (255,))
    return x + w + pad_x * 2 + 12


def make_banner(width=1280, height=420) -> Image.Image:
    base = gradient((width, height), BG_TOP, BG_BOTTOM)

    # Both glows stay in the blue half of the palette: layering cyan over teal
    # on a near-black base turns the whole banner green.
    for centre, radius, colour, strength in (
        ((int(width * 0.16), int(height * 0.30)), 340, ACCENT, 0.10),
        ((int(width * 0.84), int(height * 0.50)), 300, ACCENT, 0.09),
        ((int(width * 0.84), int(height * 0.50)), 150, TEAL, 0.05),
    ):
        base = ImageChops.add(base, glow((width, height), centre, radius,
                                         colour, strength))
    img = base.convert("RGBA")

    overlay = Image.new("RGBA", img.size, (0, 0, 0, 0))
    draw = ImageDraw.Draw(overlay)
    draw_river(draw, width, int(height * 0.60), height - 6)
    img.alpha_composite(overlay)

    text_layer = Image.new("RGBA", img.size, (0, 0, 0, 0))
    d = ImageDraw.Draw(text_layer)

    left = 72
    title_font = font("display", 96)
    # Letterspacing by hand: PIL has no tracking control, and the wordmark needs
    # air to read as a mark rather than a word.
    x, y = left, 74
    for char in "CHARON":
        d.text((x, y), char, font=title_font, fill=INK)
        x += d.textlength(char, font=title_font) + 9

    d.text((left + 4, 190), "Secure SFTP / FTPS file transfer",
           font=font("body", 30), fill=MUTED)
    d.text((left + 4, 232),
           "Copy from your server. Paste on your machine. Verified on arrival.",
           font=font("body", 22), fill=lerp(MUTED, INK, 0.10))

    cursor = left + 4
    for label, colour in (("SSH + TLS 1.2+", ACCENT),
                          ("Host keys pinned", TEAL),
                          ("AES-256-GCM vault", GREEN),
                          ("SHA-256 verified", GREEN)):
        cursor = pill(d, cursor, 292, label, colour)

    d.text((width - 78, height - 44), f"v{__version__}",
           font=font("mono", 20), fill=lerp(MUTED, BG_BOTTOM, 0.15), anchor="rs")

    img.alpha_composite(text_layer)
    draw_mark(img, int(width * 0.855), int(height * 0.46), 196)
    return img.convert("RGB")


def make_logo(size=512) -> Image.Image:
    base = gradient((size, size), BG_TOP, BG_BOTTOM)
    base = ImageChops.add(
        base, glow((size, size), (size // 2, size // 2), size // 2, ACCENT, 0.12))
    img = base.convert("RGBA")
    draw_mark(img, size // 2, int(size * 0.47), int(size * 0.72))
    d = ImageDraw.Draw(img)
    d.text((size // 2, int(size * 0.90)), "CHARON", font=font("display", 54),
           fill=INK, anchor="ms")
    return img.convert("RGB")


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    banner = make_banner()
    banner.save(OUT / "banner.png")
    print(f"  assets/banner.png  ({banner.width}x{banner.height})")

    logo = make_logo()
    logo.save(OUT / "logo.png")
    print(f"  assets/logo.png  ({logo.width}x{logo.height})")

    social = make_banner(1280, 640)
    social.save(OUT / "social-preview.png")
    print(f"  assets/social-preview.png  ({social.width}x{social.height})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
