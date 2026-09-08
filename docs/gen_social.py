#!/usr/bin/env python3
"""Generates the GitHub social preview (1280x640): dark technical aesthetic,
VEXOR wordmark, module chips, and the tagline. Readable at small sizes."""
import os
from PIL import Image, ImageDraw, ImageFont

OUT = os.path.join(os.path.dirname(__file__), "..", "docs", "assets", "social-preview.png")
W, H = 1280, 640
BG1, BG2 = (8, 11, 20), (16, 23, 42)
ACC1, ACC2 = (0, 210, 190), (168, 85, 247)
TXT, DIM = (232, 238, 247), (120, 132, 152)


def lerp(a, b, t):
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))


def font(size, bold=False, mono=False):
    paths = []
    if mono:
        paths = [
            "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf" if bold else "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        ]
    else:
        paths = [
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf" if bold else "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        ]
    for p in paths:
        if os.path.exists(p):
            return ImageFont.truetype(p, size)
    return ImageFont.load_default()


img = Image.new("RGB", (W, H))
px = img.load()
for y in range(H):
    for x in range(0, W, 4):
        t = x / W * 0.45 + y / H * 0.55
        col = lerp(BG1, BG2, t)
        for dx in range(4):
            if x + dx < W:
                px[x + dx, y] = col

d = ImageDraw.Draw(img)

# faint grid
for gx in range(0, W, 64):
    d.line([(gx, 0), (gx, H)], fill=(255, 255, 255, 4) if False else lerp(BG2, (30, 41, 66), 0.25), width=1)
for gy in range(0, H, 64):
    d.line([(0, gy), (W, gy)], fill=lerp(BG2, (30, 41, 66), 0.25), width=1)

# pipeline motif bottom-right: crawl -> probe -> chain -> prove -> report
f_node = font(26, bold=True, mono=True)
nodes = ["CRAWL", "PROBE", "CHAIN", "PROVE", "REPORT"]
nx, ny, nw, nh, gap = 700, 470, 96, 46, 26
for i, n in enumerate(nodes):
    x0 = nx + i * (nw + gap)
    d.rounded_rectangle([x0, ny, x0 + nw, ny + nh], radius=10,
                        outline=lerp(ACC1, ACC2, i / 4), width=2)
    d.text((x0 + nw / 2, ny + nh / 2), n, font=f_node, fill=TXT, anchor="mm")
    if i < len(nodes) - 1:
        d.line([(x0 + nw + 4, ny + nh / 2), (x0 + nw + gap - 6, ny + nh / 2)],
               fill=lerp(ACC1, ACC2, (i + .5) / 4), width=3)
        d.polygon([(x0 + nw + gap - 6, ny + nh / 2 - 6),
                   (x0 + nw + gap - 6, ny + nh / 2 + 6),
                   (x0 + nw + gap + 2, ny + nh / 2)],
                  fill=lerp(ACC1, ACC2, (i + .5) / 4))

# wordmark
f_vex = font(148, bold=True, mono=True)
d.text((84, 96), "VEXOR", font=f_vex, fill=TXT)

# accent underline
d.rounded_rectangle([90, 268, 560, 276], radius=4, fill=lerp(ACC1, ACC2, 0.5))

f_full = font(34)
d.text((88, 306), "Vulnerability EXploit & ORchestration", font=f_full, fill=lerp(ACC1, ACC2, 0.75))

f_tag = font(30)
d.text((88, 372), "Autonomous web vulnerability discovery and", font=f_tag, fill=DIM)
d.text((88, 412), "exploit-chain analysis — written in Go.", font=f_tag, fill=DIM)

# small footer chips
f_chip = font(22, mono=True)
chips = ["SQLi", "XSS", "CMDi", "SSTI", "LFI", "SSRF", "Redirect", "Misconfig", "Exposure"]
cx, cy = 88, 556
for c in chips:
    w = d.textlength(c, font=f_chip) + 26
    d.rounded_rectangle([cx, cy, cx + w, cy + 40], radius=20,
                        outline=lerp(ACC1, ACC2, 0.4), width=2)
    d.text((cx + w / 2, cy + 20), c, font=f_chip, fill=TXT, anchor="mm")
    cx += w + 14

os.makedirs(os.path.dirname(OUT), exist_ok=True)
img.save(OUT, optimize=True)
print("saved", os.path.abspath(OUT))
