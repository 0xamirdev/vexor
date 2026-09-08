#!/usr/bin/env python3
"""Generates the VEXOR donation banner PNG: gradient card, Ethereum glyph,
EVM wallet address, and a scannable QR code pointing at the wallet."""
import os
from PIL import Image, ImageDraw, ImageFont
import qrcode

WALLET = "0x75a727b8eb0e08e5cf184e102aa7f28497127e1b"
OUT = os.path.join(os.path.dirname(__file__), "assets", "donate.png")
W, H = 1200, 630
BG1, BG2 = (13, 17, 23), (22, 27, 34)
ACC1, ACC2 = (0, 210, 190), (190, 60, 255)
TXT = (230, 237, 243)
DIM = (139, 148, 158)
CARD = (33, 38, 45)


def lerp(a, b, t):
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))


def find_font(size, bold=False):
    candidates = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf" if bold else "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf" if bold else "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/TTF/DejaVuSansMono-Bold.ttf",
    ]
    for c in candidates:
        if os.path.exists(c):
            return ImageFont.truetype(c, size)
    return ImageFont.load_default()


img = Image.new("RGB", (W, H))
px = img.load()

# Background gradient with subtle diagonal sweep
for y in range(H):
    for x in range(0, W, 4):
        t = (x / W * 0.35 + y / H * 0.65)
        col = lerp(BG1, BG2, t)
        for dx in range(4):
            if x + dx < W:
                px[x + dx, y] = col

d = ImageDraw.Draw(img)

# Accent glow lines (top-left to bottom-right)
for i, alpha in enumerate([120, 70, 30]):
    d.line([(0, 90 + i * 14), (W, 40 + i * 14)], fill=lerp(ACC1, ACC2, 0.15 + i * 0.1), width=2)

# Ethereum glyph (diamond) top-left
gx, gy, s = 92, 78, 34
top = (gx, gy)
mid_l = (gx - s, gy + s * 1.35)
mid_r = (gx + s, gy + s * 1.35)
bot = (gx, gy + s * 2.6)
left = (gx - s * 0.82, gy + s * 1.6)
right = (gx + s * 0.82, gy + s * 1.6)
d.polygon([top, mid_l, (gx, gy + s * 1.55)], fill=lerp(ACC1, ACC2, 0.55))
d.polygon([top, mid_r, (gx, gy + s * 1.55)], fill=lerp(ACC1, ACC2, 0.35))
d.polygon([left, right, bot], fill=lerp(ACC1, ACC2, 0.45))
d.polygon([(gx, gy + s * 1.55), mid_l, bot], fill=lerp(ACC1, ACC2, 0.30))
d.polygon([(gx, gy + s * 1.55), mid_r, bot], fill=lerp(ACC1, ACC2, 0.62))

f_title = find_font(54, bold=True)
f_sub = find_font(30)
f_addr = find_font(31, bold=True)
f_note = find_font(24)

d.text((gx + s * 1.8, gy - 6), "Support VEXOR", font=f_title, fill=TXT)
d.text((gx + s * 1.8, gy + 62), "Fuel the development of an open-source exploit engine", font=f_sub, fill=DIM)

# Wallet card
card_x, card_y, card_w, card_h = 92, 300, 660, 130
d.rounded_rectangle([card_x, card_y, card_x + card_w, card_y + card_h], radius=18, fill=CARD, outline=lerp(ACC1, ACC2, 0.5), width=2)
d.text((card_x + 28, card_y + 18), "EVM WALLET ADDRESS", font=find_font(20), fill=lerp(ACC1, ACC2, 0.85))
addr = WALLET
d.text((card_x + 28, card_y + 52), addr[:20], font=f_addr, fill=TXT)
d.text((card_x + 28, card_y + 92), addr[20:], font=f_addr, fill=TXT)

# Networks note
d.text((card_x, card_y + card_h + 28), "ETH  ·  BSC  ·  Polygon  ·  Arbitrum  ·  Base  —  any EVM network", font=f_note, fill=DIM)
d.text((card_x, card_y + card_h + 66), "Every donation goes straight into research, new probe modules, and coffee.", font=f_note, fill=DIM)

# QR code panel
qr = qrcode.QRCode(border=1, box_size=1)
qr.add_data(WALLET)
qr.make(fit=True)
qimg = qr.make_image(fill_color=(230, 237, 243), back_color=(33, 38, 45)).convert("RGB")
qx, qy, qs = 830, 300, 220
d.rounded_rectangle([qx - 18, qy - 18, qx + qs + 18, qy + qs + 18], radius=18, fill=CARD, outline=lerp(ACC1, ACC2, 0.5), width=2)
img.paste(qimg.resize((qs, qs), Image.NEAREST), (qx, qy))
d.text((qx - 12, qy + qs + 30), "SCAN TO DONATE", font=find_font(20), fill=lerp(ACC1, ACC2, 0.85))

os.makedirs(os.path.dirname(OUT), exist_ok=True)
img.save(OUT, optimize=True)
print("saved", OUT)
