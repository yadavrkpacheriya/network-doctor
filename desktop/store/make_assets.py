"""Draws the Store logos (Assets/*.png) for the MSIX package: a blue rounded tile with a network-pulse mark."""
import os
import sys

from PIL import Image, ImageDraw

BLUE, WHITE = (29, 78, 216, 255), (255, 255, 255, 255)


def mark(size, w=None, h=None):
    w, h = w or size, h or size
    img = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    s = min(w, h)
    x0, y0 = (w - s) // 2, (h - s) // 2
    r = max(2, s // 6)
    d.rounded_rectangle([x0, y0, x0 + s - 1, y0 + s - 1], radius=r, fill=BLUE)
    # three linked nodes and a pulse line - "network" + "doctor"
    lw = max(1, s // 16)
    pts = [(x0 + s * 0.14, y0 + s * 0.56), (x0 + s * 0.36, y0 + s * 0.56), (x0 + s * 0.46, y0 + s * 0.30),
           (x0 + s * 0.58, y0 + s * 0.78), (x0 + s * 0.68, y0 + s * 0.56), (x0 + s * 0.86, y0 + s * 0.56)]
    d.line(pts, fill=WHITE, width=lw, joint="curve")
    for cx, cy in (pts[0], pts[-1]):
        rr = max(1, s // 14)
        d.ellipse([cx - rr, cy - rr, cx + rr, cy + rr], fill=WHITE)
    return img


def main(out):
    os.makedirs(out, exist_ok=True)
    for name, (w, h) in {"StoreLogo": (50, 50), "Square44x44Logo": (44, 44), "Square71x71Logo": (71, 71),
                         "Square150x150Logo": (150, 150), "Wide310x150Logo": (310, 150)}.items():
        # one plain file per logo: scale-qualified variants would need a resources.pri (makepri) as well
        mark(0, w, h).save(os.path.join(out, f"{name}.png"))
    mark(0, 256, 256).save(os.path.join(out, "AppIcon.png"))
    ico = mark(0, 256, 256)
    ico.save(os.path.join(out, "NetworkDoctor.ico"), sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "Assets")
