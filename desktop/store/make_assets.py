"""Store logos (Assets/*.png) for the MSIX package, made from the Android app's launcher icon so the Windows
and phone apps look the same."""
import os
import sys

from PIL import Image

HERE = os.path.dirname(os.path.abspath(__file__))
SOURCE = os.path.join(HERE, "..", "..", "mobile", "android", "app", "src", "main", "res", "mipmap-xxxhdpi",
                      "ic_launcher.png")


def icon(size):
    return Image.open(SOURCE).convert("RGBA").resize((size, size), Image.LANCZOS)


def tile(w, h):
    """The icon centred on a transparent tile of w x h."""
    img = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    s = min(w, h)
    img.paste(icon(s), ((w - s) // 2, (h - s) // 2))
    return img


def main(out):
    os.makedirs(out, exist_ok=True)
    # one plain file per logo: scale-qualified variants would need a resources.pri (makepri) as well
    for name, (w, h) in {"StoreLogo": (50, 50), "Square44x44Logo": (44, 44), "Square71x71Logo": (71, 71),
                         "Square150x150Logo": (150, 150), "Wide310x150Logo": (310, 150)}.items():
        tile(w, h).save(os.path.join(out, f"{name}.png"))


def make_ico(path):
    """The Windows exe icon (same picture)."""
    icon(192).save(path, sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (192, 192)])


if __name__ == "__main__":
    if len(sys.argv) > 2 and sys.argv[1] == "--ico":
        make_ico(sys.argv[2])
    else:
        main(sys.argv[1] if len(sys.argv) > 1 else "Assets")
