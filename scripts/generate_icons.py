from pathlib import Path
from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parent.parent
ICONS = ROOT / "src-tauri" / "icons"
ICONS.mkdir(parents=True, exist_ok=True)

SIZE = 1024
image = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
draw = ImageDraw.Draw(image)
draw.rounded_rectangle((24, 24, SIZE - 24, SIZE - 24), radius=190, fill=(10, 12, 16, 255), outline=(42, 51, 68, 255), width=8)
for step in range(160, SIZE, 160):
    draw.line((step, 96, step, SIZE - 96), fill=(27, 33, 45, 255), width=2)
    draw.line((96, step, SIZE - 96, step), fill=(27, 33, 45, 255), width=2)
draw.rounded_rectangle((70, 70, SIZE - 70, SIZE - 70), radius=150, outline=(30, 38, 52, 255), width=4)
points = [(322, 286), (322, 548), (512, 730), (702, 548), (702, 286)]
draw.line(points, fill=(43, 116, 255, 255), width=88, joint="curve")
draw.line([(372, 300), (372, 532), (512, 668), (652, 532), (652, 300)], fill=(107, 168, 255, 255), width=20, joint="curve")
draw.ellipse((484, 508, 540, 564), fill=(34, 211, 238, 255))
draw.ellipse((470, 494, 554, 578), outline=(34, 211, 238, 120), width=8)
draw.line((160, 800, 864, 800), fill=(42, 51, 68, 255), width=6)
for x in (160, 512, 864):
    draw.ellipse((x - 8, 792, x + 8, 808), fill=(34, 211, 238, 255))

image.save(ICONS / "icon.png")
for size, name in ((32, "32x32.png"), (128, "128x128.png"), (256, "128x128@2x.png")):
    icon = image.resize((size, size), Image.Resampling.LANCZOS)
    icon.save(ICONS / name)
image.resize((256, 256), Image.Resampling.LANCZOS).save(
    ICONS / "icon.ico",
    sizes=[(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (16, 16)],
)
print("icons written")
