from pathlib import Path
from PIL import Image, ImageOps

ROOT = Path(__file__).resolve().parent.parent
# Keep the supplied artwork intact: no crop, recolouring or generated replacement.
source = Image.open(ROOT / "icon.webp").convert("RGBA")
image = ImageOps.pad(source, (256, 256), method=Image.Resampling.LANCZOS,
                     color=(0, 0, 0, 0), centering=(0.5, 0.5))
for icons in (ROOT / "crates/ura-native/assets", ROOT / "src-tauri/icons"):
    icons.mkdir(parents=True, exist_ok=True)
    image.save(icons / "icon.png")
    for size, name in ((32, "32x32.png"), (128, "128x128.png"), (256, "128x128@2x.png")):
        image.resize((size, size), Image.Resampling.LANCZOS).save(icons / name)
    image.save(icons / "icon.ico", sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
print("Official URA icons generated from icon.webp")
