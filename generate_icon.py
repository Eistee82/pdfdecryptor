"""Generates the pdfdecryptor.ico icon."""

from PIL import Image, ImageDraw, ImageFont


def create_icon():
    sizes = [256, 128, 64, 48, 32, 16]
    images = []

    for size in sizes:
        img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)

        # Document background (rounded rectangle)
        margin = size // 10
        doc_rect = [margin, margin, size - margin, size - margin]
        draw.rounded_rectangle(doc_rect, radius=size // 12, fill=(220, 50, 50), outline=(180, 30, 30), width=max(1, size // 40))

        # "PDF" text
        font_size = size // 4
        try:
            font = ImageFont.truetype("arialbd.ttf", font_size)
        except OSError:
            font = ImageFont.load_default()

        text = "PDF"
        bbox = draw.textbbox((0, 0), text, font=font)
        tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
        tx = (size - tw) // 2
        ty = size // 4 - th // 2 + margin
        draw.text((tx, ty), text, fill=(255, 255, 255), font=font)

        # Open lock symbol (lower half)
        lock_cx = size // 2
        lock_cy = int(size * 0.68)
        lock_w = size // 4
        lock_h = size // 5

        # Lock body
        body_rect = [
            lock_cx - lock_w // 2,
            lock_cy,
            lock_cx + lock_w // 2,
            lock_cy + lock_h,
        ]
        draw.rounded_rectangle(body_rect, radius=max(1, size // 40), fill=(255, 220, 80), outline=(200, 170, 40), width=max(1, size // 50))

        # Lock shackle (open — shifted to the right)
        arc_w = max(1, size // 20)
        arc_radius = lock_w // 3
        arc_rect = [
            lock_cx - arc_radius + arc_radius // 2,
            lock_cy - arc_radius,
            lock_cx + arc_radius + arc_radius // 2,
            lock_cy + arc_radius // 3,
        ]
        draw.arc(arc_rect, start=180, end=350, fill=(200, 170, 40), width=arc_w)

        images.append(img)

    images[0].save(
        "pdfdecryptor.ico",
        format="ICO",
        sizes=[(s, s) for s in sizes],
        append_images=images[1:],
    )
    print("pdfdecryptor.ico created.")


if __name__ == "__main__":
    create_icon()
