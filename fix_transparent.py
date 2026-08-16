from PIL import Image
import numpy as np

# Load original generated image
orig_path = r"C:\Users\iqras\.gemini\antigravity-ide\brain\05af28ab-d646-4cc1-bb8a-bb63740ba8ac\hero_3d_shield_platform_1786901697952.png"
out_path = "frontend/public/hero_3d_shield_platform.png"

img = Image.open(orig_path).convert("RGBA")
arr = np.array(img, dtype=np.float32)

r, g, b, a = arr[:, :, 0], arr[:, :, 1], arr[:, :, 2], arr[:, :, 3]

# The top-left corner pixel color
bg_r, bg_g, bg_b = r[0, 0], g[0, 0], b[0, 0]
print(f"Background corner color: ({bg_r}, {bg_g}, {bg_b})")

# Calculate Euclidean distance from corner background color
dist = np.sqrt((r - bg_r)**2 + (g - bg_g)**2 + (b - bg_b)**2)

# Any pixel with color distance < 45 from the corner background is background!
# Create smooth alpha channel
alpha = np.clip((dist - 15.0) / 30.0 * 255.0, 0, 255)

arr[:, :, 3] = alpha
out = Image.fromarray(arr.astype(np.uint8))
out.save(out_path, "PNG")
print(f"Successfully saved 100% transparent PNG to {out_path}!")
