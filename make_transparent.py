from PIL import Image
import numpy as np

img_path = "frontend/public/hero_3d_shield_platform.png"
img = Image.open(img_path).convert("RGBA")
arr = np.array(img, dtype=np.float32)

# Extract R, G, B, A channels
r, g, b, a = arr[:, :, 0], arr[:, :, 1], arr[:, :, 2], arr[:, :, 3]

# Identify background pixels (light grayish-blue / off-white background)
# Background in the generated image is around RGB (235-255, 240-255, 245-255)
bg_mask = (r > 225) & (g > 232) & (b > 238)

# Feather the edges for smooth transparency
dist = np.minimum(np.minimum((255 - r)/30.0, (255 - g)/30.0), (255 - b)/30.0)
alpha = np.where(bg_mask, np.clip(dist * 255.0, 0, 255), 255.0)

arr[:, :, 3] = alpha
out = Image.fromarray(arr.astype(np.uint8))
out.save(img_path, "PNG")
print("Successfully made hero_3d_shield_platform.png background 100% transparent!")
