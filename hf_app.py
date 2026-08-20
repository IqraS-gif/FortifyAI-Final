import os
import sys

root_dir = os.path.abspath(os.path.dirname(__file__))
backend_dir = os.path.join(root_dir, "backend")
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from main import app as fastapi_app
import gradio as gr

# Minimal Gradio UI mounted at /ui
with gr.Blocks(title="FortifyAI Security Engine") as demo:
    gr.Markdown("# 🛡️ FortifyAI Prompt Injection & Document Security Engine")
    gr.Markdown("API is **ONLINE**. Use `/docs` for Swagger documentation.")

# Mount Gradio into FastAPI — single unified server, no port conflict
app = gr.mount_gradio_app(fastapi_app, demo, path="/ui")

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 7860))
    uvicorn.run(app, host="0.0.0.0", port=port)
