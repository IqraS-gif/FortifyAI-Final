import os
import sys

root_dir = os.path.abspath(os.path.dirname(__file__))
backend_dir = os.path.join(root_dir, "backend")
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

import gradio as gr

with gr.Blocks(title="FortifyAI Security Engine") as demo:
    gr.Markdown("# 🛡️ FortifyAI Prompt Injection & Document Security Engine")
    gr.Markdown("""
    ## API is ONLINE
    
    This Hugging Face Space hosts the **FortifyAI FastAPI backend**.
    
    | Endpoint | Description |
    | --- | --- |
    | `/docs` | Interactive Swagger Documentation |
    | `/api/scan` | Prompt Injection Scanner |
    | `/api/projects` | Projects Management |
    | `/api/analytics` | Security Analytics |
    | `/api/retrain` | Model Re-Training |
    """)

from main import app as fastapi_app
import uvicorn

app = gr.mount_gradio_app(fastapi_app, demo, path="/")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=7860)
else:
    # Hugging Face Spaces entry point
    demo.launch(server_name="0.0.0.0", server_port=7860)
