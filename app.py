import os
import sys

# Ensure project root is in python path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

import gradio as gr
from backend.main import app as fastapi_app

# Mount FastAPI app inside Gradio for 100% FREE Hugging Face Space deployment
demo = gr.Interface(
    fn=lambda text: f"FortifyAI API is running! Docs available at /docs",
    inputs="text",
    outputs="text",
    title="FortifyAI Prompt Injection & Document Security Engine",
    description="Enterprise Prompt Injection Protection API. OpenAPI Swagger docs accessible at /docs endpoint."
)

app = gr.mount_gradio_app(fastapi_app, demo, path="/")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=7860)
