import os
import sys
import gradio as gr
import requests

BACKEND_URL = os.environ.get("BACKEND_URL", "https://fortifyai-final.onrender.com")

def scan_prompt(text, sensitivity):
    try:
        response = requests.post(
            f"{BACKEND_URL}/api/scan/prompt",
            json={"text": text, "sensitivity_profile": sensitivity},
            timeout=30
        )
        data = response.json()
        action = data.get("action", "UNKNOWN")
        risk = data.get("risk_score", 0)
        summary = data.get("human_summary", "")
        color = "🔴" if action == "BLOCKED" else "🟡" if action == "FLAGGED" else "🟢"
        return f"{color} **{action}** | Risk Score: {risk}/100\n\n{summary}"
    except Exception as e:
        return f"⚠️ Error connecting to backend: {str(e)}"

with gr.Blocks(title="FortifyAI Security Engine", theme=gr.themes.Soft()) as demo:
    gr.Markdown("# 🛡️ FortifyAI — Prompt Injection & Document Security Engine")
    gr.Markdown(f"**API Backend**: [{BACKEND_URL}/docs]({BACKEND_URL}/docs)")

    with gr.Tab("Prompt Scanner"):
        with gr.Row():
            with gr.Column():
                prompt_input = gr.Textbox(
                    label="Input Text to Scan",
                    placeholder="Enter prompt or text to scan for injection attacks...",
                    lines=5
                )
                sensitivity = gr.Radio(
                    choices=["FINANCE_STRICT", "BALANCED", "SUPPORT_LENIENT"],
                    value="BALANCED",
                    label="Sensitivity Profile"
                )
                scan_btn = gr.Button("🔍 Scan", variant="primary")
            with gr.Column():
                result_output = gr.Markdown(label="Scan Result")

        scan_btn.click(
            fn=scan_prompt,
            inputs=[prompt_input, sensitivity],
            outputs=result_output
        )

    with gr.Tab("API Documentation"):
        gr.Markdown(f"""
        ## Available API Endpoints
        
        | Endpoint | Method | Description |
        |---|---|---|
        | `/api/scan/prompt` | POST | Scan text for prompt injection |
        | `/api/scan/document` | POST | Scan PDF/DOCX for hidden injections |
        | `/api/scan/web` | POST | Scan a website URL |
        | `/api/projects` | GET/POST | Manage projects |
        | `/api/analytics` | GET | Security analytics |
        | `/api/retrain` | POST | Submit feedback for retraining |
        
        **Full Swagger Docs**: [{BACKEND_URL}/docs]({BACKEND_URL}/docs)
        """)

demo.launch(server_name="0.0.0.0", server_port=7860)
