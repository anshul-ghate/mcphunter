"""HuggingFace Spaces entry point for MCPHunter Dashboard."""

import gradio as gr

from mcphunter.dashboard.app import create_app

app = create_app()
app.launch(
    server_name="0.0.0.0",
    theme=gr.themes.Soft(primary_hue="red", secondary_hue="blue", neutral_hue="slate"),
)
