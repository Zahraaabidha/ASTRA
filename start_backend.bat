@echo off
set PYTHONPATH=C:\Users\Aabidha\Desktop\astra_project
set OLLAMA_BASE=http://localhost:11434
set OLLAMA_MODEL=qwen2.5-coder:7b

echo Starting ASTRA backend on http://localhost:8000
C:\Users\Aabidha\Desktop\astra_project\venv\Scripts\uvicorn.exe backend.api.main:app --reload --port 8000 --host 0.0.0.0
