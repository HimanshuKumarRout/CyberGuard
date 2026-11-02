"""
CYBERGUARD Root Launcher
Convenience launcher to run the FastAPI backend server with correct module paths.
Usage: python run_backend.py
"""
import sys
import os
from pathlib import Path

# Add backend directory to sys.path
backend_path = Path(__file__).resolve().parent / "backend"
if str(backend_path) not in sys.path:
    sys.path.insert(0, str(backend_path))

import uvicorn
from app.config import settings

if __name__ == "__main__":
    print(f"[*] Starting {settings.app_name} on http://{settings.host}:{settings.port}")
    print(f"[*] Swagger UI available at: http://127.0.0.1:{settings.port}/docs")
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.app_debug
    )
