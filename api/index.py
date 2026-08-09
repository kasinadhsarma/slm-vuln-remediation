"""Vercel serverless entrypoint. Vercel auto-detects any api/*.py file that
exports an ASGI `app` and wraps it as a function. The actual application
lives in slm_avr/api/main.py so the exact same code runs here, on Render,
and locally via `uvicorn slm_avr.api.main:app`."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from slm_avr.api.main import app  # noqa: E402

__all__ = ["app"]
