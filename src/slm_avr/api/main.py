"""FastAPI backend exposing the slm-avr pipeline to a web frontend.

Two endpoints matter:
  - POST /api/scan        synchronous SAST-only scan
  - POST /api/remediate   runs the full agentic pipeline, streaming NDJSON
                           progress events (one JSON object per line) as
                           each pipeline stage completes, so the browser can
                           render the multi-agent loop live instead of
                           waiting on one long blocking request.
"""

from __future__ import annotations

import dataclasses
import json
import queue
import tempfile
import threading
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from slm_avr.config import Config
from slm_avr.models import Finding
from slm_avr.orchestrator import Orchestrator

PROJECT_ROOT = Path(__file__).resolve().parents[3]
BENCHMARK_DIR = PROJECT_ROOT / "benchmark"

app = FastAPI(title="slm-avr API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

_base_config = Config.load()


class ScanRequest(BaseModel):
    code: str
    filename: str = "app.py"


class RemediateRequest(BaseModel):
    code: str
    filename: str = "app.py"
    max_iterations: int | None = None


def _finding_to_dict(f: Finding) -> dict:
    return {
        "cwe_id": f.cwe_id,
        "cwe": f.cwe,
        "rule_id": f.rule_id,
        "message": f.message,
        "line": f.start_line,
        "end_line": f.end_line,
        "severity": f.severity,
        "snippet": f.lines,
    }


@app.get("/api/health")
def health() -> dict:
    return {
        "status": "ok",
        "llm_provider": _base_config.llm_provider,
        "model": _base_config.ollama.model,
    }


@app.get("/api/examples")
def examples() -> dict:
    """Vulnerable snippets from the seeded benchmark, for a quick-load
    dropdown in the frontend."""
    items = []
    for case_dir in sorted(BENCHMARK_DIR.glob("*/meta.json")):
        meta = json.loads(case_dir.read_text())
        target = case_dir.parent / meta["target_file"]
        items.append(
            {
                "name": meta["name"],
                "cwe_id": meta["cwe_id"],
                "description": meta.get("description", ""),
                "filename": meta["target_file"],
                "code": target.read_text(),
            }
        )
    return {"examples": items}


@app.post("/api/scan")
def scan(req: ScanRequest) -> dict:
    orchestrator = Orchestrator(_base_config)
    with tempfile.TemporaryDirectory(prefix="slm_avr_api_") as tmp:
        target = Path(tmp) / req.filename
        target.write_text(req.code)
        findings = orchestrator.scan(str(target))
    return {"findings": [_finding_to_dict(f) for f in findings]}


@app.post("/api/remediate")
def remediate(req: RemediateRequest) -> StreamingResponse:
    config = _base_config
    if req.max_iterations:
        config = dataclasses.replace(config, max_iterations=req.max_iterations)

    def event_stream():
        q: queue.Queue = queue.Queue()
        sentinel = object()

        def on_event(event: dict) -> None:
            q.put(event)

        def worker() -> None:
            try:
                orchestrator = Orchestrator(config)
                with tempfile.TemporaryDirectory(prefix="slm_avr_api_") as tmp:
                    target = Path(tmp) / req.filename
                    target.write_text(req.code)
                    report = orchestrator.remediate_file(
                        str(target), repo_root=tmp, on_event=on_event
                    )
                    q.put(
                        {
                            "type": "complete",
                            "final_source": report.final_source,
                            "fixed_count": report.fixed_count,
                            "total_count": report.total_count,
                        }
                    )
            except Exception as e:  # surfaced to the client, not swallowed
                q.put({"type": "error", "message": str(e)})
            finally:
                q.put(sentinel)

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()

        while True:
            item = q.get()
            if item is sentinel:
                break
            yield json.dumps(item) + "\n"

    return StreamingResponse(event_stream(), media_type="application/x-ndjson")
