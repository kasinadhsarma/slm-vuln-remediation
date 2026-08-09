# slm-avr

**Retrieval-Augmented Autonomous Code Vulnerability Remediation using Static
Analysis-Guided Small Language Models.**

A working, locally-run implementation of the RAVEN-style architecture: a
deterministic SAST engine finds and verifies vulnerabilities, program
slicing reduces each finding to the code that actually matters, a local
Semantic Retriever supplies historical CWE fix exemplars, a Curator Agent
adds cross-file repository context, and a small on-premise language model
(via [Ollama](https://ollama.com)) generates patches that are iteratively
refined until they pass every check.

Everything runs on your machine. No cloud LLM API, no API cost, no code
leaves the host.

## Architecture

```
                 ┌─────────────────────────────────────────────┐
                 │                Orchestrator                 │
                 └─────────────────────────────────────────────┘
 file ──▶ SemgrepRunner ──▶ Finding(s)
                    │
                    ▼
            ProgramSlicer ──▶ CodeSlice (backward data-flow slice,
                    │          full function, imports)
                    ▼
          SemanticRetriever ──▶ top-k historical CWE fix exemplars
                    │            (local TF-IDF over cwe_fixes.json)
                    ▼
             CuratorAgent ──▶ cross-file callers / callees /
                    │          related global definitions
                    ▼
            PatchGenerator ──▶ candidate patch (Ollama SLM)
                    │
                    ▼
             PatchReviewer ──▶ syntax check → undefined-name check
                    │           (pyflakes) → SAST re-scan → sandboxed
                    │           pytest run
                    │
          ┌─────────┴─────────┐
          ▼                   ▼
        FIXED          feedback ──▶ regenerate (up to max_iterations)
```

Each stage maps directly onto a component described in the report:

| Report concept | This implementation |
|---|---|
| Static Analysis-Guided SLM | [`sast/semgrep_runner.py`](src/slm_avr/sast/semgrep_runner.py) — Semgrep with a bundled taint-aware ruleset ([`rules/custom_rules.yaml`](rules/custom_rules.yaml)) |
| Program slicing / PDG | [`slicing/slicer.py`](src/slm_avr/slicing/slicer.py) — AST-based backward data-flow slice, drops statements the vulnerable sink doesn't depend on |
| Semantic Retriever (Agentic RAG) | [`retrieval/vector_store.py`](src/slm_avr/retrieval/vector_store.py) — local TF-IDF/cosine retrieval over a curated CWE fix corpus, CWE-category-aware |
| Curator Agent | [`agents/curator.py`](src/slm_avr/agents/curator.py) — repo-wide AST index of callers, callees, and related global definitions |
| Patch Generator | [`agents/generator.py`](src/slm_avr/agents/generator.py) — builds the enriched prompt, calls the local SLM via Ollama |
| Patch Reviewer ("compiler-in-the-loop") | [`agents/reviewer.py`](src/slm_avr/agents/reviewer.py) — syntax + undefined-name + SAST re-scan + sandboxed test run, feeds structured failure feedback back to the Generator |
| Local SLM | [`llm/ollama_provider.py`](src/slm_avr/llm/ollama_provider.py) — any Ollama-served model (default `qwen2.5-coder:3b`) |
| Test-based evaluation (L-AVRBench) | [`eval/harness.py`](src/slm_avr/eval/harness.py) — grades on functional pass/fail, not token overlap |

### Why iterative refinement matters (a real example from development)

During testing, the Patch Generator once produced a fix for a hardcoded
password that also invented an undefined `db.connect(...)` call, copied
from a retrieval exemplar's illustrative context. This patch was
syntactically valid and even passed the SAST re-scan — a textbook
"plausible but incorrect" patch. The Patch Reviewer's `pyflakes`
undefined-name check caught it, fed `"undefined name: db"` back to the
Generator, and the next iteration produced a clean fix. This is exactly the
failure mode the report describes as the core reason match-based (BLEU/EM)
evaluation is unreliable, and why deterministic, multi-stage verification is
necessary.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Install [Ollama](https://ollama.com/download) and pull a small local coding
model:

```bash
ollama pull qwen2.5-coder:3b
```

`qwen2.5-coder:3b` (~1.9GB) is the default — it runs on modest hardware
(tested on 14GB RAM, no GPU required) and is fully free and on-premise. For
better patch quality on stronger hardware, swap in `qwen2.5-coder:7b` or
`deepseek-coder:6.7b` via `config.yaml`.

## Usage

```bash
# Static analysis only
slm-avr scan path/to/file.py

# Detect and remediate, iteratively, writing the patch back
slm-avr remediate path/to/file.py --repo-root path/to/repo --apply

# Detect and remediate + verify against the project's test suite
slm-avr remediate path/to/file.py --test-dir path/to/repo --apply

# Run the L-AVRBench-style evaluation harness against the seeded benchmark
slm-avr benchmark
```

`remediate` without `--apply` is a dry run: it shows what would change and
the verdict for each finding without writing anything.

## Web UI

A small FastAPI backend + Next.js frontend let you paste code in a browser,
scan it, and watch the multi-agent remediation loop run live (slicing,
retrieval, curator, generation, review -- one line per pipeline event,
streamed as newline-delimited JSON).

```bash
# Terminal 1 -- API backend (wraps the same Orchestrator the CLI uses)
source .venv/bin/activate
uvicorn slm_avr.api.main:app --reload --port 8000

# Terminal 2 -- frontend
cd web
npm install   # first time only
npm run dev
```

Open http://localhost:3000. The "Load an example..." dropdown pulls the six
seeded benchmark cases straight from `/api/examples`, so you can try a
full run without writing any code.

Backend API surface:

| Endpoint | Method | Description |
|---|---|---|
| `/api/health` | GET | provider/model status |
| `/api/examples` | GET | the six seeded benchmark snippets |
| `/api/scan` | POST | `{code, filename}` -> SAST findings, no remediation |
| `/api/remediate` | POST | `{code, filename, max_iterations?}` -> NDJSON stream of pipeline events, ending with a `complete` event carrying the final patched source |

The frontend reads `NEXT_PUBLIC_API_BASE_URL` (defaults to
`http://localhost:8000`) if the backend runs elsewhere.

## Deployment

The frontend and backend deploy to **different kinds of platforms** -- this
is not a Vercel-only app.

- **Frontend (Next.js) -> Vercel.** This is exactly what Vercel is built for.
- **Backend (FastAPI + Semgrep) -> a regular always-on host, not Vercel
  serverless functions.** Semgrep alone installs to ~260MB, which exceeds
  Vercel's serverless function size limits (50MB Hobby / 250MB Pro,
  unzipped), and the remediation loop's shape (a background thread streaming
  progress over a long-lived connection) doesn't fit a stateless,
  short-lived function model well either. Render, Railway, Fly.io, or any
  plain VPS all work fine since Semgrep just runs as a normal subprocess
  there, same as it does locally.
- **The LLM itself -> a hosted OpenAI-compatible inference API**, not a
  self-hosted Ollama. This avoids needing a server with the model loaded in
  memory at all; the backend just makes an HTTPS call. This is the
  `openai_compatible` provider ([`llm/openai_compatible_provider.py`](src/slm_avr/llm/openai_compatible_provider.py))
  -- it works with **any** provider that speaks the OpenAI chat-completions
  format: [Together.ai](https://together.ai) (hosts
  `Qwen/Qwen2.5-Coder-32B-Instruct`, the exact flagship model from the
  report), Fireworks.ai, Groq, OpenRouter, or a self-hosted vLLM server.
  Running Ollama yourself (a VPS with the model pulled) remains a valid,
  fully free/on-premise alternative -- see [Setup](#setup) -- this section
  covers the zero-self-hosting path.

### 1. Backend on Render

[`render.yaml`](render.yaml) is a ready-to-use Render Blueprint. In the
Render dashboard: **New -> Blueprint**, point it at this repo, and it will
provision a web service with the right build/start commands. Then set the
one secret it doesn't fill in for you:

```bash
OPENAI_COMPATIBLE_API_KEY=<your Together.ai / Fireworks / Groq / ... key>
```

Or configure manually as a Render Web Service:

```
Build command:  pip install --upgrade pip && pip install -e .
Start command:  uvicorn slm_avr.api.main:app --host 0.0.0.0 --port $PORT
Health check:   /api/health
```

Environment variables:

| Variable | Value |
|---|---|
| `SLM_AVR_LLM_PROVIDER` | `openai_compatible` |
| `OPENAI_COMPATIBLE_BASE_URL` | e.g. `https://api.together.xyz/v1` |
| `OPENAI_COMPATIBLE_MODEL` | e.g. `Qwen/Qwen2.5-Coder-32B-Instruct` |
| `OPENAI_COMPATIBLE_API_KEY` | your provider API key (secret) |
| `ALLOWED_ORIGINS` | your Vercel domain once known, e.g. `https://your-app.vercel.app` (defaults to `*`) |

Every `Config` field can be set this way -- see [`config.py`](src/slm_avr/config.py)
for the full env var list -- so the same code runs locally against Ollama
and in production against a hosted API with no code changes, just
different environment variables.

### 2. Frontend on Vercel

Import the repo in Vercel, set the **root directory to `web/`**, and add one
environment variable:

```
NEXT_PUBLIC_API_BASE_URL=https://<your-render-service>.onrender.com
```

Vercel auto-detects Next.js; no other configuration is needed. Once both
are live, go back to Render and tighten `ALLOWED_ORIGINS` to your actual
Vercel URL instead of `*`.

## Benchmark

[`benchmark/`](benchmark/) contains six seeded, self-contained
vulnerability cases (CWE-89 SQL injection, CWE-78 command injection, CWE-22
path traversal, CWE-798 hardcoded credentials, CWE-327 weak crypto, CWE-502
insecure deserialization). Each case has a vulnerable module and a pytest
suite with both a functional test and a security/exploit test that fails
against the vulnerable baseline and only passes once the vulnerability is
actually closed -- not just superficially patched.

```bash
slm-avr benchmark
```

With `qwen2.5-coder:3b`, this currently achieves a **100% repair success
rate (6/6)** on the seeded benchmark, in 1-2 refinement iterations per case
-- see [`eval_report.md`](eval_report.md) for the latest run.

## Known limitations

This is a research prototype, and several simplifications from the
production architecture described in the report are worth being explicit
about:

- **Slicing** is an AST-based approximation (statement-level backward
  data-flow), not a full Program Dependency Graph built by a tool like
  Joern.
- **Retrieval** is local TF-IDF over a small (~12-exemplar) hand-curated
  corpus, not a large vector database of real historical commits.
- **The SAST rules** are a small bundled Semgrep ruleset covering 6 CWE
  classes for Python, not CodeQL's full query suite. Path-traversal
  detection in particular required explicit structural exclusions for known
  safe idioms (`os.path.basename`, `os.path.realpath` + containment check)
  since Semgrep's taint-mode sanitizers did not reliably propagate through
  variable reassignment in testing -- a good example of the "SAST tools are
  prone to false positives" problem the report itself calls out.
- **Undefined-name checking** (`pyflakes`) catches missing names but not
  missing third-party packages that aren't installed, or deeper semantic
  errors -- the sandboxed pytest run (`--test-dir`) is the strongest
  functional guarantee this pipeline provides, matching the report's own
  argument for test-based over match-based evaluation.
- **RAG poisoning and LoRA supply-chain attacks**, discussed in the report
  as a real operational risk for production deployments, are out of scope
  for this local research prototype (the exemplar corpus is a static,
  version-controlled JSON file with no external write path).

## Project layout

```
rules/custom_rules.yaml          bundled Semgrep ruleset (6 CWE classes)
src/slm_avr/
  sast/semgrep_runner.py         SAST wrapper + finding parser
  slicing/slicer.py              AST-based program slicer
  retrieval/                     Semantic Retriever + exemplar corpus
  agents/curator.py              cross-file dependency scanner
  agents/generator.py            Patch Generator (prompt building)
  agents/reviewer.py             Patch Reviewer (verification)
  llm/                           LLM provider abstraction (Ollama / OpenAI-compatible / mock)
  orchestrator.py                wires it all into the iterative loop
  eval/harness.py                L-AVRBench-style evaluation harness
  cli.py                         slm-avr command-line interface
  api/main.py                    FastAPI backend (scan / remediate / examples)
benchmark/                       seeded vulnerability + test cases
web/                             Next.js frontend (App Router + TypeScript + Tailwind)
render.yaml                      Render Blueprint for the backend
```

## Reference

Built from the research report *"Retrieval-Augmented Autonomous Code
Vulnerability Remediation using Static Analysis-Guided Small Language
Models,"* which surveys RAVEN, VulKey, L-AVRBench, GitHub Copilot Autofix,
and the broader SLM/Agentic RAG/SAST literature this architecture is based
on.
