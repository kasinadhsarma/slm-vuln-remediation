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
  llm/                           LLM provider abstraction (Ollama / mock)
  orchestrator.py                wires it all into the iterative loop
  eval/harness.py                L-AVRBench-style evaluation harness
  cli.py                         slm-avr command-line interface
benchmark/                       seeded vulnerability + test cases
```

## Reference

Built from the research report *"Retrieval-Augmented Autonomous Code
Vulnerability Remediation using Static Analysis-Guided Small Language
Models,"* which surveys RAVEN, VulKey, L-AVRBench, GitHub Copilot Autofix,
and the broader SLM/Agentic RAG/SAST literature this architecture is based
on.
