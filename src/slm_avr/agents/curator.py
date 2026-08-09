"""Curator Agent: repository-wide cross-file dependency scanning.

Many critical vulnerabilities (race conditions, use-after-free, type
confusions) are hard to patch correctly because the root cause lives in a
different file than the vulnerable sink. The Curator Agent scans the target
repository to find:

  - callers: other functions in the repo that call the vulnerable function
  - callees: functions/names used inside the vulnerable function that are
    actually defined elsewhere in the repo
  - related_definitions: repo-wide definitions of ALL-CAPS constants
    referenced by the vulnerable function (common home for security-relevant
    config like an allowed base directory or an allowlist)
  - imported_by: other modules that import the vulnerable file's module

This is a lightweight, AST-based approximation of RAVEN's Curator Agent --
no execution, no external tools, just a repo-wide static index.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from slm_avr.models import CrossFileContext

_IGNORED_DIRS = {".git", ".venv", "venv", "__pycache__", "node_modules", ".semgrep"}


@dataclass
class _FileIndex:
    path: Path
    module_name: str
    function_defs: set[str] = field(default_factory=set)
    global_assigns: set[str] = field(default_factory=set)
    imports: set[str] = field(default_factory=set)
    calls: dict[str, list[int]] = field(default_factory=dict)


class CuratorAgent:
    def __init__(self, repo_root: str):
        self.repo_root = Path(repo_root).resolve()
        self._index: list[_FileIndex] = self._build_index()

    def _python_files(self) -> list[Path]:
        files = []
        for p in self.repo_root.rglob("*.py"):
            if any(part in _IGNORED_DIRS for part in p.parts):
                continue
            files.append(p)
        return files

    def _build_index(self) -> list[_FileIndex]:
        index = []
        for file_path in self._python_files():
            try:
                source = file_path.read_text()
                tree = ast.parse(source)
            except (OSError, SyntaxError):
                continue

            fi = _FileIndex(
                path=file_path,
                module_name=file_path.stem,
            )
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    fi.function_defs.add(node.name)
                elif isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            fi.global_assigns.add(target.id)
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        fi.imports.add(alias.name)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    fi.imports.add(node.module)
                elif isinstance(node, ast.Call):
                    fname = self._call_name(node)
                    if fname:
                        fi.calls.setdefault(fname, []).append(
                            getattr(node, "lineno", 0)
                        )
            index.append(fi)
        return index

    @staticmethod
    def _call_name(node: ast.Call) -> str | None:
        func = node.func
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            return func.attr
        return None

    def gather(
        self,
        file_path: str,
        function_name: str,
        referenced_names: set[str],
    ) -> CrossFileContext:
        target_path = Path(file_path).resolve()
        target_module = target_path.stem

        callers: list[str] = []
        callees: list[str] = []
        related_definitions: list[str] = []
        imported_by: list[str] = []

        for fi in self._index:
            is_same_file = fi.path == target_path

            if not is_same_file and function_name in fi.calls:
                lines = ",".join(str(ln) for ln in fi.calls[function_name])
                rel = self._relpath(fi.path)
                callers.append(f"{rel}: calls {function_name}() at line(s) {lines}")

            if not is_same_file and function_name in fi.function_defs:
                pass  # handled by definition search below if needed

            if not is_same_file and any(
                target_module in modname.split(".") for modname in fi.imports
            ):
                imported_by.append(self._relpath(fi.path))

            for name in referenced_names:
                if is_same_file:
                    continue
                if name in fi.function_defs:
                    callees.append(f"{name}() defined in {self._relpath(fi.path)}")
                if name in fi.global_assigns:
                    related_definitions.append(
                        f"{name} defined in {self._relpath(fi.path)}"
                    )

        return CrossFileContext(
            callers=sorted(set(callers)),
            callees=sorted(set(callees)),
            related_definitions=sorted(set(related_definitions)),
            imported_by=sorted(set(imported_by)),
        )

    def _relpath(self, path: Path) -> str:
        try:
            return str(path.relative_to(self.repo_root))
        except ValueError:
            return str(path)
