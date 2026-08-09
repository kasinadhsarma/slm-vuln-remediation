"""AST-based program slicing.

Real AVR frameworks build a full Program Dependency Graph (control-flow +
data-flow) via tools like Joern to compute precise slices. Doing that
requires a heavyweight external engine; this module implements a pragmatic
approximation using Python's built-in `ast` module:

1. Locate the function (or module scope) enclosing the vulnerable line.
2. Break its body into top-level statement units, each tagged with the line
   range it spans and the variable names it reads (Load) / defines (Store).
3. Starting from the statement containing the vulnerable line, walk
   backward, pulling in any earlier statement that defines a variable the
   slice currently depends on (transitive backward data-flow slice).

The result discards logging calls, unrelated branches, and other statements
that don't feed the vulnerable sink, so the SLM's prompt stays focused on
the statements that actually matter -- mirroring the "distracting token
elimination" role slicing plays in the report.
"""

from __future__ import annotations

import ast

from slm_avr.models import CodeSlice


class SliceError(RuntimeError):
    pass


class ProgramSlicer:
    def slice(self, source: str, file_path: str, target_line: int) -> CodeSlice:
        try:
            tree = ast.parse(source)
        except SyntaxError as e:
            raise SliceError(f"could not parse {file_path}: {e}") from e

        imports = self._collect_imports(tree)
        enclosing = self._find_enclosing_scope(tree, target_line)

        if enclosing is None:
            # Vulnerable line lives at module level (no enclosing function).
            # Bound the replacement to just the target top-level statement
            # (plus its backward data-flow dependencies) -- NOT the whole
            # file, otherwise the generator's reply overwrites every import
            # and every other function in the module.
            source_lines = source.splitlines()
            units = self._statement_units(tree.body)
            included = self._backward_slice(units, target_line)

            target_unit = self._unit_at_line(units, target_line)
            if target_unit is None:
                # Couldn't isolate a single statement; fall back to the
                # smallest safe unit: the single physical line itself.
                stmt_start = stmt_end = target_line
            else:
                stmt_start, stmt_end = target_unit.start, target_unit.end

            slice_source = self._render_slice(
                source_lines, stmt_start, stmt_end, included & set(range(stmt_start, stmt_end + 1))
            )
            statement_source = self._extract_lines(source_lines, stmt_start, stmt_end)

            return CodeSlice(
                file_path=file_path,
                enclosing_name="<module>",
                slice_source=slice_source or statement_source,
                imports=imports,
                included_lines=sorted(included),
                vulnerable_line=target_line,
                full_function_source=statement_source,
                func_start_line=stmt_start,
                func_end_line=stmt_end,
            )

        source_lines = source.splitlines()
        func_start = enclosing.lineno
        func_end = self._max_lineno(enclosing)
        full_function_source = self._extract_lines(source_lines, func_start, func_end)

        units = self._statement_units(enclosing.body)
        included = self._backward_slice(units, target_line)

        # Always keep the def/class signature line itself.
        included.add(func_start)

        slice_source = self._render_slice(source_lines, func_start, func_end, included)

        name = getattr(enclosing, "name", "<anonymous>")

        return CodeSlice(
            file_path=file_path,
            enclosing_name=name,
            slice_source=slice_source,
            imports=imports,
            included_lines=sorted(included),
            vulnerable_line=target_line,
            full_function_source=full_function_source,
            func_start_line=func_start,
            func_end_line=func_end,
        )

    # ---------------------------------------------------------------- utils

    @staticmethod
    def _collect_imports(tree: ast.Module) -> list[str]:
        imports = []
        for node in tree.body:
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                imports.append(ast.unparse(node))
        return imports

    @staticmethod
    def _find_enclosing_scope(
        tree: ast.Module, target_line: int
    ) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
        best = None
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                start = node.lineno
                end = ProgramSlicer._max_lineno(node)
                if start <= target_line <= end:
                    # Prefer the innermost (most specific) enclosing function.
                    if best is None or (start >= best.lineno):
                        best = node
        return best

    @staticmethod
    def _max_lineno(node: ast.AST) -> int:
        max_line = getattr(node, "lineno", 0)
        for child in ast.walk(node):
            end = getattr(child, "end_lineno", None) or getattr(child, "lineno", 0)
            max_line = max(max_line, end)
        return max_line

    @staticmethod
    def _extract_lines(source_lines: list[str], start: int, end: int) -> str:
        return "\n".join(source_lines[start - 1 : end])

    class _Unit:
        __slots__ = ("node", "start", "end", "reads", "writes")

        def __init__(self, node, start, end, reads, writes):
            self.node = node
            self.start = start
            self.end = end
            self.reads = reads
            self.writes = writes

    @classmethod
    def _statement_units(cls, body: list[ast.stmt]) -> list["ProgramSlicer._Unit"]:
        units = []
        for stmt in body:
            start = stmt.lineno
            end = cls._max_lineno(stmt)
            reads: set[str] = set()
            writes: set[str] = set()
            for node in ast.walk(stmt):
                if isinstance(node, ast.Name):
                    if isinstance(node.ctx, ast.Store):
                        writes.add(node.id)
                    elif isinstance(node.ctx, ast.Load):
                        reads.add(node.id)
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.arg)):
                    name = getattr(node, "name", None) or getattr(node, "arg", None)
                    if name:
                        writes.add(name)
            units.append(cls._Unit(stmt, start, end, reads, writes))
        return units

    @staticmethod
    def _unit_at_line(
        units: list["ProgramSlicer._Unit"], target_line: int
    ) -> "ProgramSlicer._Unit | None":
        for u in units:
            if u.start <= target_line <= u.end:
                return u
        return None

    @staticmethod
    def _backward_slice(units: list["ProgramSlicer._Unit"], target_line: int) -> set[int]:
        included_lines: set[int] = set()
        needed_vars: set[str] = set()

        target_idx = None
        for i, u in enumerate(units):
            if u.start <= target_line <= u.end:
                target_idx = i
                break

        if target_idx is None:
            # Target line isn't a direct top-level statement (nested deeper);
            # fall back to including everything -- safer than guessing wrong.
            for u in units:
                included_lines.update(range(u.start, u.end + 1))
            return included_lines

        target_unit = units[target_idx]
        included_lines.update(range(target_unit.start, target_unit.end + 1))
        needed_vars.update(target_unit.reads)

        for i in range(target_idx - 1, -1, -1):
            u = units[i]
            if u.writes & needed_vars:
                included_lines.update(range(u.start, u.end + 1))
                needed_vars.update(u.reads)

        return included_lines

    @staticmethod
    def _render_slice(
        source_lines: list[str], start: int, end: int, included: set[int]
    ) -> str:
        out = []
        omitting = False
        for lineno in range(start, end + 1):
            if lineno in included:
                if omitting:
                    out.append("    # ... (omitted: not relevant to vulnerable sink)")
                    omitting = False
                out.append(source_lines[lineno - 1])
            else:
                omitting = True
        if omitting:
            out.append("    # ... (omitted: not relevant to vulnerable sink)")
        return "\n".join(out)
