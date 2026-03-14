#!/usr/bin/env python3
"""Generate a normalized PlusCal corpus for fuzzing.

Sources:
1) test-model/pcal/*.tla: extract the PlusCal algorithm and re-wrap it.
2) test/pcal inline-source tests: extract PlusCal snippets embedded in Java strings.

Outputs go to src/fuzz_targets/pcal_corpus with module name == file stem.
"""

from __future__ import annotations

import re
from pathlib import Path

PCAL_START_RE = re.compile(r"--(?:fair\s+)?algorithm\b")
MODULE_HEADER_RE = re.compile(r"(?m)^-+\s*MODULE\b")
BEGIN_TRANSLATION_RE = re.compile(r"(?m)^\\\*\s*BEGIN TRANSLATION\b")
END_MODULE_RE = re.compile(r"(?m)^=+\s*$")
METHOD_RE = re.compile(r"(?m)^\s*public\s+void\s+(\w+)\s*\(")
STRING_RE = re.compile(r'"((?:\\.|[^"\\])*)"', re.S)


def decode_java_string(s: str) -> str:
    return bytes(s, "utf-8").decode("unicode_escape")


def extract_pluscal_algorithm(text: str) -> str | None:
    start_match = PCAL_START_RE.search(text)
    if not start_match:
        return None

    start = start_match.start()
    suffix = text[start:]

    stops = []
    for pat in (MODULE_HEADER_RE, BEGIN_TRANSLATION_RE, END_MODULE_RE):
        m = pat.search(suffix)
        if m and m.start() > 0:
            stops.append(m.start())

    stop = min(stops) if stops else len(suffix)
    chunk = suffix[:stop]

    # Trim outer comment wrapper when present.
    chunk = re.sub(r"^\s*\(\*\s*", "", chunk, count=1, flags=re.S)
    alg_start = PCAL_START_RE.search(chunk)
    if not alg_start:
        return None
    chunk = chunk[alg_start.start() :]
    chunk = re.sub(r"\s*\*\)\s*$", "", chunk, flags=re.S)
    chunk = chunk.rstrip()

    return chunk if chunk else None


def render_module(module_name: str, algorithm: str) -> str:
    return f"---- MODULE {module_name} ----\n(*\n{algorithm}\n*)\n====\n"


def write_module(out_dir: Path, module_name: str, algorithm: str) -> None:
    out_path = out_dir / f"{module_name}.tla"
    out_path.write_text(render_module(module_name, algorithm), encoding="utf-8")


def extract_second_arg_expression(src: str, call_start: int) -> str | None:
    # call_start points at first character after function name + '('.
    depth = 1
    i = call_start
    comma_idx = None
    while i < len(src):
        c = src[i]
        if c == '"':
            i += 1
            while i < len(src):
                if src[i] == '\\':
                    i += 2
                    continue
                if src[i] == '"':
                    i += 1
                    break
                i += 1
            continue
        if c == '(':
            depth += 1
        elif c == ')':
            depth -= 1
            if depth == 0:
                if comma_idx is None:
                    return None
                return src[comma_idx + 1 : i]
        elif c == ',' and depth == 1 and comma_idx is None:
            comma_idx = i
        i += 1
    return None


def extract_inline_modules(java_path: Path, out_dir: Path) -> int:
    src = java_path.read_text(encoding="utf-8")
    method_positions = [(m.start(), m.group(1)) for m in METHOD_RE.finditer(src)]

    def method_for_pos(pos: int) -> str:
        name = "snippet"
        for start, method_name in method_positions:
            if start <= pos:
                name = method_name
            else:
                break
        return name

    count = 0
    for fn in ("writeTempFile", "writeFile"):
        token = fn + "("
        idx = 0
        while True:
            pos = src.find(token, idx)
            if pos == -1:
                break
            arg_start = pos + len(token)
            expr = extract_second_arg_expression(src, arg_start)
            if expr:
                pieces = [decode_java_string(m.group(1)) for m in STRING_RE.finditer(expr)]
                joined = "".join(pieces)
                algo = extract_pluscal_algorithm(joined)
                if algo:
                    method = method_for_pos(pos)
                    module_name = f"{java_path.stem}_{method}_{count + 1}"
                    write_module(out_dir, module_name, algo)
                    count += 1
            idx = pos + len(token)

    return count


def main() -> None:
    this = Path(__file__).resolve()
    repo_root = this.parents[2]

    model_pcal_dir = repo_root / "test-model" / "pcal"
    test_pcal_dir = repo_root / "test" / "pcal"
    out_dir = this.parent / "pcal_corpus"
    out_dir.mkdir(parents=True, exist_ok=True)

    # Clean old generated corpus files.
    for p in out_dir.glob("*.tla"):
        p.unlink()

    from_model = 0
    for tla_file in sorted(model_pcal_dir.glob("*.tla")):
        text = tla_file.read_text(encoding="utf-8")
        algo = extract_pluscal_algorithm(text)
        if not algo:
            continue
        module_name = tla_file.stem
        write_module(out_dir, module_name, algo)
        from_model += 1

    inline_sources = [
        test_pcal_dir / "OptionalSemicolonTest.java",
        test_pcal_dir / "UnhandledInvalidSyntaxTest.java",
        test_pcal_dir / "AssignmentToUndeclaredVariableTest.java",
        test_pcal_dir / "DivergenceTest.java",
    ]

    from_inline = 0
    for java_path in inline_sources:
        from_inline += extract_inline_modules(java_path, out_dir)

    print(f"Wrote {from_model + from_inline} modules to {out_dir}")
    print(f"  from test-model/pcal: {from_model}")
    print(f"  from inline Java tests: {from_inline}")


if __name__ == "__main__":
    main()
