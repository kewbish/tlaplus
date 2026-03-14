#!/usr/bin/env python3
"""Generate a monolithic TLC corpus from test-model .tla/.cfg pairs.

Output files are written to src/fuzz_targets/tlc_corpus and mirror the
relative directory structure under test-model.
"""

from __future__ import annotations

import shutil
from pathlib import Path


def build_monolith(spec_text: str, cfg_text: str, module_name: str) -> str:
    spec = spec_text.rstrip() + "\n\n"
    cfg = cfg_text.strip() + "\n"
    marker = f"----- CONFIG {module_name} -----\n"
    return spec + marker + cfg + "====\n"


def main() -> None:
    this = Path(__file__).resolve()
    repo_root = this.parents[2]

    test_model_dir = repo_root / "test-model"
    out_dir = this.parent / "tlc_corpus"

    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    total_cfg = 0
    converted = 0
    missing_tla = 0

    used_names: dict[str, int] = {}

    for cfg_path in sorted(test_model_dir.rglob("*.cfg")):
        total_cfg += 1
        tla_path = cfg_path.with_suffix(".tla")
        if not tla_path.exists():
            missing_tla += 1
            continue

        rel_tla = tla_path.relative_to(test_model_dir)
        flat_stem = "__".join(rel_tla.with_suffix("").parts)
        flat_name = f"{flat_stem}.tla"
        if flat_name in used_names:
            used_names[flat_name] += 1
            flat_name = f"{flat_stem}__{used_names[flat_name]}.tla"
        else:
            used_names[flat_name] = 1
        out_path = out_dir / flat_name

        spec_text = tla_path.read_text(encoding="utf-8")
        cfg_text = cfg_path.read_text(encoding="utf-8")
        out_text = build_monolith(spec_text, cfg_text, tla_path.stem)
        out_path.write_text(out_text, encoding="utf-8")

        converted += 1

    print(f"Wrote {converted} monolithic specs to {out_dir}")
    print(f"Scanned cfg files: {total_cfg}")
    print(f"Skipped (missing matching .tla): {missing_tla}")


if __name__ == "__main__":
    main()
