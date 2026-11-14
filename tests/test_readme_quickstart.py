"""The README quickstart is the public example. It has to run."""
from __future__ import annotations

from pathlib import Path


def test_readme_quickstart_runs():
    readme = Path(__file__).resolve().parents[1].joinpath("README.md").read_text(encoding="utf-8")
    section = readme.split("## Quickstart", 1)[1]
    fenced = section.split("```python", 1)[1]
    code = fenced.split("```", 1)[0]
    namespace: dict[str, object] = {"__name__": "readme_quickstart"}
    exec(compile(code, "README.md", "exec"), namespace)
    assert namespace["sender"] == 0
    assert namespace["pt"] == b"hello"
