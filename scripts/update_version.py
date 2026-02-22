#!/usr/bin/env python
"""Update project version in pyproject.toml and src/rfc9420/__init__.py.

Usage:
    python scripts/update_version.py 0.2.1
    uv run python scripts/update_version.py 0.3.0

This script is the single updater: it writes version to pyproject.toml and
to __version__ in src/rfc9420/__init__.py. Docs (docs/conf.py) read from
pyproject.toml.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = PROJECT_ROOT / "pyproject.toml"
SRC_INIT = PROJECT_ROOT / "src" / "rfc9420" / "__init__.py"

VERSION_RE = re.compile(r"^\d+\.\d+(\.\d+)?([a-zA-Z0-9.-]*)?$")  # e.g. 0.2.0, 0.2.1a1


def current_version() -> str | None:
    """Read current version from pyproject.toml."""
    if not PYPROJECT.exists():
        return None
    text = PYPROJECT.read_text(encoding="utf-8")
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("version ") or line.startswith("version="):
            return line.split("=", 1)[1].strip().strip('"').strip("'")
    return None


def set_version_pyproject(new_version: str) -> bool:
    """Replace version in pyproject.toml. Returns True if changed."""
    text = PYPROJECT.read_text(encoding="utf-8")
    new_line = f'version = "{new_version}"'
    new_text = re.sub(
        r'^version\s*=\s*["\'][^"\']*["\']',
        new_line,
        text,
        count=1,
        flags=re.MULTILINE,
    )
    if new_text == text:
        return False
    PYPROJECT.write_text(new_text, encoding="utf-8")
    return True


def set_version_src(new_version: str) -> bool:
    """Replace __version__ in src/rfc9420/__init__.py. Returns True if changed."""
    if not SRC_INIT.exists():
        return False
    text = SRC_INIT.read_text(encoding="utf-8")
    # Match: __version__: str = "0.2.0" or __version__ = "0.2.0"
    new_text = re.sub(
        r'(__version__\s*(?::\s*str\s*)?=\s*)["\'][^"\']*["\']',
        rf'\g<1>"{new_version}"',
        text,
        count=1,
    )
    if new_text == text:
        return False
    SRC_INIT.write_text(new_text, encoding="utf-8")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Update version in pyproject.toml and src/rfc9420/__init__.py."
    )
    parser.add_argument(
        "version",
        metavar="VERSION",
        help="New version string (e.g. 0.2.1 or 0.3.0a1)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Only print what would be done.",
    )
    args = parser.parse_args()

    version = args.version.strip()
    if not VERSION_RE.match(version):
        print(f"Error: invalid version format: {version!r}", file=sys.stderr)
        print("Use e.g. 0.2.1 or 0.3.0a1", file=sys.stderr)
        return 1

    current = current_version()
    if current is None:
        print("Error: pyproject.toml not found or has no version.", file=sys.stderr)
        return 1

    if current == version:
        print(f"Version already set to {version}. Nothing to do.")
        return 0

    if args.dry_run:
        print(f"Would update version from {current} to {version} in:")
        print(f"  - {PYPROJECT}")
        print(f"  - {SRC_INIT}")
        return 0

    ok_pyproject = set_version_pyproject(version)
    ok_src = set_version_src(version)
    if not ok_pyproject:
        print("Error: could not update version in pyproject.toml.", file=sys.stderr)
        return 1
    if not ok_src:
        print("Warning: could not update __version__ in src/rfc9420/__init__.py.", file=sys.stderr)

    print(f"Updated version: {current} -> {version}")
    print("  - pyproject.toml")
    print("  - src/rfc9420/__init__.py (__version__)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
