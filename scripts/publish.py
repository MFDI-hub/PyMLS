#!/usr/bin/env python
"""Build and publish this package to TestPyPI, PyPI, or both."""

from __future__ import annotations

import argparse
import glob
import os
import shutil
import subprocess
from pathlib import Path

from dotenv import load_dotenv


TEST_PYPI_URL = "https://test.pypi.org/legacy/"
PYPI_URL = "https://upload.pypi.org/legacy/"
# Env var names for tokens (support both standard and .env key names)
TEST_PYPI_TOKEN_KEYS = ("TEST_PYPI_API_TOKEN", "TEST_PYPI_TOKEN_ENV")
PYPI_TOKEN_KEYS = ("PYPI_API_TOKEN", "PYPI_TOKEN_ENV")


def load_env() -> None:
    """Load .env from project root (parent of scripts/) or cwd."""
    script_dir = Path(__file__).resolve().parent
    project_root = script_dir.parent
    for path in (project_root / ".env", Path.cwd() / ".env"):
        if path.is_file():
            load_dotenv(path, override=False)
            return


def run(command: list[str]) -> None:
    """Run a command and stop on failure."""
    print(f"+ {' '.join(command)}")
    subprocess.run(command, check=True)  # noqa: S603 (args are from this script, not user input)


def require_uv() -> None:
    """Ensure uv is available."""
    if shutil.which("uv") is None:
        raise SystemExit(
            "uv is required but was not found in PATH.\n"
            "Install it first: https://docs.astral.sh/uv/getting-started/installation/"
        )


def clean_dist() -> None:
    """Remove old build artifacts before creating new ones."""
    for folder in ("dist", "build"):
        path = Path(folder)
        if path.exists():
            shutil.rmtree(path)


def build_package() -> None:
    clean_dist()
    run(["uv", "build"])
    run(["uv", "run", "--with", "twine", "twine", "check", "dist/*"])


def upload(repository_url: str, token: str) -> None:
    artifacts = sorted(glob.glob("dist/*"))
    if not artifacts:
        raise SystemExit("No files found in dist/. Build the package first.")

    run(
        [
            "uv",
            "run",
            "--with",
            "twine",
            "twine",
            "upload",
            "--repository-url",
            repository_url,
            "-u",
            "__token__",
            "-p",
            token,
            *artifacts,
        ]
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build and publish to TestPyPI, PyPI, or both."
    )
    parser.add_argument(
        "--repository",
        choices=("testpypi", "pypi", "both"),
        default="testpypi",
        help="Target repository. Default: testpypi.",
    )
    parser.add_argument(
        "--skip-build",
        action="store_true",
        help="Skip building and checking package before upload.",
    )
    return parser.parse_args()


def main() -> int:
    load_env()
    args = parse_args()
    # Run from project root so dist/ and uv build resolve correctly for src layout
    project_root = Path(__file__).resolve().parent.parent
    os.chdir(project_root)
    require_uv()

    if not args.skip_build:
        build_package()

    if args.repository in ("testpypi", "both"):
        test_token = next(
            (os.environ.get(k) for k in TEST_PYPI_TOKEN_KEYS if os.environ.get(k)),
            None,
        )
        if not test_token:
            raise SystemExit(
                f"Set one of {TEST_PYPI_TOKEN_KEYS} (e.g. in .env) before uploading to TestPyPI."
            )
        upload(TEST_PYPI_URL, test_token)

    if args.repository in ("pypi", "both"):
        pypi_token = next(
            (os.environ.get(k) for k in PYPI_TOKEN_KEYS if os.environ.get(k)),
            None,
        )
        if not pypi_token:
            raise SystemExit(
                f"Set one of {PYPI_TOKEN_KEYS} (e.g. in .env) before uploading to PyPI."
            )
        upload(PYPI_URL, pypi_token)

    print("Publish completed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
