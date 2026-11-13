#!/usr/bin/env python3
"""Check a built sdist before it is published.

Two checks, each a subcommand:

``allowlist``
    The sdist carries only what it is meant to. `pyproject.toml` gives hatchling
    an allow-list, but hatchling force-includes some files whatever it says --
    README files anywhere in the tree, for one -- so the configuration states
    the intent and this states the guarantee. A new top-level path fails here
    rather than being published. If it belongs in the sdist, add it here and in
    `pyproject.toml`; if it does not, that is the check doing its job.

``suite``
    The sdist carries a test suite that passes. The allow-list cannot see that
    something wanted is missing: `tests` is inside it, so a test whose subject
    was left out is allowed and broken at the same time. So this runs what
    ships, extracted into a directory holding nothing else. Install pytest,
    pytest-asyncio and jsonschema first and nothing more: the traffic tests
    need jsonschema, and tests that need the other dev dependencies skip
    without them, as they will for a downstream packager.

The release job runs both on the sdist it publishes, and the test workflow runs
both on every pull request, so a test added with a dependency outside the
allow-list fails while its branch is open rather than at the tag.

    python tools/check_dist.py allowlist dist/py1815-1.0.0.tar.gz
    python tools/check_dist.py suite dist/py1815-1.0.0.tar.gz
"""

from __future__ import annotations

import argparse
import pathlib
import subprocess
import sys
import tarfile
import tempfile
from collections.abc import Iterable

#: Top-level entries the sdist may carry, whole.
ALLOWED = frozenset(
    {
        "PKG-INFO",
        "pyproject.toml",
        ".gitignore",
        "README.md",
        "CHANGELOG.md",
        "CONTRIBUTING.md",
        "SECURITY.md",
        "LICENSE",
        "NOTICE",
        "src",
        "tests",
        "docs",
        "conformance",
        "schema",
        "changelog.d",
    }
)

#: Single files the sdist may carry from a directory it otherwise leaves out.
ALLOWED_FILES = frozenset({"scripts/extract_conformance.py"})

#: The directories of `ALLOWED_FILES`. An sdist may list a directory as a
#: member of its own, so these are allowed as bare entries and nothing else.
ALLOWED_DIRS = frozenset(path.split("/")[0] for path in ALLOWED_FILES)

#: Paths left out from inside an entry `ALLOWED` takes whole.
FORBIDDEN = ("docs/planning/",)


def allowlist_problems(paths: Iterable[str]) -> list[str]:
    """Return one message for each path the sdist should not carry.

    ``paths`` are relative to the sdist's top directory, as `sdist_paths`
    returns them.
    """
    paths = list(paths)
    kept = [p for p in paths if p not in ALLOWED_FILES and p not in ALLOWED_DIRS]
    strays = sorted({p.split("/")[0] for p in kept} - ALLOWED)
    inside = sorted(p for p in paths if p.startswith(FORBIDDEN))
    return [f"the sdist carries {p}, which is not in the allow-list" for p in strays] + [
        f"the sdist carries {p}, which is excluded" for p in inside
    ]


def sdist_paths(sdist: pathlib.Path) -> list[str]:
    """Return every member of ``sdist`` relative to its top directory."""
    with tarfile.open(sdist) as tar:
        return [name.split("/", 1)[1] for name in tar.getnames() if "/" in name]


def run_suite(sdist: pathlib.Path) -> int:
    """Extract ``sdist`` into an empty directory, run its tests and return pytest's exit code."""
    with tempfile.TemporaryDirectory() as work:
        with tarfile.open(sdist) as tar:
            tar.extractall(work, filter="data")
        (top,) = pathlib.Path(work).iterdir()
        return subprocess.call([sys.executable, "-m", "pytest", "tests", "-q"], cwd=top)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("check", choices=("allowlist", "suite"))
    parser.add_argument("sdist", type=pathlib.Path)
    args = parser.parse_args(argv)

    if args.check == "suite":
        return run_suite(args.sdist)
    problems = allowlist_problems(sdist_paths(args.sdist))
    for problem in problems:
        print(problem)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
