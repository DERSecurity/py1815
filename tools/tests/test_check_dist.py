"""Check the sdist allow-list that `tools/check_dist.py` applies before a release.

Kept beside the tool rather than in ``tests/``, for the reason
``test_generate_sbom.py`` gives: the sdist ships ``tests`` and not ``tools``.

Hatchling may or may not list a directory as a member of its own, so each case
runs against both shapes of member list.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

TOOL = Path(__file__).resolve().parent.parent / "check_dist.py"


def _load():
    spec = importlib.util.spec_from_file_location("check_dist", TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cd = _load()

BASE = [
    "PKG-INFO",
    "pyproject.toml",
    "README.md",
    "src/py1815/__init__.py",
    "tests/test_catalog.py",
    "docs/index.md",
    "conformance/ieee-1815-2012.json",
]


def _shapes(paths: list[str]) -> list[list[str]]:
    """Return ``paths`` as is and with each parent directory listed as a member."""
    with_dirs = set(paths)
    for path in paths:
        parts = path.split("/")
        with_dirs.update("/".join(parts[:end]) for end in range(1, len(parts)))
    return [list(paths), sorted(with_dirs)]


@pytest.mark.parametrize("paths", _shapes([*BASE, "scripts/extract_conformance.py"]))
def test_the_allowed_files_pass(paths):
    assert cd.allowlist_problems(paths) == []


@pytest.mark.parametrize(
    "paths", _shapes([*BASE, "scripts/extract_conformance.py", "scripts/build_changelog.py"])
)
def test_another_file_beside_an_allowed_file_is_a_stray(paths):
    assert cd.allowlist_problems(paths) == [
        "the sdist carries scripts, which is not in the allow-list"
    ]


@pytest.mark.parametrize("paths", _shapes([*BASE, "interop/outstation.py"]))
def test_a_directory_not_in_the_allow_list_is_a_stray(paths):
    assert cd.allowlist_problems(paths) == [
        "the sdist carries interop, which is not in the allow-list"
    ]


@pytest.mark.parametrize("paths", _shapes([*BASE, "docs/planning/MASTER.md"]))
def test_a_forbidden_path_inside_an_allowed_directory_is_reported(paths):
    problems = cd.allowlist_problems(paths)
    assert "the sdist carries docs/planning/MASTER.md, which is excluded" in problems
    assert all("not in the allow-list" not in problem for problem in problems)


def test_every_allowed_file_is_named_in_the_sdist_include_list():
    pyproject = (TOOL.parent.parent / "pyproject.toml").read_text(encoding="utf-8")
    for path in cd.ALLOWED_FILES:
        assert f'"/{path}"' in pyproject, f"{path} is allowed but not in the sdist include list"
