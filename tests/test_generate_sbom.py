"""Unit coverage for the release SBOM generator.

This module decides what every published SBOM says and enforces the check
that keeps build-machine detail out of a public document, and none of it was
covered. The cases below are the ones that have actually gone wrong, each
kept as a regression:

* a scoped npm name emitted a PURL that does not resolve;
* a transitive package was described as a direct dependency of the project;
* a trove classifier became an SPDX id in one document and stayed free text
  in the other, so the pair disagreed;
* the publication check matched a UUID this tool generates, and separately
  exempted a repository whose name merely began with an allowlisted one;
* the document identifier ignored everything except names and versions, so
  two materially different documents could share one identity.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parent.parent / "tools" / "generate_sbom.py"


def _load():
    spec = importlib.util.spec_from_file_location("generate_sbom", TOOLS)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gs = _load()


# --------------------------------------------------------------------------
# PURLs


@pytest.mark.parametrize(
    "name,version,expected",
    [
        ("vue", "3.5.26", "pkg:npm/vue@3.5.26"),
        ("@vue/shared", "3.5.26", "pkg:npm/%40vue/shared@3.5.26"),
        ("@babel/parser", "7.28.5", "pkg:npm/%40babel/parser@7.28.5"),
    ],
)
def test_scoped_npm_names_percent_encode_the_scope(name, version, expected):
    """A raw "@" produces a reference that will not resolve, and a PURL is the
    key a vulnerability scanner matches on."""
    assert gs.npm_purl(name, version) == expected


# --------------------------------------------------------------------------
# npm lockfile parsing


def _write_lock(tmp_path: Path, packages: dict) -> Path:
    lock = tmp_path / "package-lock.json"
    lock.write_text(json.dumps({"lockfileVersion": 3, "packages": packages}), encoding="utf-8")
    return lock


def test_dev_and_optional_packages_are_excluded(tmp_path):
    """They are not in the published artifact, so including them would attach
    advisories to components no consumer runs."""
    lock = _write_lock(
        tmp_path,
        {
            "": {"dependencies": {"vue": "^3"}},
            "node_modules/vue": {"version": "3.5.26"},
            "node_modules/typescript": {"version": "5.6.0", "dev": True},
            "node_modules/fsevents": {"version": "2.3.3", "optional": True},
        },
    )
    names = {c["name"] for c in gs.load_npm_lock(lock)}
    assert names == {"vue"}


def test_only_lockfile_declared_dependencies_are_direct(tmp_path):
    """The root of a lockfile names its direct dependencies; everything else is
    reached through them. Marking a whole transitive closure direct describes a
    graph that does not exist."""
    lock = _write_lock(
        tmp_path,
        {
            "": {"dependencies": {"vue": "^3"}},
            "node_modules/vue": {"version": "3.5.26", "dependencies": {"@vue/shared": "3.5.26"}},
            "node_modules/@vue/shared": {"version": "3.5.26"},
        },
    )
    by_name = {c["name"]: c for c in gs.load_npm_lock(lock)}
    assert by_name["vue"]["npm_direct"] is True
    assert by_name["@vue/shared"]["npm_direct"] is False
    assert by_name["vue"]["npm_resolved_edges"] == ["@vue/shared"]
    # Asserted here as well as on npm_purl directly: testing the helper in
    # isolation passes while the loader still formats its own raw PURL, which
    # is the shape the defect actually had.
    assert by_name["@vue/shared"]["purl"] == "pkg:npm/%40vue/shared@3.5.26"


def test_integrity_is_decoded_to_hex_and_mislabelled_digests_dropped(tmp_path):
    lock = _write_lock(
        tmp_path,
        {
            "": {"dependencies": {}},
            # sha512 of b"", base64 -- the shape npm records.
            "node_modules/good": {
                "version": "1.0.0",
                "integrity": (
                    "sha512-z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8"
                    "XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg=="
                ),
            },
            "node_modules/bogus": {"version": "1.0.0", "integrity": "sha512-not-base64!!"},
        },
    )
    by_name = {c["name"]: c for c in gs.load_npm_lock(lock)}
    assert by_name["good"]["digest"][0] == "sha512"
    assert len(by_name["good"]["digest"][1]) == 128
    # A digest that does not decode to the right length is dropped rather than
    # published as a checksum that cannot verify.
    assert by_name["bogus"]["digest"] is None


# --------------------------------------------------------------------------
# Licenses


def test_trove_classifier_becomes_an_spdx_identifier():
    component = {"licenses": [{"license": {"name": "License :: OSI Approved :: MIT License"}}]}
    expression, note = gs.license_expression(component)
    assert expression == "MIT"
    assert note is None


def test_duplicate_representations_of_one_license_collapse():
    """An SPDX id plus the equivalent classifier is one license expressed
    twice, not a conjunction."""
    component = {
        "licenses": [
            {"license": {"id": "Apache-2.0"}},
            {"license": {"name": "License :: OSI Approved :: Apache Software License"}},
        ]
    }
    expression, _ = gs.license_expression(component)
    assert expression == "Apache-2.0"


def test_unrecognized_license_is_not_guessed():
    component = {"licenses": [{"license": {"name": "Some Bespoke Terms"}}]}
    expression, note = gs.license_expression(component)
    assert expression == "NOASSERTION"
    assert "not expressible" in note


# --------------------------------------------------------------------------
# Requirements parsing


def test_compiled_requirements_yield_pins_and_digests(tmp_path):
    """This project declares ranges rather than pinning a tree, so what a
    release can honestly describe is the resolution its own CI produced."""
    req = tmp_path / "requirements.txt"
    req.write_text(
        "\n".join(
            [
                "# generated by uv",
                "httpx==0.28.1 \\",
                "    --hash=sha256:" + "a" * 64 + " \\",
                "    --hash=sha256:" + "a" * 64,
                "anyio==4.8.0 \\",
                "    --hash=sha256:" + "b" * 64,
            ]
        ),
        encoding="utf-8",
    )
    parsed = gs.load_requirements_hashes(req)
    assert parsed["httpx"]["version"] == "0.28.1"
    assert parsed["anyio"]["version"] == "4.8.0"
    # A pin repeating one digest describes a single artifact, not two.
    assert parsed["httpx"]["wheels"] == [{"hash": "sha256:" + "a" * 64}]


# --------------------------------------------------------------------------
# The publication guard


@pytest.mark.parametrize(
    "text,flagged",
    [
        ('{"url": "https://github.com/DERSecurity/py1815"}', False),
        ("https://github.com/DERSecurity/py1815/issues", False),
        ("https://github.com/DERSecurity/py1815.git", False),
        # A repository whose name merely starts with an allowlisted one must
        # not inherit the exemption.
        ("https://github.com/DERSecurity/py1815-fork-of-something", True),
        ("account 000000000000 owns it", True),
        (r"C:\Users\someone\build", True),
        # A document identifier is a UUID whose final group is twelve hex
        # characters; when they are all digits it looks exactly like an
        # account id. Failing a release on this tool's own output would be
        # worse than useless, because it would happen at random.
        ('{"serialNumber": "urn:uuid:b2acedde-0cc4-fe86-3352-714068832369"}', False),
        ('{"name": "py1815", "version": "0.3.0"}', False),
    ],
)
def test_publication_guard(tmp_path, text, flagged):
    document = tmp_path / "doc.json"
    document.write_text(text, encoding="utf-8")
    assert bool(gs.find_internal_references(document)) is flagged


def test_guard_reports_enough_context_to_act_on(tmp_path):
    """A bare value says something leaked without saying which component
    carried it in, which is what someone has to know to remove it."""
    document = tmp_path / "doc.json"
    document.write_text('{"component": "thing", "url": "account 000000000000"}', encoding="utf-8")
    (finding,) = gs.find_internal_references(document)
    assert "000000000000" in finding
    assert "component" in finding


# --------------------------------------------------------------------------
# Index classification


@pytest.mark.parametrize(
    "url,public",
    [
        ("https://files.pythonhosted.org/packages/ab/cd/x.whl", True),
        ("https://pypi.org/simple/", True),
        ("https://example-index.internal/pypi/x/", False),
        ("", False),
    ],
)
def test_private_index_urls_are_never_treated_as_public(url, public):
    assert gs.is_public_url(url) is public


# --------------------------------------------------------------------------
# Graph assembly


def test_graph_hangs_only_direct_dependencies_off_the_root(tmp_path):
    """The finding this guards was in graph assembly, not in parsing.

    `load_npm_lock` can classify correctly while `build_model` still attaches
    every package to the root, which produces a long list of direct
    dependencies for a project declaring a handful. Asserting the parser's
    flag does not catch that; asserting the emitted edges does.
    """
    lock = _write_lock(
        tmp_path,
        {
            "": {"dependencies": {"vue": "^3"}},
            "node_modules/vue": {"version": "3.5.26", "dependencies": {"@vue/shared": "3.5.26"}},
            "node_modules/@vue/shared": {"version": "3.5.26"},
        },
    )
    cdx = {
        "metadata": {"component": {"bom-ref": "root", "name": "demo", "version": "1.0.0"}},
        "components": [],
        "dependencies": [],
    }
    model = gs.build_model(cdx, {}, extra=gs.load_npm_lock(lock))

    root_edges = model["edges"]["root"]
    assert root_edges == ["npm:vue@3.5.26"], (
        "only the lockfile's declared dependencies belong on the root; a "
        f"transitive package was attached directly: {root_edges}"
    )
    assert model["edges"]["npm:vue@3.5.26"] == ["npm:@vue/shared@3.5.26"]


def test_vendored_assets_without_a_lockfile_are_direct(tmp_path):
    """A committed browser library has no manifest and no edges of its own:
    the project ships it, so the project depends on it directly. The
    direct/transitive distinction must not quietly demote these."""
    manifest = tmp_path / "vendor.json"
    manifest.write_text(
        json.dumps(
            {
                "assets": [
                    {
                        "name": "jquery",
                        "version": "3.7.1",
                        "license": "MIT",
                        "file": "jquery.js",
                        "sha256": "a" * 64,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    cdx = {
        "metadata": {"component": {"bom-ref": "root", "name": "demo", "version": "1.0.0"}},
        "components": [],
        "dependencies": [],
    }
    model = gs.build_model(cdx, {}, extra=gs.load_vendored_assets(manifest))
    assert model["edges"]["root"] == ["npm:jquery@3.7.1"]
