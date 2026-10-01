#!/usr/bin/env python3
"""Build the release SBOM for this project in CycloneDX and SPDX form.

Both documents are emitted from one component model so they cannot disagree.
The model is assembled from two inputs:

* the CycloneDX document produced by ``cyclonedx-py environment`` against a
  venv built from the locked runtime dependencies. That scan is what supplies
  package metadata the lockfile does not carry: declared licenses, project
  URLs, descriptions, and the resolved dependency graph.
* ``uv.lock``, which supplies the distribution artifact hashes and the index
  each package was resolved from. The environment scan cannot know these
  because installed metadata does not retain them.

Usage:
    python tools/generate_sbom.py \
        --cyclonedx build/sbom/environment.cdx.json \
        --uv-lock uv.lock \
        --version 1.2.3 \
        --out-dir dist/sbom
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
import sys
import tomllib
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# PyPI trove classifiers carry a license name rather than an SPDX identifier.
# Packages that declare only a classifier would otherwise land as NOASSERTION,
# which understates what the metadata actually says. Only unambiguous
# classifiers are mapped: anything whose SPDX equivalent depends on a version
# or variant the classifier does not pin is deliberately left out so it falls
# through to NOASSERTION rather than being guessed.
CLASSIFIER_TO_SPDX = {
    "License :: OSI Approved :: Apache Software License": "Apache-2.0",
    "License :: OSI Approved :: MIT License": "MIT",
    "License :: OSI Approved :: BSD License": "BSD-3-Clause",
    "License :: OSI Approved :: ISC License (ISCL)": "ISC",
    "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "License :: OSI Approved :: Python Software Foundation License": "PSF-2.0",
}

SPDX_ID_SAFE = re.compile(r"[^A-Za-z0-9.\-]")

# Licenses that are not on the SPDX License List, and so are referenced by a
# LicenseRef- identifier. A bare LicenseRef- in an SPDX document is an
# undefined reference: the document has to carry a matching
# hasExtractedLicensingInfos entry or a reader cannot tell what the identifier
# means. Every ref used anywhere in a document is defined from this table.
EXTRACTED_LICENSES: dict[str, dict[str, Any]] = {}

LICENSE_REF = re.compile(r"LicenseRef-[A-Za-z0-9.\-]+")


def spdx_id(*parts: str) -> str:
    """Build an SPDXID from parts, restricted to the charset SPDX permits."""
    joined = "-".join(SPDX_ID_SAFE.sub("-", p) for p in parts if p)
    return f"SPDXRef-{joined}"


def load_lock_artifacts(lock_path: Path) -> dict[str, dict[str, Any]]:
    """Map ``name -> {version, sdist, wheels, index}`` from a uv lockfile.

    Keys are normalized (lowercased, ``_`` and ``.`` folded to ``-``) because
    the lockfile, the installed metadata, and the PURL do not agree on
    separator style for every project.
    """
    data = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    out: dict[str, dict[str, Any]] = {}
    for pkg in data.get("package", []):
        name = pkg.get("name")
        if not name:
            continue
        source = pkg.get("source", {})
        out[normalize(name)] = {
            "version": pkg.get("version", ""),
            "sdist": pkg.get("sdist") or {},
            "wheels": pkg.get("wheels") or [],
            "index": source.get("registry", "") if isinstance(source, dict) else "",
        }
    return out


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def load_requirements_hashes(req_path: Path) -> dict[str, dict[str, Any]]:
    """Read artifact digests from a pinned requirements file.

    The lockfile equivalent for a library. An application pins its whole tree
    in uv.lock and ships exactly that; a library declares ranges and the
    consumer resolves them, so there is no lockfile to read. What a release
    can honestly describe is the resolution its own CI produced and tested,
    which is what ``uv pip compile --generate-hashes`` emits.

    The distinction matters to a reader, so the document says which it is
    rather than presenting a build-time resolution as though it were the tree
    every consumer will get.
    """
    out: dict[str, dict[str, Any]] = {}
    current: str | None = None
    for raw in req_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        pin = re.match(r"^([A-Za-z0-9._-]+)==([^\s\\;]+)", line)
        if pin:
            current = normalize(pin.group(1))
            out[current] = {"version": pin.group(2), "sdist": {}, "wheels": [], "index": ""}
            continue
        digest = re.search(r"--hash=(\w+):([0-9a-f]+)", line)
        if digest and current:
            # Recorded in the shape pick_checksum expects. A compiled
            # requirements file lists every acceptable artifact for the pin,
            # so the first is taken as representative rather than inventing a
            # preference between wheels the resolver treats as equivalent.
            out[current]["wheels"].append({"hash": f"{digest.group(1)}:{digest.group(2)}"})
    # Collapse repeats of the same digest. What remains is either one
    # artifact, which identifies the package, or several distinct per-platform
    # builds -- and pick_checksum already declines to elevate one of those to
    # stand for the package as a whole.
    for entry in out.values():
        seen: list[dict[str, Any]] = []
        for wheel in entry["wheels"]:
            if wheel["hash"] not in {w["hash"] for w in seen}:
                seen.append(wheel)
        entry["wheels"] = seen
    return out


# Hosts whose URLs are safe to reproduce in a published document. Anything
# else is treated as a private distribution channel and is never emitted:
# an internal index URL identifies the account and registry that hosts it,
# which is internal infrastructure detail and has no place in a customer
# artifact. Packages from such an index are reported as coming from a
# private channel, named only by the fact that they are first-party.
PUBLIC_INDEX_HOSTS = frozenset({"pypi.org", "files.pythonhosted.org"})


def is_public_url(url: str) -> bool:
    if not url:
        return False
    m = re.match(r"https?://([^/]+)", url)
    return bool(m) and m.group(1).lower() in PUBLIC_INDEX_HOSTS


# Digest algorithms both output formats can express, keyed by the prefix uv
# writes into the lockfile. Public indexes publish SHA-256; some private
# ones publish SHA-512, so a package would lose its checksum entirely if
# only SHA-256 were accepted. The digest is never relabelled: whichever
# algorithm the lockfile recorded is the one reported.
DIGEST_ALGORITHMS = {
    "sha256": {"cyclonedx": "SHA-256", "spdx": "SHA256", "length": 64},
    "sha512": {"cyclonedx": "SHA-512", "spdx": "SHA512", "length": 128},
}


def artifact_digest(entry: dict[str, Any]) -> tuple[str, str] | None:
    """Return ``(algorithm, hex_digest)`` for one lockfile artifact.

    uv records hashes as ``<algorithm>:<hex>``. The digest length is checked
    against the algorithm so a truncated or mislabelled value is dropped
    rather than published as a checksum that will not verify.
    """
    raw = entry.get("hash") or ""
    algo, _, digest = raw.partition(":")
    spec = DIGEST_ALGORITHMS.get(algo)
    if not spec or len(digest) != spec["length"]:
        return None
    return algo, digest


def pick_checksum(lock_entry: dict[str, Any]) -> tuple[tuple[str, str] | None, str | None]:
    """Choose one representative artifact digest for a package.

    Returns ``((algorithm, digest), download_url)``. The source distribution
    is preferred: it is the one artifact that exists for every platform, so
    it identifies the package rather than one platform's build of it. A
    package published as wheels only falls back to its single wheel, and a
    package with several platform wheels and no sdist returns no checksum
    rather than arbitrarily elevating one platform's digest to stand for the
    package as a whole.
    """
    sdist = lock_entry.get("sdist") or {}
    if sdist:
        found = artifact_digest(sdist)
        if found:
            return found, sdist.get("url")
    wheels = lock_entry.get("wheels") or []
    if len(wheels) == 1:
        found = artifact_digest(wheels[0])
        if found:
            return found, wheels[0].get("url")
    return None, (wheels[0].get("url") if wheels else None)


def license_expression(component: dict[str, Any]) -> tuple[str, str | None]:
    """Reduce a CycloneDX ``licenses`` array to one SPDX license expression.

    Returns ``(expression, note)``. ``note`` is non-None when the reduction
    lost or could not interpret information, so the caller can record what
    the metadata actually said instead of discarding it.

    CycloneDX does not define a join operator for multiple ``licenses``
    entries, and in practice a multi-entry array is usually one license
    expressed two ways (an SPDX id plus the equivalent trove classifier)
    rather than a genuine conjunction. Entries are therefore mapped to SPDX
    ids and de-duplicated first; only a genuine remainder of two or more
    distinct ids is treated as a choice and joined with OR.
    """
    entries = component.get("licenses") or []
    if not entries:
        return "NOASSERTION", "package metadata declares no license"

    ids: list[str] = []
    unmapped: list[str] = []
    for entry in entries:
        if "expression" in entry:
            # Already an SPDX expression; the tool emitted it verbatim.
            return entry["expression"], None
        lic = entry.get("license") or {}
        if lic.get("id"):
            ids.append(lic["id"])
            continue
        name = lic.get("name")
        if not name:
            continue
        mapped = CLASSIFIER_TO_SPDX.get(name)
        if mapped:
            ids.append(mapped)
        else:
            unmapped.append(name)

    deduped = list(dict.fromkeys(ids))
    if not deduped:
        detail = "; ".join(unmapped) if unmapped else "no recognizable license"
        return "NOASSERTION", f"declared license not expressible as an SPDX id: {detail}"
    if len(deduped) == 1:
        return deduped[0], None
    return " OR ".join(deduped), (
        "package metadata declares multiple licenses; recorded as a choice"
    )


# DERSec repositories that are public. Their URLs arrive in this document as
# upstream package metadata -- py20305 publishes its source link on PyPI, so
# reproducing it discloses nothing that is not already public, and stripping
# it would remove genuine provenance for a dependency customers can inspect.
# Verified public at the time of writing; anything not listed is treated as
# private.
PUBLIC_DERSEC_REPOS = ("py20305",)

# Patterns that must never appear in a published SBOM. Narrower here than
# in a closed-source project: this repository's dependency tree is public
# by construction, so the only thing worth catching is a local path or an
# account identifier leaking in from a build machine.
# Patterns that must never appear in a published SBOM. These documents go to
# customers, so an internal index host, a cloud account id, or a private
# repository URL reaching one is a disclosure, not a cosmetic defect. The
# check runs on the rendered bytes rather than on the model, so it catches a
# leak introduced anywhere in rendering, including by a future field nobody
# thought to filter.
#
# A third-party dependency's own public repository URL is not a leak and is
# not matched here -- it is ordinary provenance for a public package, and
# blocking it would strip useful information to no benefit. Only DERSec's
# own repositories and infrastructure are in scope.
INTERNAL_PATTERNS = [
    (re.compile(r"\b\d{12}\b"), "possible cloud account id"),
    # Matches any DERSec repository URL except the open-source ones, whose
    # addresses are already published on PyPI and are ordinary provenance for
    # a public package. The negative lookahead is an allowlist rather than a
    # blanket exemption for the org: a DERSec repo that is not named here
    # fails the build, so a new private repo leaking is caught and a new
    # public one is a one-line, deliberate addition.
    (
        re.compile(
            r"github\.com/DERSecurity/(?!" + "|".join(PUBLIC_DERSEC_REPOS) + r")",
            re.I,
        ),
        "private source repository",
    ),
    (re.compile(r"[A-Za-z]:[\\/]Users[\\/]", re.I), "local filesystem path"),
]


# A document identifier is a UUID, whose final group is twelve hex characters
# separated by hyphens. When those twelve happen to be all digits it looks
# exactly like a cloud account id to the check below, which would fail a
# release for a value this tool generated itself -- and do so unpredictably,
# since the identifier is derived from the component set. UUID-shaped tokens
# are removed before scanning.
#
# This cannot hide a real disclosure: an account id leaks inside a host name
# or an ARN, neither of which is UUID-shaped. Narrowing the account-id pattern
# instead was rejected -- the obvious narrowing, ignoring digits next to a
UUID_SHAPED = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)


def find_internal_references(path: Path) -> list[str]:
    """Return a description of every internal reference found in a document."""
    text = UUID_SHAPED.sub("<uuid>", path.read_text(encoding="utf-8"))
    found: list[str] = []
    for pattern, label in INTERNAL_PATTERNS:
        for match in sorted(set(pattern.findall(text))):
            found.append(f"{path.name}: {label}: {match}")
    return found


def load_npm_lock(lock_path: Path) -> list[dict[str, Any]]:
    """Read an npm lockfile's production closure as SBOM components.

    Parsed directly rather than by shelling out to a Node tool, so a Python
    project that happens to ship a JavaScript frontend does not need a Node
    toolchain in its release pipeline just to describe what it ships.

    Development dependencies are excluded: they are not in the shipped
    bundle, and including them would pad the document with components no
    customer runs -- and, worse, with advisories that do not apply to them.
    """
    if not lock_path.exists():
        return []
    data = json.loads(lock_path.read_text(encoding="utf-8"))
    version = data.get("lockfileVersion")
    if version not in (2, 3):
        raise SystemExit(
            f"error: unsupported npm lockfileVersion {version!r} in {lock_path}; "
            "only versions 2 and 3 carry the resolved tree this reads"
        )

    out: list[dict[str, Any]] = []
    for key, entry in (data.get("packages") or {}).items():
        # "" is the project itself; dev dependencies do not ship.
        if not key or entry.get("dev") or entry.get("optional"):
            continue
        # Nested installs appear as a/node_modules/b -- the package is the
        # part after the last marker, so a hoisted and a nested copy of the
        # same library both resolve to the same name.
        name = key.rsplit("node_modules/", 1)[-1]
        pkg_version = entry.get("version")
        if not name or not pkg_version:
            continue

        digest = None
        integrity = entry.get("integrity") or ""
        algo, _, b64 = integrity.partition("-")
        if algo in DIGEST_ALGORITHMS and b64:
            try:
                hex_digest = base64.b64decode(b64).hex()
            except (ValueError, binascii.Error):
                hex_digest = ""
            if len(hex_digest) == DIGEST_ALGORITHMS[algo]["length"]:
                digest = (algo, hex_digest)

        resolved = entry.get("resolved") or ""
        out.append(
            {
                "name": name,
                "version": pkg_version,
                "purl": f"pkg:npm/{name}@{pkg_version}",
                "description": None,
                # npm records a license string only sometimes; an absent one
                # is reported as unknown rather than guessed from the name.
                "license_expression": entry.get("license") or "NOASSERTION",
                "license_note": (
                    None if entry.get("license") else "npm lockfile records no license"
                ),
                "raw_licenses": [],
                "external_refs": [],
                "digest": digest,
                "download_url": resolved if is_public_asset_url(resolved) else "",
                "private_source": bool(resolved) and not is_public_asset_url(resolved),
                "ecosystem": "npm",
            }
        )
    return out


def load_vendored_assets(manifest_path: Path) -> list[dict[str, Any]]:
    """Read browser libraries vendored into the product as SBOM components.

    These have no package manager to interrogate: they are files committed
    into the repository, which is exactly why they need declaring. The
    manifest beside them carries the name, version, license identifier and
    digest, and tools/verify_vendored_assets.py enforces that the digest
    still matches the committed bytes -- so what lands in the SBOM is checked
    against the shipped file rather than being an assertion in a config.
    """
    if not manifest_path.exists():
        return []
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    out = []
    for asset in data.get("assets") or []:
        out.append(
            {
                "name": asset["name"],
                "version": asset["version"],
                "purl": asset.get("purl") or f"pkg:npm/{asset['name']}@{asset['version']}",
                "description": None,
                "license_expression": asset.get("license") or "NOASSERTION",
                "license_note": None,
                "raw_licenses": [],
                "external_refs": [],
                "digest": ("sha256", asset["sha256"]) if asset.get("sha256") else None,
                # The upstream URL is a public registry mirror, so it is safe
                # to publish and is genuinely useful: it says precisely which
                # artifact the committed file is a copy of.
                "download_url": asset.get("upstream", "")
                if is_public_asset_url(asset.get("upstream", ""))
                else "",
                "private_source": False,
                "ecosystem": "npm",
            }
        )
    return out


# Registry mirrors whose URLs identify a public artifact. Kept separate from
# PUBLIC_INDEX_HOSTS, which is about Python indexes.
PUBLIC_ASSET_HOSTS = frozenset(
    {"cdn.jsdelivr.net", "unpkg.com", "registry.npmjs.org", "code.jquery.com"}
)


def is_public_asset_url(url: str) -> bool:
    if not url:
        return False
    m = re.match(r"https?://([^/]+)", url)
    return bool(m) and m.group(1).lower() in PUBLIC_ASSET_HOSTS


def build_model(
    cdx: dict[str, Any],
    lock: dict[str, Any],
    extra: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Assemble the shared component model both output formats render from.

    ``extra`` carries components that no package manager reports -- currently
    the vendored browser libraries. They are real parts of what ships, so they
    belong in the same model and the same dependency graph as everything the
    environment scan found.
    """
    root_meta = cdx["metadata"]["component"]
    by_ref: dict[str, dict[str, Any]] = {}

    for comp in cdx.get("components", []):
        key = normalize(comp["name"])
        lock_entry = lock.get(key, {})
        digest, url = pick_checksum(lock_entry)
        expression, note = license_expression(comp)
        by_ref[comp["bom-ref"]] = {
            "name": comp["name"],
            "version": comp.get("version", ""),
            "purl": comp.get("purl"),
            "description": comp.get("description"),
            "license_expression": expression,
            "license_note": note,
            "raw_licenses": comp.get("licenses") or [],
            "external_refs": comp.get("externalReferences") or [],
            "digest": digest,
            # Only a public artifact URL survives into the document. A URL on
            # a private index names internal infrastructure, so it is dropped
            # here rather than filtered at each render site.
            "download_url": url if is_public_url(url) else "",
            "private_source": bool(lock_entry.get("index"))
            and not is_public_url(lock_entry.get("index", "")),
            "ecosystem": "pypi",
        }

    edges: dict[str, list[str]] = {}
    for dep in cdx.get("dependencies", []):
        edges[dep["ref"]] = list(dep.get("dependsOn") or [])

    root_ref = root_meta["bom-ref"]
    for asset in extra or []:
        # Namespaced so a browser library can never collide with a Python
        # distribution of the same name.
        ref = f"npm:{asset['name']}@{asset['version']}"
        by_ref[ref] = asset
        edges.setdefault(ref, [])
        # A vendored library is a direct dependency of the product: it is
        # shipped inside it and loaded by its UI, so the graph should say so
        # rather than leaving it as an orphan component.
        edges.setdefault(root_ref, [])
        if ref not in edges[root_ref]:
            edges[root_ref].append(ref)

    return {
        "root": {
            "name": root_meta["name"],
            "version": root_meta.get("version", ""),
            "description": root_meta.get("description"),
            "bom_ref": root_ref,
        },
        "components": by_ref,
        "edges": edges,
    }


def provenance_refs(prov: dict[str, str]) -> list[dict[str, str]]:
    """Build the external references that point at the release.

    Only the customer-facing distribution location. No source-repository
    reference: the repositories are private, so a `vcs` entry would disclose
    one to every reader of a published document.
    """
    refs: list[dict[str, str]] = []
    if prov.get("download_location"):
        refs.append({"type": "distribution", "url": prov["download_location"]})
    return refs


def render_cyclonedx(
    model: dict[str, Any],
    cdx: dict[str, Any],
    serial: str,
    now: str,
    prov: dict[str, str],
) -> dict[str, Any]:
    """Return the CycloneDX document, enriched with lockfile provenance.

    The upstream environment scan is kept as the base so the tool's own
    metadata and structure survive; this only adds what the scan could not
    see (artifact digests and the resolving index) and normalizes the
    license fields to the same expressions the SPDX document carries.
    """
    doc = json.loads(json.dumps(cdx))  # deep copy; do not mutate the input
    # A project with no dependencies produces a document with no `components`
    # key at all, which is schema-valid but makes every consumer that iterates
    # it special-case the empty case. Emit the empty arrays instead, so
    # "no components" and "some components" read the same to a reader.
    doc.setdefault("components", [])
    doc.setdefault("dependencies", [])
    doc["serialNumber"] = f"urn:uuid:{serial}"
    doc["version"] = 1
    doc.setdefault("metadata", {})["timestamp"] = now

    # Bind the document to the release it describes, so an SBOM found on its
    # own can be traced to one build rather than only to a version string.
    root = doc["metadata"]["component"]
    refs = provenance_refs(prov)
    if refs:
        root.setdefault("externalReferences", []).extend(refs)
    if prov.get("release_tag"):
        root.setdefault("properties", []).append(
            {"name": "dersec:release-tag", "value": prov["release_tag"]}
        )
    if prov.get("resolution") == "build-time":
        root.setdefault("properties", []).append(
            {
                "name": "dersec:dependency-resolution",
                "value": (
                    "build-time; this project declares dependency ranges rather "
                    "than pinning a tree, so the versions here are the resolution "
                    "this release was built and tested against, not necessarily "
                    "what a consumer installs"
                ),
            }
        )
    if prov.get("product_license"):
        # Stated as an expression rather than an id: a LicenseRef- is not on
        # the SPDX License List, so it is not a valid CycloneDX license id.
        # The companion SPDX document defines what the ref means.
        root["licenses"] = [{"expression": prov["product_license"]}]

    for comp in doc.get("components", []):
        entry = model["components"].get(comp["bom-ref"])
        if not entry:
            continue
        if entry["digest"]:
            algo, value = entry["digest"]
            comp["hashes"] = [{"alg": DIGEST_ALGORITHMS[algo]["cyclonedx"], "content": value}]
        props = comp.setdefault("properties", [])
        if entry["private_source"]:
            # States that the component came from a private channel without
            # naming it. A reader needs to know it is not a public package;
            # they do not need the registry's address.
            props.append({"name": "dersec:distribution", "value": "private"})
        if entry["license_note"]:
            props.append({"name": "dersec:license-note", "value": entry["license_note"]})

    # Components the environment scan could not see, because they are files in
    # the repository rather than installed packages. They are appended here
    # rather than enriched above: there is no existing entry to enrich.
    scanned = {c["bom-ref"] for c in doc.get("components", [])}
    for ref, entry in model["components"].items():
        if ref in scanned or entry.get("ecosystem") != "npm":
            continue
        component: dict[str, Any] = {
            "bom-ref": ref,
            "type": "library",
            "name": entry["name"],
            "version": entry["version"],
            "purl": entry["purl"],
            "properties": [{"name": "dersec:distribution", "value": "vendored"}],
        }
        if entry["license_expression"] != "NOASSERTION":
            component["licenses"] = [{"license": {"id": entry["license_expression"]}}]
        if entry["digest"]:
            algo, value = entry["digest"]
            component["hashes"] = [{"alg": DIGEST_ALGORITHMS[algo]["cyclonedx"], "content": value}]
        if entry["download_url"]:
            component["externalReferences"] = [
                {"type": "distribution", "url": entry["download_url"]}
            ]
        doc.setdefault("components", []).append(component)

    # Mirror the model's graph so the appended components are reachable from
    # the root rather than floating unreferenced.
    existing = {d["ref"]: d for d in doc.get("dependencies", [])}
    for ref, targets in model["edges"].items():
        node = existing.get(ref)
        if node is None:
            doc.setdefault("dependencies", []).append(
                {"ref": ref, **({"dependsOn": sorted(targets)} if targets else {})}
            )
        elif targets:
            merged = sorted(set(node.get("dependsOn") or []) | set(targets))
            node["dependsOn"] = merged
    return doc


def render_spdx(
    model: dict[str, Any],
    serial: str,
    now: str,
    namespace_base: str,
    prov: dict[str, str],
) -> dict[str, Any]:
    """Return an SPDX 2.3 document describing the same component model."""
    root = model["root"]
    doc_name = f"{root['name']}-{root['version']}"
    root_id = spdx_id("Package", root["name"], root["version"])

    root_comment = [
        "Root component. This SBOM covers the runtime dependency closure of "
        "the application; build-time and test-only dependencies are excluded "
        "by design."
    ]
    if prov.get("release_tag"):
        root_comment.append(f"Released as tag {prov['release_tag']}.")
    if prov.get("resolution") == "build-time":
        root_comment.append(
            "This project declares dependency ranges rather than pinning a tree, "
            "so the dependency versions recorded here are the resolution this "
            "release was built and tested against, not necessarily what a "
            "consumer installs."
        )

    root_pkg: dict[str, Any] = {
        "SPDXID": root_id,
        "name": root["name"],
        "versionInfo": root["version"],
        "downloadLocation": prov.get("download_location") or "NOASSERTION",
        "filesAnalyzed": False,
        # The product's own terms are known, unlike a third party's: this is
        # DERSec software and DERSec states how it is licensed. Only the
        # dependencies fall back to NOASSERTION.
        "licenseConcluded": prov.get("product_license") or "NOASSERTION",
        "licenseDeclared": prov.get("product_license") or "NOASSERTION",
        "copyrightText": f"Copyright (c) {datetime.now(UTC).year} DER Security Corp",
        "supplier": "Organization: DER Security Corp",
        "description": root["description"] or "",
        "comment": " ".join(root_comment),
    }
    # No sourceInfo. SPDX uses it for "how this package was obtained or
    # built", which for these products means a private repository and a
    # commit SHA -- internal detail that must not ship in a document
    # published to customers. The release tag in versionInfo and the comment
    # is the binding a reader needs.
    packages: list[dict[str, Any]] = [root_pkg]

    ref_to_id: dict[str, str] = {root["bom_ref"]: root_id}

    for ref, entry in sorted(model["components"].items(), key=lambda kv: kv[1]["name"].lower()):
        pid = spdx_id("Package", entry["name"], entry["version"])
        ref_to_id[ref] = pid
        pkg: dict[str, Any] = {
            "SPDXID": pid,
            "name": entry["name"],
            "versionInfo": entry["version"],
            "downloadLocation": entry["download_url"] or "NOASSERTION",
            "filesAnalyzed": False,
            # No license analysis of the package contents is performed, so a
            # concluded license would be an assertion this process cannot
            # support. Only the declared license is reported.
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": entry["license_expression"],
            "copyrightText": "NOASSERTION",
            "supplier": "NOASSERTION",
        }
        if entry["description"]:
            pkg["description"] = entry["description"]
        if entry["digest"]:
            algo, value = entry["digest"]
            pkg["checksums"] = [
                {"algorithm": DIGEST_ALGORITHMS[algo]["spdx"], "checksumValue": value}
            ]
        if entry["purl"]:
            pkg["externalRefs"] = [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": entry["purl"],
                }
            ]
        notes = []
        if entry["license_note"]:
            notes.append(entry["license_note"])
        if entry["private_source"]:
            notes.append("distributed from a private package index")
        if notes:
            pkg["comment"] = "; ".join(notes)
        packages.append(pkg)

    relationships: list[dict[str, str]] = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": root_id,
        }
    ]
    for ref, targets in sorted(model["edges"].items()):
        src = ref_to_id.get(ref)
        if not src:
            continue
        for target in sorted(targets):
            dst = ref_to_id.get(target)
            if dst:
                relationships.append(
                    {
                        "spdxElementId": src,
                        "relationshipType": "DEPENDS_ON",
                        "relatedSpdxElement": dst,
                    }
                )

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": doc_name,
        "documentNamespace": f"{namespace_base}/{doc_name}-{serial}",
        "creationInfo": {
            "created": now,
            "creators": [
                "Organization: DER Security Corp",
                "Tool: generate_sbom",
            ],
            "comment": (
                "Generated from the locked runtime dependency closure. Emitted "
                "alongside a CycloneDX document built from the same component "
                "model; the two are intended to agree component for component."
            ),
        },
        "packages": packages,
        "relationships": relationships,
        **extracted_licensing_info(packages),
    }


def extracted_licensing_info(packages: list[dict[str, Any]]) -> dict[str, Any]:
    """Define every LicenseRef- identifier the document actually uses.

    Only refs that appear are defined, so the document does not carry
    definitions for licenses it never mentions. An unknown ref is defined
    with NOASSERTION text rather than omitted: leaving it undefined would
    make the document invalid, and inventing license text would be worse
    than admitting the text is not recorded here.
    """
    used: set[str] = set()
    for pkg in packages:
        for field in ("licenseDeclared", "licenseConcluded"):
            used.update(LICENSE_REF.findall(pkg.get(field) or ""))
    if not used:
        return {}

    infos = []
    for ref in sorted(used):
        known = EXTRACTED_LICENSES.get(ref)
        infos.append(
            {
                "licenseId": ref,
                "name": known["name"] if known else ref,
                "extractedText": known["extractedText"] if known else "NOASSERTION",
                **({"seeAlsos": known["seeAlsos"]} if known and known.get("seeAlsos") else {}),
            }
        )
    return {"hasExtractedLicensingInfos": infos}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--cyclonedx", required=True, type=Path)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument(
        "--uv-lock",
        type=Path,
        help="uv lockfile. For an application, which pins and ships a whole tree.",
    )
    src.add_argument(
        "--requirements",
        type=Path,
        help=(
            "Pinned requirements with hashes, from `uv pip compile "
            "--generate-hashes`. For a library, which declares ranges and has "
            "no lockfile: the document then describes the resolution this "
            "release was built and tested against, not one every consumer "
            "will get."
        ),
    )
    ap.add_argument("--version", required=True)
    ap.add_argument("--out-dir", required=True, type=Path)
    ap.add_argument(
        "--product-name",
        help=(
            "Override the product name taken from the scanned root component. "
            "Needed where one codebase ships as more than one product: they "
            "share a dependency closure but are distinct to a consumer, so "
            "each gets an SBOM naming the one they installed."
        ),
    )
    ap.add_argument(
        "--namespace-base",
        default="https://sbom.invalid",
        help=(
            "Base URI for the SPDX documentNamespace. The product name is "
            "appended to it, so one value serves every product line."
        ),
    )
    # Release binding. An SBOM that records only a version number cannot be
    # tied back to the build it describes: a version present in source is not
    # necessarily a version that shipped. The release tag is what ties the
    # document to one published release.
    #
    # Deliberately absent: source repository URL and commit SHA. These
    # documents are published to customers, and the repositories are private
    # -- naming them, or the commit a build came from, discloses internal
    # development detail to every reader. Internal build traceability belongs
    # in the release record, not in a customer-facing artifact.
    ap.add_argument(
        "--release-tag",
        help="Release tag this SBOM describes, e.g. v0.18.1 or server-v1.1.34.",
    )
    ap.add_argument(
        "--npm-lock",
        type=Path,
        help=(
            "Path to a package-lock.json whose production closure ships with "
            "the product. Without it a bundled JavaScript frontend is absent "
            "from the SBOM even though customers run it."
        ),
    )
    ap.add_argument(
        "--vendored-assets",
        type=Path,
        help=(
            "Path to a vendor.json describing browser libraries committed into "
            "the product. Without it those components are absent from the SBOM "
            "even though they ship, which is the blind spot that hides them "
            "from dependency scanners too."
        ),
    )
    ap.add_argument(
        "--product-license",
        default="",
        help=(
            "SPDX license expression for the product itself. Defaults to the "
            "DERSec commercial identifier; its terms are defined in the "
            "document's extracted-licensing section so a reader is not left "
            "with an identifier they cannot resolve."
        ),
    )
    ap.add_argument(
        "--download-location",
        help=(
            "Customer-facing location the release artifact is obtained from. "
            "Becomes the SPDX root package downloadLocation and a CycloneDX "
            "distribution reference. Must be a customer-reachable URL, never "
            "an internal index or bucket."
        ),
    )
    args = ap.parse_args()

    cdx = json.loads(args.cyclonedx.read_text(encoding="utf-8"))
    if args.uv_lock:
        lock = load_lock_artifacts(args.uv_lock)
        resolution = "lockfile"
    else:
        lock = load_requirements_hashes(args.requirements)
        resolution = "build-time"
    extra = load_vendored_assets(args.vendored_assets) if args.vendored_assets else []
    if args.npm_lock:
        if not args.npm_lock.exists():
            print(f"error: --npm-lock {args.npm_lock} not found", file=sys.stderr)
            return 1
        extra += load_npm_lock(args.npm_lock)
    model = build_model(cdx, lock, extra=extra)

    if args.product_name:
        # Rename in the CycloneDX document too, not only in the model, so the
        # emitted pair agree on the product and neither can be read as
        # describing the package the venv happened to be built from.
        #
        # The version guard below is skipped in this mode on purpose. Where a
        # codebase ships as several products the release version lives outside
        # the package metadata (the dashboard workspace carries it in a VERSION
        # file at the repository root, and its member package declares none),
        # so there is no scanned version to check --version against. The caller
        # owns getting the version right here.
        model["root"]["name"] = args.product_name
        model["root"]["version"] = args.version
        cdx["metadata"]["component"]["name"] = args.product_name
        cdx["metadata"]["component"]["version"] = args.version
    elif model["root"]["version"] != args.version:
        print(
            f"error: scanned root version {model['root']['version']!r} does not match "
            f"--version {args.version!r}; refusing to emit a mislabelled SBOM",
            file=sys.stderr,
        )
        return 1

    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    # A deterministic serial keyed to the document's content means rebuilding
    # the same release produces the same identifier rather than a new one.
    seed = f"{model['root']['name']}@{args.version}:" + ",".join(
        sorted(f"{c['name']}@{c['version']}" for c in model["components"].values())
    )
    serial = str(uuid.UUID(hashlib.sha256(seed.encode()).hexdigest()[:32]))

    args.out_dir.mkdir(parents=True, exist_ok=True)
    # The product name comes from the scanned root component rather than a
    # flag, so the filename and the document's own contents cannot disagree
    # about which product this SBOM describes.
    product = model["root"]["name"]
    stem = f"{product}-{args.version}"
    namespace = f"{args.namespace_base.rstrip('/')}/{product}"

    cdx_out = args.out_dir / f"{stem}.cdx.json"
    spdx_out = args.out_dir / f"{stem}.spdx.json"
    prov = {
        "resolution": resolution,
        "release_tag": args.release_tag or "",
        "download_location": args.download_location or "",
        "product_license": args.product_license or "",
    }
    cdx_out.write_text(
        json.dumps(render_cyclonedx(model, cdx, serial, now, prov), indent=2, sort_keys=False)
        + "\n",
        encoding="utf-8",
    )
    spdx_out.write_text(
        json.dumps(render_spdx(model, serial, now, namespace, prov), indent=2) + "\n",
        encoding="utf-8",
    )

    leaks = find_internal_references(cdx_out) + find_internal_references(spdx_out)
    if leaks:
        # Refuse to leave a document on disk that a release job would go on to
        # publish. Failing the build is the only outcome that reliably stops
        # an internal reference reaching a customer.
        cdx_out.unlink(missing_ok=True)
        spdx_out.unlink(missing_ok=True)
        print("error: internal references in generated SBOM; nothing written", file=sys.stderr)
        for leak in leaks:
            print(f"  {leak}", file=sys.stderr)
        return 1

    missing_license = [
        c["name"] for c in model["components"].values() if c["license_expression"] == "NOASSERTION"
    ]
    missing_hash = [c["name"] for c in model["components"].values() if not c["digest"]]

    print(f"components:      {len(model['components'])}")
    print(f"cyclonedx:       {cdx_out}")
    print(f"spdx:            {spdx_out}")
    if missing_license:
        print(f"no declared license ({len(missing_license)}): {', '.join(sorted(missing_license))}")
    if missing_hash:
        if resolution == "build-time":
            # Expected here rather than a defect. A compiled requirements file
            # lists every artifact that satisfies a pin -- the sdist and one
            # wheel per platform -- and no single one of them identifies the
            # package, so none is recorded. A lockfile distinguishes the sdist
            # and so can. The PURL and exact version are present either way,
            # which is what a vulnerability scanner matches on.
            print(
                f"no artifact hash ({len(missing_hash)}): expected for a "
                "range-declaring project; a pin resolves to several equally "
                "valid artifacts and none identifies the package"
            )
        else:
            print(f"no artifact hash ({len(missing_hash)}): {', '.join(sorted(missing_hash))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
