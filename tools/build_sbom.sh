#!/usr/bin/env bash
# Build the release SBOM pair (CycloneDX + SPDX) for one product.
#
# Resolves the product's locked runtime dependencies into a throwaway venv,
# scans that venv for package metadata, and renders both documents from the
# result. The venv is what makes declared licenses and the dependency graph
# available -- a lockfile alone carries neither.
#
# Runtime dependencies only: --no-dev excludes test and build tooling, which
# is not in what the customer runs and would otherwise inflate the document
# with components that ship to nobody.
#
# Usage:
#   tools/build_sbom.sh --project-dir . --version 0.18.1 --out-dir dist/sbom
#   tools/build_sbom.sh --project-dir subproject --version 1.2.0 \
#       --out-dir dist/sbom
#   tools/build_sbom.sh --project-dir . --package dashboard --version 4.1.7 \
#       --product-name alt-name --out-dir dist/sbom
set -euo pipefail

PROJECT_DIR="."
PACKAGE=""
PRODUCT_NAME=""
VENDORED_ASSETS=""
NPM_LOCK=""
VERSION=""
OUT_DIR=""
PYTHON_VERSION="3.13"
# Pinned: an unpinned uvx resolves whatever cyclonedx-bom is newest at release
# time, so identical source could produce different documents, or fail, on a
# day the tool publishes a change. Upgrades should be a reviewed commit.
CYCLONEDX_BOM_VERSION="7.1.0"
RELEASE_TAG=""
# The project's own SPDX license expression. Getting this wrong is easy when
# copying an invocation between repositories under different terms, so it is
# an explicit argument with no default rather than something inferred.
PRODUCT_LICENSE=""
DOWNLOAD_LOCATION=""

while [ $# -gt 0 ]; do
  case "$1" in
    --project-dir)   PROJECT_DIR="$2"; shift 2 ;;
    # Workspace member to resolve, where the project is a uv workspace whose
    # root declares no dependencies of its own.
    --package)       PACKAGE="$2"; shift 2 ;;
    # Override the product name when one codebase ships as several products.
    --product-name)  PRODUCT_NAME="$2"; shift 2 ;;
    # Browser libraries committed into the product. Omitted for a project
    # that ships none; passing a path that does not exist is an error rather
    # than a silent skip, so a renamed manifest cannot quietly drop them.
    --vendored-assets) VENDORED_ASSETS="$2"; shift 2 ;;
    # package-lock.json for a bundled JavaScript frontend. Its production
    # closure ships with the product, so it belongs in the same document.
    --npm-lock)      NPM_LOCK="$2"; shift 2 ;;
    --version)       VERSION="$2"; shift 2 ;;
    --out-dir)       OUT_DIR="$2"; shift 2 ;;
    --python)        PYTHON_VERSION="$2"; shift 2 ;;
    --release-tag)   RELEASE_TAG="$2"; shift 2 ;;
    --product-license) PRODUCT_LICENSE="$2"; shift 2 ;;
    --download-location) DOWNLOAD_LOCATION="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [ -n "$VENDORED_ASSETS" ] && [ ! -f "$VENDORED_ASSETS" ]; then
  echo "error: --vendored-assets $VENDORED_ASSETS not found" >&2
  exit 1
fi

if [ -n "$NPM_LOCK" ] && [ ! -f "$NPM_LOCK" ]; then
  echo "error: --npm-lock $NPM_LOCK not found" >&2
  exit 1
fi

if [ -z "$VERSION" ] || [ -z "$OUT_DIR" ]; then
  echo "usage: $0 --project-dir DIR --version X.Y.Z --out-dir DIR" >&2
  exit 2
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="$(mkdir -p "$OUT_DIR" && cd "$OUT_DIR" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cd "$REPO_ROOT/$PROJECT_DIR"

EXPORT_ARGS=(--frozen --no-dev --no-emit-project --format requirements-txt)
if [ -n "$PACKAGE" ]; then
  EXPORT_ARGS+=(--package "$PACKAGE")
fi

# An application pins its whole tree in uv.lock and ships exactly that. A
# library declares ranges and the consumer resolves them, so there is no
# lockfile: the honest thing a release can describe is the resolution its own
# CI produced and tested. Which input applies is decided by what the project
# has, not by a flag someone has to remember.
if [ -f uv.lock ]; then
  echo "==> exporting locked runtime dependencies"
  uv export "${EXPORT_ARGS[@]}" -o "$WORK/requirements.txt"
  RESOLUTION_ARG=(--uv-lock uv.lock)
else
  echo "==> resolving declared dependencies (no lockfile: this is a library)"
  uv pip compile pyproject.toml --generate-hashes -q -o "$WORK/requirements.txt"
  RESOLUTION_ARG=(--requirements "$WORK/requirements.txt")
fi

# A project with no runtime dependencies resolves to nothing, and that is a
# true and useful thing for an SBOM to say -- not a failure. Distinguish it
# from a misconfiguration by asking what the project declares: nothing
# resolved AND nothing declared is correct; nothing resolved while
# dependencies are declared means the resolution did not do what was asked.
if ! grep -q '==' "$WORK/requirements.txt"; then
  DECLARED="$(python3 -c "
import tomllib
p = tomllib.load(open('pyproject.toml','rb'))['project']
print(len(p.get('dependencies') or []))
")"
  if [ "$DECLARED" != "0" ]; then
    echo "error: $DECLARED dependencies declared but none resolved from $PROJECT_DIR." >&2
    echo "If this project is a uv workspace, pass --package <member>." >&2
    exit 1
  fi
  echo "==> project declares no runtime dependencies; the SBOM will describe the root component alone"
fi

echo "==> resolving into a throwaway environment"
uv venv "$WORK/venv" --python "$PYTHON_VERSION" >/dev/null

# A project whose runtime closure includes a first-party package resolves it
# from the private index. The URL carries a credential, so it reaches uv
# through uv's own environment variable rather than as an argument:
# arguments appear in process listings and in CI step logs.
#
# Set on the install command alone, not exported. An export would also put
# the credential in the environment of the scanning tool that runs next,
# which has no need of it -- the same disclosure one process further on.
# --require-hashes makes the install itself verify every artifact against the
# lockfile, so a substituted distribution fails here rather than being
# described as trustworthy by the SBOM we are about to emit.
UV_EXTRA_INDEX_URL="${SBOM_EXTRA_INDEX_URL:-}" \
  uv pip install --python "$WORK/venv" --require-hashes \
  -r "$WORK/requirements.txt" >/dev/null

echo "==> scanning environment"
uvx --from "cyclonedx-bom==$CYCLONEDX_BOM_VERSION" cyclonedx-py environment "$WORK/venv" \
  --pyproject "${PACKAGE:+packages/$PACKAGE/}pyproject.toml" \
  --sv 1.6 --of JSON --output-reproducible \
  -o "$WORK/environment.cdx.json"

echo "==> rendering SBOM documents"
GENERATE_ARGS=(
  --cyclonedx "$WORK/environment.cdx.json"
  "${RESOLUTION_ARG[@]}"
  --version "$VERSION"
  --out-dir "$OUT_DIR"
)
if [ -n "$PRODUCT_NAME" ]; then
  GENERATE_ARGS+=(--product-name "$PRODUCT_NAME")
fi
if [ -n "$VENDORED_ASSETS" ]; then
  GENERATE_ARGS+=(--vendored-assets "$REPO_ROOT/$VENDORED_ASSETS")
fi
if [ -n "$NPM_LOCK" ]; then
  GENERATE_ARGS+=(--npm-lock "$REPO_ROOT/$NPM_LOCK")
fi
if [ -n "$RELEASE_TAG" ]; then
  GENERATE_ARGS+=(--release-tag "$RELEASE_TAG")
fi
if [ -n "$PRODUCT_LICENSE" ]; then
  GENERATE_ARGS+=(--product-license "$PRODUCT_LICENSE")
fi
if [ -n "$DOWNLOAD_LOCATION" ]; then
  GENERATE_ARGS+=(--download-location "$DOWNLOAD_LOCATION")
fi
python3 "$REPO_ROOT/tools/generate_sbom.py" "${GENERATE_ARGS[@]}"
