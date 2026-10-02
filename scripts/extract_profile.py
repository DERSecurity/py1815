"""Read the IEEE 1815.2-2025 Profile Companion Data Point Tables into JSON.

Keeps `conformance/ieee-1815-2-2025.json`, the copy the repository's tests
read, in step with a workbook held locally:

    python scripts/extract_profile.py --cdpt "<the workbook>.xlsx" --write
    python scripts/extract_profile.py --cdpt "<the workbook>.xlsx" --check

The extraction itself is `py1815.profile.extract`, which the `py1815-der
tables` command also uses; this script only says where the repository keeps
the result. Neither the workbook nor the file is committed, for the reason
`conformance/README.md` gives.
"""

from __future__ import annotations

import pathlib
import sys

_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "src"))

from py1815.profile import extract  # noqa: E402

#: Where the repository's copy of the tables lives.
TABLES = _ROOT / "conformance" / "ieee-1815-2-2025.json"

if __name__ == "__main__":
    raise SystemExit(extract.main(tables=TABLES))
