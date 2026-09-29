# Contributing

Contributions are welcome -- bug reports, interop findings from real masters,
and documentation.

## Before you write code

**For a bug**, open an issue with enough to reproduce it: the master
implementation you were talking to, the function code and objects involved, and
the frame bytes if you have them. An outstation is judged by what it puts on the
wire, so a capture or a hex dump is worth more than a description.

**For a feature or a behavior change**, open an issue first. This is a protocol
implementation, so the useful question is rarely "should we do this" but "what
does the standard require" -- and that is cheaper to settle before the code than
after.

**For a point map**, the IEEE 1815.2 DER profile's tables cannot ship here: they
assign specific indices to specific measurements and are distributed to DNP
Users Group members rather than published, so a library carrying them could not
be shared. A map for your own device belongs in your project.

That prohibition is narrower than "no maps ever". The roadmap plans a map-format
loader and a published table for the predecessor DER profile, and whether the
AN2018-001-derived map ships with the first release is an open question in
[DESIGN.md](docs/DESIGN.md) -- it carries an attribution obligation that needs
confirming before publication. Neither the loader nor the format exists yet; the
only interface today is the caller-supplied `ReadProvider`. Open an issue before
building against either.

## Development setup

```bash
git clone https://github.com/DERSecurity/py1815
cd py1815
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

There are no runtime dependencies, and that is deliberate -- an outstation that
drags a dependency tree onto an embedded target is harder to justify than one
that does not. The development extra is `pytest`, `pytest-asyncio`, `ruff` and
`mypy`.

Then:

```bash
pytest -q
ruff check src tests interop
ruff format --check src tests interop
mypy src
```

CI runs all four on Python 3.11, 3.12 and 3.13.

## The interop jobs

The unit suite is this library marking its own homework: a test that encodes
with this library and decodes with it agrees with itself through any mistake
both halves share. The `interop` workflow is the part that does not, and it
gates every pull request.

Four implementations across three jobs, chosen so no two are the same codebase
in different clothes: a C++ master through its Python bindings, a Rust master by
different authors, and Wireshark and Suricata reading a capture of the whole
function code sweep. The masters answer "does it say the right thing"; the
dissectors answer "is what it put on the wire really DNP3".

A change to framing, to object encoding, or to the function codes the outstation
answers should expect to be caught here rather than by the unit tests. Run it
locally before pushing if you can -- `interop/` holds the outstation fixture and
each peer's driver.

## What a good change looks like

**Tests that could fail.** A test that passes against the broken code tests
nothing. The check that catches this: revert your fix, confirm the test fails,
restore it. Assertions shaped like the fixture rather than the behavior are the
usual way this goes wrong.

**Bytes, not round trips.** Protocol tests compare against literal octets --
`bytes.fromhex` and an explicit expected value. A test that encodes and then
decodes with the same library proves only that the two halves agree, which they
will even when both are wrong.

**Comments that say why.** What the code does is visible; why it does that
rather than the obvious thing is not. Where the standard forced your hand, cite
the clause -- a reference to IEEE 1815 tells the next reader far more than a
restatement of the line below it.

**Type annotations on public API.** `mypy` runs against `src/`. Tests are
exempt.

## How changes land

Every change to `main` arrives through a pull request, including the
maintainers' own. Direct pushes, force pushes and branch deletion are blocked by
branch protection, with no bypass.

A pull request merges when the three test jobs and the `interop` gate are green
and it carries an approving review. Branches do not have to be up to date with
`main` first: merging one pull request does not send the others back for a
rebase, because the peer jobs run against the merge result anyway.

## The changelog

A changelog entry is a file in `changelog.d/`, not an edit to `CHANGELOG.md`.
Name it `<pull-request>.<category>.md` and write the entry body into it.
`changelog.d/README.md` has the rules and the reason, which is that two pull
requests editing the same `[Unreleased]` heading conflict on every pair.

```bash
python scripts/build_changelog.py --check     # what CI runs
python scripts/build_changelog.py --preview   # render as it will appear
```

A release folds the pending fragments in with
`python scripts/build_changelog.py --release X.Y.Z`, bumps the version in
`pyproject.toml`, and deletes the fragments it consumed in that same commit.

## Conventions

- Line length 100, enforced by `ruff`.
- American English in code, comments, and documentation.
- Commit messages: a short imperative subject, then prose explaining why the
  change is right. No trailers.

## Reporting a security issue

Please do not open a public issue for a vulnerability. See
[SECURITY.md](SECURITY.md).
