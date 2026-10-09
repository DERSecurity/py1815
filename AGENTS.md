# Rules for working in this repository

py1815 is a DNP3 (IEEE 1815) library in pure Python: an outstation, the IEEE 1815.2 DER
profile on top of it, and a master with a JSON service, an HTTP API and a web console.
Devices built on it sit on control networks, so a wrong octet is a defect in someone's
equipment.

These rules apply to every contributor, human or coding agent. They say what a change is
held to. [CONTRIBUTING.md](CONTRIBUTING.md) covers setup, the interoperability jobs and
how a release is cut, and is not repeated here.

**Before changing anything, read:**

1. [README.md](README.md), for what the library does and how it is laid out.
2. The decisions in [docs/DESIGN.md](docs/DESIGN.md) that touch the area you are changing,
   and its Layering section.
3. The plan for the area in [docs/planning/](docs/planning/), if there is one.
4. [docs/testing.md](docs/testing.md), for how each kind of behavior is tested.

## 1. Correctness comes first

Correctness outranks features, speed, convenience and a tidy API. A change that is not
known to be correct is not finished, however complete it looks.

### What decides what is correct

In this order:

1. **IEEE Std 1815-2012**, the DNP3 standard.
2. **IEEE Std 1815.2-2025**, for the DER profile. Where Subset Level 2 and the profile
   disagree, the profile wins and the divergence is named in `docs/DESIGN.md`.
3. **The DNP Users Group's technical bulletins and application notes.** They correct and
   clarify the standard. Where one corrects the standard, the bulletin is what the code
   follows.
4. **The DNP Users Group's IED Certification Procedure and subset definitions**, for what
   an outstation of a level must accept and how a test house checks it.
5. **EPRI's test procedure for the DER profile** (report 3002016144). It predates IEEE
   1815.2. Where the two differ, follow the standard and record the departure in
   `tests/test_epri_coverage.py`.

Other implementations are witnesses, not authorities. opendnp3, the Step Function I/O
`dnp3` crate, Wireshark and Suricata show whether this library interoperates. When a peer
disagrees with this library, go back to the documents above to find out which is right.

These do not decide anything:

- What this library does today.
- What another implementation happens to do.
- Memory, a forum post, or a model's recollection of a clause.

### Rules that follow

- **Cite the source.** Where a document forced a choice, name the clause, table or
  bulletin in the code comment and in the decision: `IEEE 1815-2012 4.3 rule 16`,
  `TB2013-003`. A reader must be able to check the claim.
- **Never invent a protocol fact.** No guessed clause numbers, function codes, qualifier
  codes, object variations, enumeration values or point indices. If you cannot find the
  source, say so in the pull request and ask. "Not verified against the standard" is an
  acceptable sentence. A confident guess is not.
- **Where the documents are silent or ambiguous, decide in the open.** Write a numbered
  decision with its trade-off, and prefer what interoperates with the independent peers.
- **List every deliberate departure** beside the test that would otherwise fail, with the
  reason. Anything not on the list must fail.
- **A failing test is a finding.** Do not weaken an assertion, widen a tolerance, or mark a
  test skipped to get a green run. Find out which side is wrong first.
- **Report what you did not check.** If a step was skipped or a test could not run on your
  machine, say so.

## 2. What must not be committed

This repository is public. Some of the material the work depends on may not be
redistributed.

- **No standards text.** Not IEEE 1815, not IEEE 1815.2, not their tables as published.
- **No IEEE 1815.2 point tables.** Not the workbook and not the file made from it
  (`ieee-1815-2-*.json`). `.gitignore` excludes them; never force-add them, and never
  build them into a Docker image. CI checks that the images carry none.
- **No DNP Users Group documents**: the certification procedure, the subset workbook, the
  Device Profile schema and stylesheets, the bulletins themselves.
- **No EPRI report text.**

What may be committed:

- Code assignments, canonical names and field widths, which are the wire vocabulary a
  second implementation needs. `conformance/README.md` explains where that line is.
- A procedure's section number or identifier, and a description of what is checked in
  your own words.
- Synthetic tables invented for the tests (`tests/profile_fixtures.py`). CI runs against
  these. A test that needs the real tables skips when they are absent and runs on a
  machine that has them.

Also never commit:

- Names of private repositories, internal products, customers or people, or anything else
  that only makes sense inside one organization.
- Local paths, host names, credentials, tokens or keys.
- A capture or log from a real device, unless its owner agreed and it holds nothing that
  identifies the site.
- Code copied from another implementation. The interoperability peers are run against,
  not copied from, and none of them may become a dependency. The `dnp3` crate is not under
  an open-source license; [docs/testing.md](docs/testing.md) states the terms it is used on.
- A check or script that lists private names so that they can be caught. The list would
  publish them. Remove the reference itself.

Related rules:

- **Everything posted here is public and permanent**: issues, pull requests, comments,
  commit messages and branch names. Write each as a self-contained record that a stranger
  can follow.
- **Credit what is taken from another project**, such as a default or a name chosen
  because it is the one that interoperates. `docs/testing.md` shows how.
- **A bug found in another project is reported there** as a neutral, self-contained
  report: the protocol, the version, a reproduction and a suggested fix. Check that
  project's rules first.
- **A vulnerability is reported privately**, as [SECURITY.md](SECURITY.md) describes, not
  in a public issue or a pull request.
- **A secret is not a setting.** The console's token and a key's password are given on
  the command line or in the environment and are not keys of the configuration file. Do not add a
  secret to a file the tools write.

## 3. Design rules

- **No runtime dependencies (D1).** The library uses the standard library only, so it runs
  where no compiler does. A new import of a third-party package in `src/` needs a decision
  that replaces D1, which is unlikely to be accepted. Development and documentation tools
  go in the optional extras.
- **Python 3.11 and later**, on 64-bit and 32-bit machines. Do not assume the width of a
  native integer in a `struct` format or in anything that handles time. The suite also
  runs on 32-bit ARM.
- **Keep the layers apart.** Each layer is testable without the ones above it. The session
  and the master association do no I/O: octets in, octets out, with time injected. The
  Layering section of `docs/DESIGN.md` says what each module knows and does not know. A
  new module gets a line there.
- **Everything from the network is untrusted.** A malformed frame, fragment or object is
  refused the way the standard says, never by an unhandled exception. Do not trust a
  length before its checksum verifies.
- **Every buffer has a limit (D89).** No list, queue or file grows without bound in a
  process meant to run for days.
- **A control is sent once (D80).** The master never repeats a select, an operate, a
  write, a freeze or a restart. Only a read may be sent again, and only when asked.
- **Writing to an outstation is opt-in.** The service, the console and the commands write
  only when started with `--allow-control`. A new operation that changes anything at an
  outstation is refused without it, is recorded in the command log, and is covered by the
  test that holds the two together.
- **One list of operations.** The socket master, the in-process master, the blocking
  master and the service share one list, and tests fail when one gains an operation
  another lacks. Add an operation to the list, not to one carrier.
- **Every setting is in the configuration file and has a flag.** See section 5.
- **A timer must not act for an absent master.** `tests/test_master_silence.py` has to
  pass with any timer you add.
- **The DER is out of scope.** The library carries the profile's points. What a DER does
  with them is the device's. The simulated DER exists to show the points working and is
  not to grow into a model of a DER.
- **Use the standard's terms**: master, outstation, fragment, segment, frame, select,
  operate, unsolicited response.
- **Follow the pattern that is already there.** A profile operation is a plan of requests
  that any carrier runs. A result is a frozen dataclass. A timeout or a refusal is a
  result, not an exception. Read a neighboring module before adding a new shape.
- **Prefer one general mechanism to many similar edits.** If a change repeats the same
  few lines in a dozen places, the shared piece is missing.
- **Do not expose what does not work.** A command, a console control or an API operation
  is added when its behavior works, not before. No placeholders and no "coming soon".
- **Name the encoding and the line ending** of every text file the code reads or writes
  (`encoding="utf-8"`, `newline="\n"`). Contributors work on Windows and Linux, and the
  defaults differ.

### Where things go

| What | Where |
|---|---|
| The protocol layers and the outstation | `src/py1815/` |
| The IEEE 1815.2 DER profile and the simulated DER | `src/py1815/profile/` |
| The master, its service, API and commands | `src/py1815/master/` |
| The console's files and the generated API document | `src/py1815/master/console/` |
| Unit tests, one file per subject, and their harnesses and fixtures | `tests/` |
| Drivers for the independent peers | `interop/` |
| Scripts a maintainer runs by hand | `scripts/` |
| Release tooling and its own tests | `tools/` |
| Guides, the design record and plans | `docs/`, `docs/DESIGN.md`, `docs/planning/` |
| Published reference pages | `docs/reference/` |
| Tables checked against the standard | `conformance/` |
| Pending changelog entries | `changelog.d/` |

A new top-level directory or a new kind of file needs a reason in the pull request. The
source distribution is an allow-list in `pyproject.toml`: a path that should ship has to
be named there.

### Recording a decision

A choice a reader could reasonably argue with gets a numbered entry in the Decisions
section of `docs/DESIGN.md`:

```markdown
**D<n> -- One sentence that states the decision.** Why, with the clause or bulletin that
bears on it, and what was considered. *Trade-off:* what this costs.
```

- Take the next free number. Numbers are never reused or renumbered, because code,
  tests and other decisions refer to them.
- A decision that replaces an earlier one says which, and the earlier one stays.
- Refer to a decision by its number in code comments where it explains the code.

## 4. Tests

- **Every change in behavior has a test that fails without it.** Check this: commit, break
  the line the test is for, confirm the test fails, restore it. Say in the pull request
  that you did.
- **Literal octets, not round trips.** A protocol test compares against octets written out
  by hand (`bytes.fromhex`). A test that encodes and decodes with this library agrees
  with itself through any mistake both halves share.
- **Test behavior, not source text.** Do not assert on the wording of the implementation
  or search source files for a string.
- **Do not replace the thing under test.** A test that mocks the code path it claims to
  check proves nothing. Substitute what is outside the unit: the clock, the socket, the
  device behind a binding.
- **Prove a check can fail.** A test, a guard or a validator is shown to catch the fault it
  is for, with a case that has the fault.
- **Keep the catalogs in step.** `tests/test_ied_coverage.py`,
  `tests/test_bulletin_coverage.py` and `tests/test_epri_coverage.py` list every section,
  bulletin and procedure as tested or as not applicable with the reason. A feature that
  makes an entry applicable moves the entry and adds its test in the same change.
  `tests/test_conformance.py` checks the code tables against `conformance/`.
- **Name a test for the behavior it checks**, so the name reads on its own in a failure
  report. A test that carries out a procedure also carries its identifier:
  `test_8_2_1_2_4_...`, `test_tb2013_003_...`, `test_mon_001_...`.
- **Mark async tests.** `asyncio_mode` is strict: an `async def` test without
  `@pytest.mark.asyncio` never runs.
- **Inject the clock.** Do not sleep in real time where a clock or an advance hook can be
  passed in. A test that waits on the wall clock is slow and fails on a busy runner.
- **Stay on the loopback interface.** The unit suite uses no network beyond `127.0.0.1`.
- **A skip needs a reason and must be visible.** A test that needs a file or a browser the
  machine lacks skips and says why. Where CI has what the test needs, a skip there is a
  failure.
- **Interoperability is the independent check.** A change to framing, object encoding,
  the function codes answered or the requests the master builds is expected to be caught
  by the `interop` workflow. Update the peers' expectations in `interop/` in the same
  change, including the counts that guard against a check silently not running.
- **The console is tested in a browser.** A change to the console's files comes with a
  test in `tests/test_master_console*.py`.
- **Run the full suite once before pushing**, on its own. Several suites in parallel on
  one machine fail for reasons that are not in the code.

## 5. Documentation and generated files move with the code

A change is not complete until every surface that describes it is updated in the same
pull request.

| When you | Also update |
|---|---|
| Add or change a feature | The guide that covers it under `docs/` (`outstation.md`, `der.md`, `master.md`, `console.md`, `master-api.md`), the README where it describes what the library does, and the docstrings |
| Add a guide page | `nav` in `mkdocs.yml`, and links to it from the pages a reader would come from |
| Add a public module | `docs/reference/`, so its docstrings are published, and the Layering list in `docs/DESIGN.md` |
| Add or change a service operation, an HTTP route, a parameter or a result | Its description in `src/py1815/master/openapi.py`, then `python -m py1815.master.openapi --write` to regenerate `src/py1815/master/console/openapi.json`, then `docs/master-api.md` |
| Add or change a setting | The configuration class (`master/config.py` or `profile/config.py`), its command-line flag, and `docs/master-config.md` or `docs/der-config.md`: the example file, the settings table and the flags table |
| Change the console | `docs/console.md` and the browser tests |
| Make a design choice | A numbered decision in `docs/DESIGN.md` |
| Finish or change a planned item | Its status in `docs/planning/` |
| Change how something is tested | `docs/testing.md` |
| Change anything a user can observe | A changelog fragment (section 7) |

Rules for these:

- **The OpenAPI document is generated, not edited.** CI runs
  `python -m py1815.master.openapi --check` and fails when the committed file is not the
  one the description builds. `tests/test_master_openapi.py` also fails when an operation
  exists that the document does not describe, and when the service's answer to a
  documented example does not fit the document.
- **A setting has four parts**: a key in the JSON configuration, validated with an error
  that names where the mistake is; a flag whose default is "not given", so it overrides
  the file only when used; a place in what the `config` command prints; and its row in the
  documentation. A test holds the documented example file to the real defaults.
- **The documentation build is strict.** `mkdocs build --strict` runs on every pull
  request, and a warning is an error.
- **Guides describe what the software does now.** Plans, status and what is left belong in
  `docs/planning/`.
- **The bar for a guide is that it is enough.** A person who reads only the guide can use
  the feature: the command, its options, what the output means and what it changes.
- **A fact lives in many places.** When a name, a default, a flag or a behavior changes,
  search for every place that states it: the README, the guides, the docstrings, the
  command help, the plans and the tests. Fixing only the place a reviewer pointed at
  leaves the others wrong.
- **Describe a capability by what it does for the reader**, not by the name of the module
  that implements it.
- **Bold marks a label** at the start of a paragraph or a list item. It is not used for
  emphasis in the middle of a sentence.
- **Do not write counts that will drift** ("the 34 checks", "all 12 endpoints") in
  comments, guides or the README. Name the thing, or point at the command that lists it.

## 6. Comments, docstrings, names and messages

Write in plain, direct technical English. Say what the code does in the fewest words that
are still clear.

| Do not write | Write |
|---|---|
| `"""When the change this reading shows is said to have happened."""` | `"""Return the timestamp for an event raised by this reading."""` |
| `# Whoever asked has stopped waiting, so it is ended here and kept as a result.` | `# The caller cancelled while the request was in flight. End it as abandoned and record it.` |
| `def test_so_is_one_announced_unasked(self):` | `def test_unsolicited_restart_runs_startup_again(self):` |

- **Lead with the action or the fact.** A function's docstring starts with a verb:
  "Return...", "Build...", "Wait until...".
- **Use the standard terms** of DNP3 and of this codebase: request, response, pending,
  enabled, timeout, retry. Do not invent figurative substitutes.
- **Name the subject.** Avoid chains of "it", "one" and "that" the reader has to resolve.
- **Prefer active voice and short sentences.** No storytelling.
- **Keep the why** when it is not obvious, and cite the clause where the standard is the
  reason. Do not restate what the line below already says.
- **Do not refer to pull requests, issues or project phases in code comments.** They go
  stale. A decision number or a clause stays true. The changelog and `docs/DESIGN.md` are
  where a pull request is cited.
- **A test name makes sense alone.** No names that depend on the test before them
  (`test_and_...`, `test_nor_is_...`).
- **An error message says what is wrong and where**, and how to fix it when that is known:
  `defaults.port must be a whole number from 1 to 65535`.
- **Text a user sees** (command help, console labels, API messages, guides) describes what
  the software does. It carries no internal names, no build status and no plans.
- **American English** in code, comments and documentation.
- **Line length 100**, enforced by `ruff`. Formatting is `ruff format`; do not hand-format
  against it.
- **Type annotations on everything in `src/`.** `mypy` runs in strict mode. A
  `# type: ignore` names the error code it silences and is rare.
- **A new module starts with a docstring** that says what the module is and what it does
  not know, and ends with the license line the other modules carry.
- **Run `pylint` on the files you add or change** and clear its warnings and errors. It is
  not in CI, and the code is kept clean of them. A disabled message is disabled on the
  line it applies to.

## 7. Commits, pull requests and review

- **Every change reaches `main` through a pull request**, the maintainers' own included.
  No direct pushes and no force pushes to `main`.
- **Look before you start.** Check the open issues and pull requests for work that
  overlaps yours. For a feature or a change in behavior, open an issue first: what the
  standard requires is cheaper to settle before the code than after.
- **Branches are named `<user>/<topic>`.**
- **One subject to a pull request.** Split unrelated work. A reviewer has to be able to
  hold the whole change in mind.
- **Do not push to a branch that is someone else's** without asking them.
- **A pull request merges when** the three test jobs and the `interop` gate are green, it
  has an approving review, and every review conversation is resolved. The ARM jobs are not
  among the required checks: read them before merging.
- **Pull requests are squash-merged.**
- **Commit messages**: a short imperative subject, then prose that says why the change is
  right. No trailers.
- **No tool or AI attribution.** No `Co-Authored-By` line for a tool, and no "generated
  with" footer, in a commit, a pull request description or a comment.
- **The pull request description says** what changed, why, how it was tested, what was
  deliberately left out, and anything that was not verified.
- **A changelog entry is a file**, `changelog.d/<pull-request>.<category>.md`, not an edit
  to `CHANGELOG.md`. The body opens with a bold sentence that says what changed and cites
  its own number: `(#42)`. Use the real number of the pull request, and check the file is
  staged after renaming it. `changelog.d/README.md` has the rest.
- **Answer every review comment.** Fix it with a test, or say why not. Reply on the thread
  with what was done and resolve it. This applies to automated reviewers as well.
- **In a stack of pull requests**, say in each description where it sits in the stack,
  keep the stack short, and merge from the bottom. Point the child at `main` before the
  parent is merged and its branch deleted.
- **Merge the head you checked.** Read that the required checks are green on the commit
  being merged. Auto-merge is not a substitute for reading them.
- **Review effort goes where CI cannot.** Section 8 lists what is checked mechanically. A
  reviewer's time is for whether the behavior is what the standard requires, whether the
  tests could fail, and whether the documentation is enough.
- **Do not go around a check.** No skipped hooks, no disabled jobs, no merging on red.
- **Releases** are cut by maintainers as CONTRIBUTING.md describes. A version on PyPI
  cannot be replaced, so nothing is tagged casually.

## 8. Before opening a pull request

```bash
ruff check src tests interop scripts
ruff format --check src tests interop scripts
mypy src
python scripts/build_changelog.py --check
python -m py1815.master.openapi --check
pytest -q
mkdocs build --strict
```

CI runs these on every pull request, on three versions of Python. It also runs the unit
suite on 32-bit ARM, builds the Docker images and checks that they carry no point tables,
and runs the interoperability jobs against the independent peers. The workflow files in
`.github/workflows/` are the authority on what runs. Where this page and a workflow
disagree, the workflow is right and this page needs fixing.

Then confirm:

- [ ] Each new behavior has a test, and the test fails when the behavior is broken.
- [ ] Protocol behavior is tied to a clause, a bulletin or a numbered decision.
- [ ] The guides, the README, the reference pages and the configuration pages say what the
      code now does.
- [ ] `openapi.json` was regenerated if the API changed.
- [ ] A changelog fragment exists and carries the pull request's number.
- [ ] `git status` shows only files that belong to the change, and none of the material
      section 2 forbids.

## 9. For coding agents

Everything above applies. In addition:

- **Do not rely on recall for protocol facts.** If the standard or the bulletin is not in
  front of you, say so and ask the maintainer. Do not fill the gap with what seems likely.
- **Read before you write.** Match the module you are in: its comment density, its naming
  and the way its tests are laid out.
- **Stage files by name.** Do not `git add -A` without reading `git status` first. Test
  runs and local tools leave files behind.
- **Send traffic only to the loopback interface and the simulated DER.** Never connect to,
  poll or command a real device unless the person directing the work names that device and
  asks for it.
- **Do not publish without being asked.** Opening a pull request, commenting on an issue
  and pushing a branch are visible to everyone. Tags and releases are the maintainers'.
- **Report faithfully.** State failures with their output, name the steps you skipped, and
  do not describe work as verified when it was only written.
- **When two rules here conflict, or a rule does not fit the case, stop and ask.**
