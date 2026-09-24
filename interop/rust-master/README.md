# The interoperability Rust master

A second DNP3 master, in a second language, used only to read this library's
outstation in continuous integration.

It exists because the other master this repository drives is built on opendnp3,
a C++ stack, and two interfaces over one core is one implementation rather than
two. It also checks something that one structurally cannot: opendnp3's Python
bindings store point values as bare scalars and discard the quality octet, so
that job verifies values and not flags. This stack hands the flags to its read
handler, so the point the fixture serves offline is verified as offline.

## The dependency is not open source

`dnp3`, published by Step Function I/O, is source available rather than open
source. Its licence forbids use that "directly or indirectly, generates
revenue", forbids use in a production environment, and forbids publishing
benchmark results. It permits non-production use for "testing, teaching,
training and research/development".

Nothing it provides is linked into, distributed with, or depended on by the
library. It is fetched only when this directory's job runs.

**If you are working from a fork, this applies to you and not to us.** The
licence question is about who is running the crate and why, so a downstream
running this job is making its own decision rather than inheriting one. Anyone
who would rather not: delete this directory. The `interop` gate job in
`.github/workflows/interop.yml` lists `rust-master` in its `needs`, so remove
it there as well and the remaining peers -- the C++ master and the two
independent dissectors -- carry on unchanged.

The reading recorded in `Cargo.toml` is a judgment about this repository's use
and is not legal advice.
