# The interoperability Rust master

A second DNP3 master, in a second language, used only to read this library's
outstation in continuous integration.

It exists because the other master this repository drives is built on opendnp3,
a C++ stack, and two interfaces over one core is one implementation rather than
two. It also checks something that one structurally cannot: opendnp3's Python
bindings store point values as bare scalars and discard the quality octet, so
that job verifies values and not flags. This stack hands the flags to its read
handler, so the point the fixture serves offline is verified as offline.

## The crate, and the terms it is used on

The master is built on [`dnp3`](https://github.com/stepfunc/dnp3), published by
[Step Function I/O](https://stepfunc.io). It is the peer in this suite that
checks quality flags and refused controls, so a real share of what this
repository claims about interoperability is owed to it.

It is used under Step Function I/O's public license, which is not an
open-source license. Read it instead of a summary of it:

<https://github.com/stepfunc/dnp3/blob/main/LICENSE.txt>

Step Function I/O has said that using the crate for testing and
interoperability of py1815 in its public CI is in line with that license
([#48](https://github.com/DERSecurity/py1815/issues/48)). Before they said so, that was this repository's own reading.

Nothing the crate provides is linked into, distributed with, or depended on by
the library. It is fetched only when this directory's job runs.

**If you are working from a fork, that statement is about this repository and
not about yours.** The license question is about who is running the crate and
why, so a downstream running this job should read the license for its own use.
Commercial licensing is available from Step Function I/O at <https://stepfunc.io/contact>.
Anyone who would rather not run it: delete this directory. The `interop` gate
job in `.github/workflows/interop.yml` lists `rust-master` in its `needs`, so
remove it there as well and the remaining peers, the C++ master and the two
independent dissectors, carry on unchanged.
