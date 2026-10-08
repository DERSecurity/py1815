# The interoperability Rust outstation

An outstation built on a DNP3 stack this project did not write. It is used only
in continuous integration, where this library's master reads and commands it.

The master is also tested against this library's own outstation, but the two
share their protocol code, so they would agree with each other even if both
read the standard wrongly. This outstation shares no code with the master.

It serves a fixed set of points and prints every control and time write it
receives. `interop/master_check.py` checks what the master decoded against the
points, and what this outstation printed against what the master sent.
`interop/opendnp3_outstation.py` serves the same points on a second
independent stack.

## The crate, and the terms it is used on

The outstation is built on [`dnp3`](https://github.com/stepfunc/dnp3),
published by [Step Function I/O](https://stepfunc.io). The same crate provides
the Rust master in `interop/rust-master`, which reads this library's
outstation.

It is used under Step Function I/O's public license, which is not an
open-source license. Read it instead of a summary of it:

<https://github.com/stepfunc/dnp3/blob/main/LICENSE.txt>

Step Function I/O has said that using the crate for testing and
interoperability of py1815 in its public CI is in line with that license
([#48](https://github.com/DERSecurity/py1815/issues/48)).

Nothing the crate provides is linked into, distributed with, or depended on by
the library. It is fetched only when this directory's job runs.

**If you are working from a fork, that statement is about this repository and
not about yours.** A downstream running this job should read the license for
its own use. Commercial licensing is available from Step Function I/O at
<https://stepfunc.io/contact>. To stop using it, delete this directory, and in
`.github/workflows/interop.yml` delete the `rust-outstation` job and remove it
from the `needs` of the `interop` job.

## Running it

From the repository root:

```bash
(cd interop/rust-outstation && cargo build --locked)
interop/rust-outstation/target/debug/interop-rust-outstation 127.0.0.1:20000 > outstation.log &
python interop/master_check.py --port 20000 --log outstation.log
```
