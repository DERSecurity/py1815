# The interoperability Rust outstation

An outstation built on a DNP3 stack this project did not write. It is used only
in continuous integration, where this library's master reads and commands it.

The master is also tested against this library's own outstation, but the two
share their protocol code, so they would agree with each other even if both
read the standard wrongly. This outstation shares no code with the master.

It serves a fixed set of points and prints every control, counter freeze and
time write it receives. `interop/master_check.py` checks what the master
decoded against the points, and what this outstation printed against what the
master sent. `interop/opendnp3_outstation.py` serves the same points on a
second independent stack.

Two things are tested against this outstation only, because opendnp3 and its
Python bindings do not offer them: counter freezes that are carried out, and
TLS. Given an authority, a certificate, a key and the master's name, it listens
with TLS and accepts only a master whose certificate the authority signed and
that carries that name.

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

Over TLS, with certificates made for the run in a directory outside the
checkout. The outstation is started again because the checks change its
points:

```bash
certs=$(mktemp -d)
interop/make_certificates.sh "$certs"
interop/rust-outstation/target/debug/interop-rust-outstation 127.0.0.1:20001 \
    "$certs/authority.pem" "$certs/outstation.pem" "$certs/outstation.key" master.test \
    > outstation-tls.log &
python interop/master_check.py --port 20001 --log outstation-tls.log \
    --tls-ca "$certs/authority.pem" --tls-certificate "$certs/master.pem" \
    --tls-key "$certs/master.key" --tls-server-name outstation.test
```
