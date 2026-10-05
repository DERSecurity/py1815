# Serving an outstation

!!! warning "Early development"
    The protocol layers, the listener, controls and the event path are
    implemented and tested: a master reads classes 1 to 3, confirms what it was
    sent, and is told through the indication bits what is still waiting. Not yet
    done are unsolicited responses, which is outstation-initiated traffic. An
    answer too large for one fragment is a conversation:
    the master confirms each fragment and the next follows. The first release is
    `0.1.0` and the API is not stable: while the major version is `0`, a minor
    bump may carry a breaking change.

## The shape of it

Three pieces fit together:

- A **read provider** you write, which turns a master's request into encoded
  objects. This is where your data comes from.
- A **`Session`**, which owns the protocol state of one master association and
  does no I/O at all: octets in, octets out.
- An **`OutstationServer`**, which owns the socket.

The session doing no I/O is deliberate. It means every protocol behavior on this
page can be tested against literal frames with no listener, no TLS and no event
loop.

## A minimal outstation

```python
import asyncio
from collections.abc import Sequence

from py1815.application import ObjectHeader
from py1815.objects import AnalogPoint, AnalogVariation, analog_flags, analog_range
from py1815.server import OutstationServer
from py1815.session import Session, UnknownObject

POINTS = [
    AnalogPoint(10),
    AnalogPoint(-20),
    AnalogPoint(30),
    # A point whose device has gone unreachable keeps its last value, with
    # ONLINE cleared and COMM_LOST set, rather than disappearing or reading
    # as zero.
    AnalogPoint(40, analog_flags(online=False, comm_lost=True)),
    AnalogPoint(50),
]


class Provider:
    """Answers reads for the groups this outstation serves."""

    def read(self, headers: Sequence[ObjectHeader]) -> bytes:
        unknown = sorted({header.group for header in headers} - {30, 60})
        if unknown:
            # Refused as an unknown object rather than an unsupported
            # function: READ is supported, and the master should learn which
            # of the two went wrong.
            raise UnknownObject(f"no group {unknown} here")
        return analog_range(0, POINTS, variation=AnalogVariation.INT32_WITH_FLAG)


async def main() -> None:
    session = Session(Provider(), outstation_address=1024, master_address=1)
    server = OutstationServer(session, bind="0.0.0.0:20000")
    await server.start()
    try:
        await asyncio.Event().wait()
    finally:
        await server.stop()


asyncio.run(main())
```

Point a master at port 20000 and it will read five analog inputs, one of them
marked comm-lost.

## Values arrive already scaled

The library encodes and decodes the wire format. It does not embed a point map
and it does not apply scaling: the number you hand it is the number that goes on
the wire.

That separation is deliberate. The IEEE 1815.2 tables assign specific indices to
specific measurements, and those tables are distributed to DNP Users Group
members rather than published, so a library that embedded them could not be
shared. See [D6](DESIGN.md).

## One connection is the master

A second authorized connection **displaces** the first rather than joining it.
Event buffers, confirmation state and unsolicited retry ownership belong to a
master association, not to a socket, and the usual cause of a second connection
is a master whose socket died without a FIN. Refusing it would leave the
outstation unreachable until a timeout it cannot observe.

The session survives the displacement. Its *framing* state does not: half a
frame belongs to the socket that carried it, and completing it with octets from
the next connection would splice two conversations into one request.

So a reconnecting master finds the restart indication it has not cleared, and
the events it has not read, exactly where it left them. See [D7](DESIGN.md).

## A master you cannot name in advance

A session serves one master address, and drops frames from any other:

```python
session = Session(Provider(), outstation_address=1024, master_address=1)
```

An outstation shipped to a site whose controller has not been chosen cannot be
configured that way. Pass `None` and the session serves whichever master
speaks first on a connection:

```python
session = Session(Provider(), outstation_address=1024, master_address=None)
```

Replies go to the address that asked. That address is the master for as long
as the connection lasts: a frame from a second address on the same connection
is dropped, because two masters would interleave over one set of sequence
numbers. A new connection starts again, so a master that comes back under a
different address is served. `session.master_address` says who is being served
now, and is `None` until someone has spoken.

!!! warning
    A link address is not authorization, and this makes that plain. With no
    transport security, any peer that can reach the listener can read from an
    outstation built this way, and command it if controls are bound. Restrict
    who can connect with the TLS allow-list below, or with the network.

See [D64](DESIGN.md).

## TLS

```python
import ssl

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain("outstation.pem", "outstation.key")
context.load_verify_locations("ca.pem")
context.verify_mode = ssl.CERT_REQUIRED

server = OutstationServer(
    session,
    bind="0.0.0.0:20000",
    ssl_context=context,
    authorized_peers=frozenset(
        {
            "master.example",
            "sha256:9a1f...",
        }
    ),
)
```

Three configurations are refused at construction rather than allowed to run
looking secure:

- **TLS without an allow-list.** Trusting a CA alone authenticates every
  certificate that CA ever issued.
- **TLS without `CERT_REQUIRED`.** There would be no client certificate, so
  nothing to check the allow-list against.
- **An allow-list without TLS.** A plaintext connection presents no
  certificate, so the list could not be applied, and a caller who passed one
  would believe they had restricted who may connect.

Entries match a certificate's common name, a DNS subject alternative name, or
its SHA-256 fingerprint with the `sha256:` prefix. Names compare
case-insensitively because DNS does; fingerprints compare exactly. There are no
wildcards, because an allow-list whose entries match things nobody enumerated is
not an allow-list.

Names and fingerprints are matched **only against their own kind**, so a
certificate whose common name is the literal text of a pinned fingerprint does
not satisfy it.

A peer outside the list is disconnected before any session state is touched.
That ordering is the substance rather than a detail: an admitted connection
displaces the active one, so a peer authorized too late would take the
association down on its way to being refused. See [D8](DESIGN.md).

## What it refuses

A function this outstation does not implement gets a response carrying
`FUNC_NOT_SUPPORTED` rather than silence, because a master that times out learns
nothing and retries. A control sent to an outstation with no outputs is answered
with `OBJECT_UNKNOWN`: the function is one it knows, and what is missing is
anything for it to act on.

A function can also be turned off: `Session(disabled_functions=[...])` refuses each
one named exactly as it refuses a function it never implemented, which is the safer
configuration for an outstation with no use for it.

Something that is not a request at all is not answered: a fragment too short to hold
a header, one marked as part of a longer message, a link frame whose length
contradicts its function.

The exceptions are the five function codes the standard defines as taking no
reply, which are dropped and logged rather than answered. See
[How DNP3 works](dnp3.md#the-functions-that-expect-no-reply) and
[D9](DESIGN.md).

The one write this outstation honors is a master clearing the restart
indication, at group 80 variation 1 index 7. An outstation that never cleared it
would flag every response it ever sent.
