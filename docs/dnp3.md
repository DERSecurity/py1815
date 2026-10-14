# How DNP3 works

A working introduction to the protocol this library implements, for someone who
has to read a frame or decide what an outstation should do, rather than a
restatement of the standard. Where this page and IEEE 1815 disagree, the
standard is right.

## What it is

DNP3 moves telemetry and control between a control center and field equipment.
It was designed for electric utilities communicating over slow, noisy serial
links, and nearly every decision in it follows from that: checksums on every few
octets, a transport layer whose whole job is to cut a message into pieces that
fit a frame, and a data model that lets a master ask "what changed" rather than
re-read everything.

It was later carried over TCP, on the port IANA assigns it, 20000, without
changing any of that framing. A DNP3 conversation over a modern network is still
shaped by the radio link it was designed for.

Standardized as IEEE 1815.

## Two roles

A **master** asks; an **outstation** answers. The master polls on a schedule and
issues controls. The outstation holds the data for one device and replies.

The asymmetry is worth holding on to, because it is not a peer protocol: an
outstation never initiates a request. It can push an **unsolicited response**
when something changes, but only if the master has enabled them, and that is a
report rather than a question.

This library implements the outstation side.

## Three layers

| Layer | What it carries | Bound |
|---|---|---|
| Data link | One frame: addresses and a checksummed payload | 292 octets |
| Transport | One octet, cutting a fragment into frames | 249 octets of payload per frame |
| Application | One fragment: a function code and objects | 2048 octets, by convention |

### Data link

A frame starts with the two octets `0x05 0x64`, then a length, a control octet,
a 16-bit destination and a 16-bit source address. A CRC-16/DNP covers that
header, and another covers **every 16 octets of user data**. A 292-octet frame
carries 32 octets of checksum.

That density is the serial heritage. It means a corrupted frame is usually
rejected within a few octets of the corruption rather than at the end.

The control octet carries the direction, whether this frame is primary (it
starts a link transaction) or secondary (it answers one), and a link function:
reset the link, request its status, or carry user data with or without
confirmation.

| Code | Primary, which starts a transaction | Secondary, which answers one |
|---|---|---|
| 0 | `RESET_LINK_STATES` | `ACK` |
| 1 | | `NACK` |
| 2 | `TEST_LINK_STATES` | |
| 3 | `CONFIRMED_USER_DATA` | |
| 4 | `UNCONFIRMED_USER_DATA` | |
| 9 | `REQUEST_LINK_STATUS` | |
| 11 | | `LINK_STATUS` |
| 15 | | `NOT_SUPPORTED` |

The same four bits mean different things in the two directions, so a decoder
reads the primary bit before it reads the function. This library's master sends
`UNCONFIRMED_USER_DATA` and leaves delivery to TCP, and its outstation accepts
user data sent either way.

Addresses are 16-bit and little endian. Anything at or above `0xFFF0` is
reserved, leaving `0` through `0xFFEF` for stations, and three of the reserved
values are broadcasts: `0xFFFD` wants no confirmation, `0xFFFE` requires one,
and `0xFFFF` leaves it optional. A frame that arrives on one of those is what
sets the broadcast indication below.

!!! note "The link address is not authorization"
    Source and destination are 16-bit integers chosen by whoever is sending.
    They identify a conversation; they do not establish who is on the other end.
    That distinction is the reason this library's TLS listener requires an
    explicit allow-list ([D8](DESIGN.md)).

### Transport

A single octet: FIN, FIR, and a six-bit sequence number. Its entire job is to
split an application fragment across as many link frames as it needs and
reassemble it on the other side.

!!! warning "FIR and FIN swap places"
    The transport octet is FIN `0x80`, FIR `0x40`. The application control octet
    is FIR `0x80`, FIN `0x40`. The two layers assign them to opposite bits.

    This is the kind of detail an implementation can get wrong consistently on
    both sides and never notice, which is why this library pins both to literal
    octets rather than to round trips.

### Application

A fragment begins with a control octet carrying FIR, FIN, CON (a confirmation is
requested) and UNS (this is unsolicited), plus a four-bit sequence. Then a
function code. Then, on a response, the two **internal indication** octets. Then
object headers and their data.

### A frame, octet by octet

An integrity poll, master 1 to outstation 10. Twenty-seven octets, one data
block:

```text
05 64 14 C4 0A 00 01 00 8F ED   header, and its checksum
C1                              transport: FIR, FIN, sequence 1
C1 01                           application: FIR, FIN, sequence 1; READ
3C 02 06                        group 60 variation 2, all objects: class 1
3C 03 06                        class 2
3C 04 06                        class 3
3C 01 06                        class 0
62 01                           checksum over the fifteen octets above
```

The header is the fixed part:

| Octets | Field | |
|---|---|---|
| `05 64` | Start | what to search a capture for |
| `14` | Length | 20: the control octet, four address octets, fifteen of user data |
| `C4` | Control | from the master, primary, `UNCONFIRMED_USER_DATA` |
| `0A 00` | Destination | 10 |
| `01 00` | Source | 1 |
| `8F ED` | Checksum | over the eight octets above, low octet first |

The length counts neither the start octets, nor itself, nor any checksum,
which is how a 27-octet frame comes to declare 20. `frame_size()` in
[Protocol layers](reference/protocol.md) does the same arithmetic the other
way round.

Four object headers, three octets each, ask for the four classes. The event
classes come first and class 0 last, so that a change held in a buffer is never
applied over a newer static value. That is an integrity poll, and the rest of
this page is mostly an explanation of those twelve octets.

## Internal indications

Two octets on every response. DNP3 has no separate status channel, so this is
how a master learns anything about the outstation that it did not specifically
ask about.

The first octet is the **state of the device**, true regardless of the request:

| Bit | Meaning |
|---|---|
| `0x01` | the request arrived as a broadcast |
| `0x02` `0x04` `0x08` | class 1, 2 or 3 events are waiting |
| `0x10` | the clock needs setting |
| `0x20` | a point is in local control |
| `0x40` | device trouble |
| `0x80` | the device restarted and the master has not cleared it |

The second octet is **what went wrong with this request**:

| Bit | Meaning |
|---|---|
| `0x01` | function not supported |
| `0x02` | object unknown |
| `0x04` | parameter error, including a fragment that did not parse |
| `0x08` | events were lost to a full buffer |
| `0x10` | already executing |
| `0x20` | configuration corrupt |

The restart bit is the one a master clears by writing to it, which is why an
otherwise read-only outstation still honors one write.

## The data model

Every value is identified by a **group** and a **variation**, and addressed by a
**qualifier**.

**Group** is what kind of point it is.

| Group | Contents |
|---|---|
| 1, 2 | Binary input, static and event |
| 12 | Control relay output block |
| 20, 22 | Counter, static and event |
| 30, 32 | Analog input, static and event |
| 40, 41 | Analog output status, and the output itself |
| 50, 51, 52 | Time |
| 60 | Class objects, which is how a master asks for "everything" |
| 80 | Internal indications, addressable as data |
| 120 | Secure authentication |

**Variation** is how the value is encoded: 32-bit or 16-bit, integer or float,
with or without a quality flag, with or without a timestamp. Group 30 variation
1 is a 32-bit analog input with flags; variation 5 is the same measurement as a
single-precision float.

A master and an outstation must agree on variations, and that agreement is a
document rather than a negotiation. This is what a **device profile** is for.

**Qualifier** says how the objects that follow are addressed. The two shapes
that matter:

- A **range**: a start and a stop index, for contiguous static data. "Indices 0
  through 4" costs four octets regardless of how many points that is.
- A **count with an index prefix** on each object, for events. Events are
  whichever points happened to change, so they are not a range, the same index
  can appear twice, and the points between two events need not have moved.

| Qualifier | What follows it | Where it is used |
|---|---|---|
| `0x00` | an 8-bit start and stop index | contiguous static data |
| `0x01` | a 16-bit start and stop index | the same, past index 255 |
| `0x06` | nothing at all | every object in the group; what a class read sends |
| `0x07` | an 8-bit count | a count of objects with no indices |
| `0x08` | a 16-bit count | the same, where the count runs past 255 |
| `0x17` | an 8-bit count, then an 8-bit index on each object | events, and controls |
| `0x28` | a 16-bit count, then a 16-bit index on each object | the same, past index 255 |

The octet is two fields: the low nibble says what the range looks like, and
bits 4 to 6 say what prefixes each object, an index or a size, and how wide
that prefix is. `0x06` is the one
to memorize. It is what makes a class read three octets long, and therefore
cheap enough to send every second.

## Static data and events

This is the central idea, and the one most worth getting right.

**Static** data is what a point reads *now*. **Event** data is the record that
it *changed*, carrying the value it held at the time, buffered until a master
reads it.

A master that only ever read static data would see a sampled signal and miss
everything between samples. A breaker that opened and reclosed between two polls
did not happen, as far as static data is concerned.

Events are assigned to **classes 1, 2 and 3**. These are reporting priorities
rather than data types: a class is a statement about how urgently something
should be reported, and a master asking for class 1 wants everything assigned to
class 1 whatever kind of point it came from. **Class 0** is the static data.

An **integrity poll** reads classes 1, 2, 3 and 0 in one request: give me
everything you have been holding, and then the current state of the world.

A **deadband** decides what counts as a change worth recording. Without one, a
noisy analog input generates an event per reading and fills the buffer with
noise nobody asked for. The deadband is the operator's statement of what
movement matters.

!!! note "Quality is not subject to the deadband"
    A point that goes comm-lost while holding the same number has not moved and
    has changed in the way that matters most. A deadband applied to quality
    would hide exactly the transitions someone is watching for.

Quality travels *with* each value, in a flags octet: online, restart, comm-lost,
remote or local forced, over-range, reference error. A consumer has to be able
to tell a fresh reading from a retained one, and arrival time cannot tell it.

| Bit | Binary input | Analog input |
|---|---|---|
| `0x01` | online | online |
| `0x02` | restart | restart |
| `0x04` | comm-lost | comm-lost |
| `0x08` | remote forced | remote forced |
| `0x10` | local forced | local forced |
| `0x20` | chatter filter | over-range |
| `0x40` | | reference error |
| `0x80` | the state itself | |

The low five bits mean the same thing in both, which is what lets a consumer
decide whether a value can be trusted without knowing what kind of point it
came from. Above them the two diverge, and on a binary input the top bit is
the value itself, so a binary input whose flags octet is zero reads as an
offline false rather than as a missing reading.

## Function codes

| Code | Name | |
|---|---|---|
| 0 | Confirm | acknowledges a fragment; not a request |
| 1 | Read | |
| 2 | Write | |
| 3, 4 | Select, Operate | the two halves of the control interlock |
| 5 | Direct Operate | skips the interlock |
| 6 | Direct Operate, No Acknowledgment | and asks for no reply |
| 7 to 12 | Freeze variants | three of them ask for no reply |
| 13, 14 | Cold and Warm Restart | |
| 20, 21 | Enable and Disable Unsolicited | |
| 23, 24 | Delay Measurement, Record Current Time | clock synchronization |
| 129, 130 | Response, Unsolicited Response | |

### Select before operate

Controls have a safety interlock. `SELECT` arms a point, and the outstation
**echoes back what it understood**. `OPERATE` then executes it only if the two
match. A master that meant to open one breaker and misaddressed the request
finds out before anything moves.

| Direction | Message |
|---|---|
| master -> outstation | `SELECT`, group 12 variation 1, index 3, latch on |
| outstation -> master | the block echoed back, carrying a status |
| master -> outstation | `OPERATE`, the identical block |
| outstation -> master | the block again, carrying the status of the operation |

Both replies carry a status. The one on the select is what tells the master
whether to go on to the operate.

`DIRECT_OPERATE` skips the interlock for cases where the round trip costs more
than the mistake would.

### The control block

A control is group 12 variation 1, eleven octets:

| Octets | Field | |
|---|---|---|
| 1 | Control code | what to do |
| 1 | Count | how many times to do it |
| 4 | On-time | milliseconds, for a pulse |
| 4 | Off-time | milliseconds, for a pulse |
| 1 | Status | zero in a request, the outcome in the reply |

The control code is the octet to read carefully. Its low nibble is the
operation: `1` pulse on, `2` pulse off, `3` latch on, `4` latch off. Its top
two bits are the trip-close code, `1` close and `2` trip, which is how a
single point operates equipment with a pair of coils. Between them sit two
more bits. The queue bit is obsolete in IEEE 1815-2012 and required to be zero,
and a master that sets it is asking for behavior the standard withdrew. The
clear bit is not obsolete: this library builds it and reads it back.

A direct operate of latch-on against point 3. Thirty-three octets, and this
one needs two data blocks:

```text
05 64 18 C4 0A 00 01 00 3D 3A   header, and its checksum
C2                              transport: FIR, FIN, sequence 2
C2 05                           application: sequence 2; DIRECT_OPERATE
0C 01 17                        group 12 variation 1, count and 8-bit indices
01                              one control follows
03                              index 3
03                              control code: latch on, no trip-close
01                              count: once
00 00 00 00                     on-time, which a latch ignores
00 00                           off-time, first half
CE 33                           checksum: sixteen octets of user data end here
00 00                           off-time, continued
00                              status
FF FF                           checksum over the three octets above
```

!!! warning "A data block ends where it ends"
    The checksum lands in the middle of the off-time field, because a block is
    sixteen octets wherever that falls and knows nothing about the structure
    above it. A parser that reads fields as it strips checksums, rather than
    reassembling the user data first and parsing it afterwards, works on every
    short frame and then fails on this one.

The last checksum is `FF FF` because the three octets it covers are all zero
and CRC-16/DNP complements its result. It is correct, and it looks exactly
like a placeholder.

### The functions that expect no reply

Five function codes carry a "no acknowledgment" meaning, and IEEE 1815-2012
Table 4-2 describes each as *"same as function code N but outstation shall not
send a response"*: `0x06`, `0x08`, `0x0A`, `0x0C` and `0x21`.

The obligation is on the function code rather than on whether the outstation
implements what was asked. An outstation that refuses one of these out loud is
sending a fragment to a master that is not listening for it, and that is true
even when the refusal is correct and even when the request did not parse.

## What a session looks like

An outstation has restarted and a master reconnects:

| Direction | Message |
|---|---|
| master -> outstation | read classes 1, 2, 3 and 0 |
| outstation -> master | the data, with the restart indication set |
| master -> outstation | write zero to that indication bit |
| master -> outstation | write the time, if the outstation asked for it |
| master -> outstation | read classes 1, 2, 3 and 0 again |

IEEE 1815-2012 5.1.1.1.2, rule 2, gives the order: clear the restart
indication, then the optional steps with time synchronization among them, then
the integrity poll. A master learns of the restart only from a response, so a
poll comes first in practice and comes again once the indication is cleared.

Every step answers something the outstation said rather than something the
master assumed. The restart bit is why the write happens, the clock bit is why
the time follows, and an outstation that never asks for either is one the
master leaves alone.

A master configured to use unsolicited reporting also asks the outstation to
enable it (5.1.1.2, and the same rule). That is not a step every master takes,
and an outstation built without unsolicited responses, which is this library's
default, refuses the request.

After that the traffic settles into a repetition: event reads at whatever
interval the deployment asks for, an integrity poll less often to repair
anything the event path lost, and unsolicited responses in between where they
are enabled. This library's master sends nothing on a schedule unless it is
told to.

## Security

DNP3 originally had none, which is why the protocol identifies but does not
authenticate.

**TLS** is the usual answer over TCP. **DNP3 Secure Authentication** adds
challenge-response at the application layer using group 120 objects, so that a
critical request can be proven to come from who it claims to.

Neither is a substitute for deciding *which* peers may connect at all.

## Conformance

Interoperability is graded in **subset levels 1 through 4**, level 1 being the
minimum a device can implement and still be called DNP3. Higher levels add
object groups, qualifiers and functions.

**IEEE 1815.2** is the DER profile built on top, assigning specific indices to
specific measurements for distributed energy resources. It is the target this
library is built toward, and where it and Level 2 disagree, this library follows
the profile and names the divergence.

## Where to go next

- [Design decisions](DESIGN.md), for why this library is shaped the way it is.
- [Serving an outstation](outstation.md), to put the above to work.
- [Testing](testing.md), for how the wire behavior above is held to.
