# Security Policy

## Reporting a vulnerability

Please report vulnerabilities privately rather than in a public issue.

Use GitHub's [private vulnerability
reporting](https://github.com/DERSecurity/py1815/security/advisories/new)
on this repository. It goes to the maintainers and stays private until an
advisory is published.

Please include what you have: affected version, what an attacker can do, and a
reproduction if you have one. You will get an acknowledgment within a few
working days.

## What is in scope

This is an outstation -- the side a SCADA master connects *to* -- so everything
it accepts from the network is untrusted input.

**Some of that input now changes state.** Until controls existed the worst a
request could do was crash the process, hang it, or make it answer wrongly.
A control moves equipment. A defect that lets an unauthorized peer operate a
point, or lets one point's command reach another, is a different category of
finding from the parsing bugs below, and reports of that kind are the ones most
worth sending.

How much of it is reachable before authentication depends on the listener. Given
a TLS context, the standard library validates the client certificate and
`server.authorize` matches it against the allow-list before the connection is
admitted and before a single DNP3 octet reaches the session, so the parsers below
run only for a peer already accepted. Given none, there is no authentication at
all and every parser is exposed to anyone able to open a socket. Both are
supported deployments and both are in scope; please say which one you tested.

- Data link parsing in `link`: FT3 framing, the control byte, addresses, and
  the CRC over each block.
- Transport reassembly in `transport`: segment ordering, duplicate and missing
  segments, and the memory a partial fragment holds while it waits for the rest.
- Application parsing in `application`: function codes, the control octet,
  object headers, and the qualifier and range fields that decide how much a
  single request asks the outstation to allocate or emit.
- Object decoding in `objects`, including index ranges that do not correspond
  to points the caller configured.
- Control decoding in `control`, and the interleaved index-and-object walk in
  `application.parse_object_blocks` that feeds it. A control request carries its
  objects, so this is the one parser whose input a master chooses the length and
  count of.
- The select state machine in `session`: that an operate cannot spend a select
  it does not match, that an expired one cannot be spent at all, and that a
  select granted over one connection cannot be operated over the next.
- The boundary a control crosses into the caller's `ControlProvider`: the index,
  the decoded object and the function are what it receives, and a defect that
  hands it a different point from the one the master named is a control applied
  to the wrong equipment.
- TLS: certificate verification, and the peer allow-list in
  `server.authorize` that decides which certificate identities may connect.
- Association handling in `server`: in particular that an unauthorized peer
  cannot displace an established master, and that a connection which fails
  authorization changes nothing about the association already in progress.
- Resource exhaustion reachable from a single connection, against the limit each
  resource actually carries: event buffers bounded by their configured capacity,
  which survive a reconnect by design because a returning master expects the
  events it has not read; fragment reassembly bounded by its own `max_fragment`
  ceiling; and the idle timeout, which closes a connection that has stopped
  making progress rather than bounding either of the above.

A crash, a hang, an unbounded allocation, or a response built from one
association leaking into another are all in scope, whether or not the input is
valid DNP3.

## What is not a finding

Two properties are deliberate and documented rather than defects:

- **Plaintext operation.** `ssl_context` is optional, and DNP3 over plain TCP is
  ordinary on the isolated OT networks this is built for. A report that traffic
  is unencrypted when TLS was not configured is not a finding. A report that TLS
  is *not* applied when it was configured, or that the peer allow-list admits an
  identity it should refuse, very much is.

  Worth stating plainly now that controls exist: on a plaintext listener there is
  no authentication, so anyone who can open the socket can command the equipment.
  That is a deployment decision rather than a defect in this library, and it is
  the reason an outstation reachable from anywhere it should not be belongs
  behind TLS with an allow-list.
- **Accepting a control from an authorized master.** Operating a point a
  provider says it owns is what this is for. A finding is a control that reaches
  a provider it should not have, or reaches it naming something other than what
  the master sent.
- **No DNP3 Secure Authentication.** SAv5 is not implemented. Its absence is a
  missing feature rather than a vulnerability, and requests for it belong in an
  issue.

## Supported versions

| Version | Supported |
|---|---|
| `main` | yes |
| anything else | no -- this library has not had a release yet |

There is no published release: the version is `0.1.0.dev0` and nothing has been
uploaded to PyPI. Fixes land on `main`, and until the first release there is
nothing to backport to. Reports against a commit rather than a version are
expected and welcome; please name the commit.
