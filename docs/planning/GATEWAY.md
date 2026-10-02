# Plan: an outstation embedded in a gateway

What the library owes a caller that runs the outstation inside a gateway, in front of a
unit it does not control directly and for a master it has not met. The other plans in this
directory each build one mechanism. This one is a list of what a first deployment of that
kind needs across all of them, kept as a checklist so it can be tracked here.

## The deployment

A gateway in front of one unit: one outstation, one DER behind it. The gateway reads the
unit through another protocol into its own point store and serves that store upstream over
more than one protocol at once. The DNP3 outstation, built with the IEEE 1815.2 profile in
[DER_PROFILE.md](DER_PROFILE.md), is one of those upstream interfaces, and in this
deployment it is the one a plant controller commands through. The gateway runs in a
container on a small ARM controller, beside the unit's own control software.

Five things about it shape the list:

- **Control is assigned, not assumed.** The gateway names one upstream interface as its
  control interface and serves the others read-only. Which one holds control is
  configuration, so this outstation has to run either way.
- **The gateway relays.** It passes commands down and reports what the unit applied. It
  holds no opinion about what the unit should do when a master goes quiet: the last
  commanded value holds, and the unit's own controller owns safety.
- **The master is not known in advance.** Whoever connects is the master.
- **What gets reported is the customer's choice.** Event classes and deadbands are
  configuration.
- **The point set grows.** The first delivery carries what the unit publishes today, and
  that set is expected to grow substantially.

None of these is peculiar to one deployment. Each is something any caller embedding the
outstation in a gateway would ask for.

## Scope

In scope: the items below. Each says what the deployment needs, what the library already
does toward it, and what is missing.

Not in scope, and recorded so it is not built for this:

- **Secure authentication.** The first release runs over plain TCP. TLS is already in the
  listener for a deployment that wants it later, and secure authentication stays out of
  scope as [DER_PROFILE.md](DER_PROFILE.md) states it.
- **The fleet layout.** One unit needs no strided blocks.
- **Anything the gateway does with its other upstream interfaces.** Serving the same
  point store over a second protocol at the same time is the gateway's business. The
  library's part is that the outstation reads through bindings and owns no copy of the
  data, so a second reader costs it nothing.

## The list

Tick an item when the missing part is merged and tested. G1, G2, G5, G6 and G10 land in
`py1815.profile` and are tracked in [DER_PROFILE.md](DER_PROFILE.md), where the builder's
plan is; they are summarized here and ticked there. The others are tracked here.

**In the profile builder** (see [DER_PROFILE.md](DER_PROFILE.md#needs-from-a-single-unit-gateway)):

- **G1.** Either role, chosen by the caller: commanding or read-only, with a read-only
  outstation refusing every control and still reporting the value in force.
- **G2.** In the commanding role, the outstation reports what the unit applied, which may
  differ from what the master asked for.
- **G5.** Event class and deadband set by the deployment, as data, per point. Built.
- **G6.** A partial map that grows, with a report of what is bound against the profile.
- **G10.** Static groups read by index, for a master that picks scattered points. Built.

**In the outstation and the project:**

- [ ] **G3. Nothing happens when the master goes quiet.** The outstation must hold no
  timeout that changes an output and apply no fallback when requests stop. Today it has
  none: nothing in the session or the builder changes an output because time has passed,
  and the profile builder passes the profile's timing parameters through as point values
  for the DER to honor. *Missing:* a
  test that pins it, so later work cannot introduce a path from "no request for a while"
  to "an output changed". Unsolicited responses bring the library's first timer, and that
  timer retries a report; it must never touch an output.
- [ ] **G4. A master that is not known in advance.** `Session` serves one configured
  `master_address` and drops frames from any other source, for a stated reason: answering
  an unexpected address would interleave two conversations over one set of sequence
  numbers. This deployment cannot name its master. *Missing:* an option to accept any
  source address and reply to the address that asked, with the rule for a second address
  arriving mid-conversation stated and tested. One association still owns one set of
  sequence numbers, one pending confirmation and one select awaiting its operate, so a
  new address must either be refused while another is active or reset that state, and it
  must never interleave. The device profile document's master address entry has to say
  which. Accepting any address is not authorization, and without transport security it
  means any peer that can reach the port can command; the option's documentation should
  say so plainly.
- [ ] **G7. Unsolicited responses, when a master asks.** An unknown master may send
  `ENABLE_UNSOLICITED`. It is refused today, which stays the honest answer until the
  roadmap entry in [DESIGN.md](../DESIGN.md) lands. *Missing:* that entry, which this
  deployment is the first consumer waiting on. Until a master enables them the outstation
  sends none, which is also the right default for a master nobody has identified: there
  is no known address to send to.
- [ ] **G8. Small ARM controllers.** The gateway runs in a container on 32-bit and 64-bit
  ARM Linux controllers with little memory. No runtime dependencies and pure Python
  already make that possible. *Missing:* the test suite run on a 32-bit target at least
  once and then in CI, since nothing here has been exercised where a native integer is
  32 bits; and a stated memory cost for the event buffers at their default capacity, with
  guidance for sizing them down.
- [ ] **G9. A release the gateway can pin.** With G1 through G5 in it. The API is not
  stable below `1.0`, so the gateway pins an exact version, and the release notes say
  which of these items it carries.

## Sequencing

G4 first, because without it no master connects at all. Then G1 and G2 together, which
are the two roles, with G3's test beside them. Then G5 and G6, which is where the
deployment's configuration and its growth live. G8 can run at any point and is best done
early, since a 32-bit surprise is cheaper to find before the release than after. G9
closes. G7 follows the roadmap and is not gated on the rest.

## Open

- **The status a read-only outstation refuses a control with** (G1). It has to tell a
  master "not through this interface" and not "this point cannot be controlled".
- **A second master address while one is active** (G4): refuse it, or let it displace the
  first. Displacing is friendlier to a master that restarted with a different address;
  refusing is safer when two masters are both alive.
- **Whether the event policy file is the library's format or the caller's** (G5).
  Settled: the caller's. The library takes the policy as a mapping it validates and
  reads no file, so the gateway keeps the policy in its own configuration and hands
  over what that loads to (D66 in [DESIGN.md](../DESIGN.md)).

## References

- [DER_PROFILE.md](DER_PROFILE.md), for the builder and items G1, G2, G5, G6 and G10
- [EVENTS.md](EVENTS.md) and [CONTROLS.md](CONTROLS.md), whose mechanisms G2, G3 and G5
  build on
- [DESIGN.md](../DESIGN.md): the decision on one master association per session, the
  decision that refusals are made out loud, and the roadmap entry for unsolicited
  responses
