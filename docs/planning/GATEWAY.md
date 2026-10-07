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
  Built.
- **G10.** Static groups read by index, for a master that picks scattered points. Built.

**In the outstation and the project:**

- [x] **G3. Nothing happens when the master goes quiet.** The outstation must hold no
  timeout that changes an output and apply no fallback when requests stop. It has none:
  nothing in the session or the builder changes an output because time has passed, and the
  profile builder passes the profile's timing parameters through as point values for the
  DER to honor. *Built:* `tests/test_master_silence.py` pins it. Each test commands an
  output and then lets time pass with no request, in every way the library meets silence:
  the session's clock moving on, the caller's loop still polling and freezing, a select
  left to expire, and the listener closing a connection it has heard nothing on. The
  binding has been called once and the output stands where the master left it.
  Unsolicited responses brought the library's first timer, and that timer retries a
  report. These tests pass unchanged with it, and `tests/test_unsolicited_silence.py` runs
  their session tests again with unsolicited responses on and retrying, and counts the
  calls to a binding through hours of unconfirmed retries, over a session and over a
  listener: one each time.
- [x] **G4. A master that is not known in advance.** `Session` served one configured
  `master_address` and dropped frames from any other source, for a stated reason: answering
  an unexpected address would interleave two conversations over one set of sequence
  numbers. This deployment cannot name its master. *Built:* `Session(master_address=None)`
  serves whichever address speaks first on a connection and replies to it. A second
  address on the same connection is dropped, so nothing interleaves, and a new connection
  starts again, so a master that restarted under another address is served. The device
  profile document says source addresses are not validated and any address is expected.
  Accepting any address is not authorization, and the option's documentation says so:
  without transport security, any peer that can reach the port can command (D64 in
  [DESIGN.md](../DESIGN.md)).
- [x] **G7. Unsolicited responses, when a master asks.** *Built:* a session constructed
  with `unsolicited=True`, which the profile builder passes through, announces a restart
  with a null response and takes `ENABLE_UNSOLICITED` and `DISABLE_UNSOLICITED` by class.
  Events of an enabled class are sent in unsolicited responses, retired by their
  confirmation, and retried at a configurable timeout, a configurable number of times or
  without limit. A read is held while one waits, and nothing unsolicited is sent while a
  solicited response waits. The session gained `initiate()` and still does no I/O;
  `OutstationServer` drives it, and `notify()` reports a new event at once. Off by default,
  and off answers as before, refusing `ENABLE_UNSOLICITED`. D69 to D71 in
  [DESIGN.md](../DESIGN.md) and [UNSOLICITED.md](UNSOLICITED.md) record it. The
  destination is asked of one helper, which names the master being served and says nowhere
  when there is none. A session that takes any master (G4) reports to the master that
  spoke first on the connection, sends nothing before one has, and disables every class
  when a different master takes the next connection, so no master is sent what another
  enabled (D72).
- [x] **G8. Small ARM controllers.** The gateway runs in a container on 32-bit and 64-bit
  ARM Linux controllers with little memory. No runtime dependencies and pure Python
  already make that possible. *Built:* the `test-arm32` job runs the whole unit suite on
  Python 3.12 for `linux/arm/v7` under emulation on every pull request, and `image-arm`
  builds the Docker image for `linux/arm64` and `linux/arm/v7`. The first 32-bit run
  passed every test and found nothing to fix: the encoders name their byte order and
  widths, and a time is a Python integer that never passes through a native one. The
  memory a full event buffer costs is measured by `scripts/measure_event_memory.py` and
  stated, with how to size `event_capacity` down, in
  [Serving a DER](../der.md#memory-on-a-small-controller).
- [x] **G9. A release the gateway can pin.** With G1 through G5 in it. The API is not
  stable below `1.0`, so the gateway pins an exact version, and the release notes say
  which of these items it carries. *Built:* `0.2.0` carries G1 through G8 and G10. Its
  section of the [changelog](https://github.com/DERSecurity/py1815/blob/main/CHANGELOG.md)
  has an entry for each under the pull request that built it: G1 and G2 (#64), G3 (#66,
  tests only, so it has no entry), G4 (#61), G5 (#65), G6 (#63), G7 (#67 and #68), G8
  (#62) and G10 (#59).

## Sequencing

G4 first, because without it no master connects at all. Then G1 and G2 together, which
are the two roles, with G3's test beside them. Then G5 and G6, which is where the
deployment's configuration and its growth live. G8 can run at any point and is best done
early, since a 32-bit surprise is cheaper to find before the release than after. G9
closes. G7 follows the roadmap and is not gated on the rest.

## Open

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
