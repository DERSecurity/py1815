# DER profile

The IEEE 1815.2 point map, and the builder that turns a map and a binding
into an outstation. [Serving a DER](../der.md) is the guide; this is the
reference.

## Map

::: py1815.profile.model

::: py1815.profile.load

## Binding

::: py1815.profile.binding

## Event policy

Which points report events, in which class, and past what deadband: data a
deployment hands to the builder as `event_policy`. The guide's
[Setting the event policy](../der.md#setting-the-event-policy) has an example
and the order in which a point's own rule, its kind's rule and the tables are
consulted.

::: py1815.profile.policy

## Outstation

::: py1815.profile.outstation

## Curves

::: py1815.profile.curves

## Device Profile

::: py1815.profile.device_profile

## Simulated DER

::: py1815.profile.der

## Probe

::: py1815.profile.probe
