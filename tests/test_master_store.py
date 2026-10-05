"""What a master keeps of what it was told."""

from __future__ import annotations

from py1815.decode import PointType, decode_objects
from py1815.master import Store

TIME_OCTETS = "00 E4 0B 54 02 00"


def _objects(octets: str):
    decoded = decode_objects(bytes.fromhex(octets))
    assert decoded.complete, decoded.problem
    return decoded.objects


class TestTheLastValue:
    def test_a_static_value_is_kept_with_what_came_with_it(self):
        store = Store()
        store.apply(_objects("1E 02 00 04 04  01 2C 01"), now=12.5)

        value = store.analog_input(4)
        assert (value.value, value.flags, value.time_ms) == (300, 0x01, None)
        assert (value.group, value.variation) == (30, 2)
        assert not value.from_event and value.received == 12.5

    def test_a_point_never_reported_is_none_and_not_zero(self):
        store = Store()
        assert store.analog_input(4) is None
        assert store.points(PointType.ANALOG_INPUT) == {}
        assert len(store) == 0

    def test_each_point_type_is_kept_apart_under_its_own_index(self):
        store = Store()
        store.apply(
            _objects(
                "01 02 00 07 07 81"
                "  0A 02 00 07 07 01"
                "  14 01 00 07 07 01 0A 00 00 00"
                "  15 09 00 07 07 0B 00 00 00"
                "  1E 02 00 07 07 01 0C 00"
                "  28 02 00 07 07 01 0D 00"
            ),
            now=0.0,
        )
        assert store.binary_input(7).value is True
        assert store.binary_output(7).value is False
        assert store.counter(7).value == 10
        assert store.frozen_counter(7).value == 11
        assert store.analog_input(7).value == 12
        assert store.analog_output(7).value == 13
        assert len(store) == 6

    def test_a_variation_with_no_flags_is_stored_as_having_none(self):
        store = Store()
        store.apply(_objects("1E 04 00 00 00  2C 01"), now=0.0)
        assert store.analog_input(0).flags is None

    def test_what_arrives_later_replaces_what_arrived_earlier(self):
        store = Store()
        store.apply(_objects("1E 02 00 00 00  01 2C 01"), now=1.0)
        store.apply(_objects("1E 02 00 00 00  01 2D 01"), now=2.0)
        assert (store.analog_input(0).value, store.analog_input(0).received) == (301, 2.0)

    def test_within_one_response_the_order_sent_is_the_order_applied(self):
        """An integrity poll sends events before static data, so the static value stands."""
        store = Store()
        store.apply(_objects("20 02 17 01 00  01 05 00   1E 02 00 00 00  01 2C 01"), now=0.0)
        assert store.analog_input(0).value == 300
        assert not store.analog_input(0).from_event

    def test_points_of_a_type_come_back_in_index_order(self):
        store = Store()
        store.apply(_objects("1E 02 00 09 09  01 01 00   1E 02 00 02 02  01 02 00"), now=0.0)
        assert list(store.points(PointType.ANALOG_INPUT)) == [2, 9]

    def test_an_object_that_is_not_a_points_value_is_not_stored(self):
        store = Store()
        store.apply(_objects(f"32 01 07 01 {TIME_OCTETS}   34 02 07 01 F4 01"), now=0.0)
        assert len(store) == 0 and store.events == ()


class TestEvents:
    def test_an_event_updates_its_point_and_is_kept_in_order(self):
        store = Store()
        events = _objects(f"20 04 17 02  03 01 05 00 {TIME_OCTETS}  04 01 06 00 {TIME_OCTETS}")
        store.apply(events, now=3.0)

        value = store.analog_input(3)
        assert (value.value, value.from_event, value.time_ms) == (5, True, 10_000_000_000)
        assert store.events == events

    def test_a_static_value_is_not_an_event(self):
        store = Store()
        store.apply(_objects("1E 02 00 00 01  01 2C 01  01 2D 01"), now=0.0)
        assert len(store) == 2
        assert store.events == ()

    def test_the_oldest_events_are_dropped_past_the_capacity(self):
        store = Store(event_capacity=2)
        store.apply(_objects("20 02 17 03  01 01 01 00  02 01 02 00  03 01 03 00"), now=0.0)
        assert [event.index for event in store.events] == [2, 3]
        assert len(store) == 3, "the points themselves are all kept"

    def test_the_events_can_be_cleared_without_losing_the_values(self):
        store = Store()
        store.apply(_objects("20 02 17 01  01 01 01 00"), now=0.0)
        store.clear_events()
        assert store.events == () and store.analog_input(1).value == 1
