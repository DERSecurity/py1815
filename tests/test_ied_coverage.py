"""Every section of the IED certification procedures, and what was done about it.

The conformance tests are named for the procedure sections they carry out.
This file is the other half of that: a catalog of the sections of the DNP
Users Group's *DNP3 IED Certification Procedure*, version 3.1 revision 1, each
either pointing at the tests that carry it out or saying why it does not apply
to this outstation. Two checks keep the catalog and the tests in step, so a
section cannot be claimed without a test and a test cannot claim a section
the catalog has not accounted for.

The procedures themselves are the Users Group's and are not reproduced here.
Section numbers are how this suite refers to them; the descriptions are ours.

The device is tested as a subset level 2 outstation over TCP.
"""

from __future__ import annotations

import ast
import pathlib

import pytest
from ied_harness import IIN2_BAD_FUNCTION, IIN2_OBJECT_UNKNOWN, Dut, header

_HERE = pathlib.Path(__file__).resolve().parent

#: A section that is carried out: the prefixes of the test names that do it.
Tested = tuple[str, ...]

#: Sections with a test. The prefix is what the test's name starts with, after
#: ``test_``.
TESTED: dict[str, Tested] = {
    # 6: data link layer
    "6.1.2 reset link and passive confirm": ("6_1_2_",),
    "6.3.2 request link status": ("6_3_2_",),
    "6.5.2 DIR and FCV bits": ("6_5_2_",),
    "6.6.2 invalid start octets": ("6_6_2_1_",),
    "6.6.2 invalid primary function code": ("6_6_2_2_",),
    "6.6.2 invalid destination address": ("6_6_2_3_",),
    "6.6.2 no inter-frame gap": ("6_6_2_4_",),
    "6.6.2 invalid CRC": ("6_6_2_5_",),
    "6.6.2 invalid FCV": ("6_6_2_6_",),
    "6.7.2 self-address, in the disabled state": ("6_7_2_",),
    # 7: transport layer
    "7.2 transport segmentation": ("7_2_",),
    # 8.1 to 8.4: outputs
    "8.1.2 binary output status": ("8_1_2_",),
    "8.2.1.1 select before operate, desired behavior": ("8_2_1_1_",),
    "8.2.1.2.1 SBO, 16-bit index": ("8_2_1_2_1_",),
    "8.2.1.2.2 SBO, 8-bit index": ("8_2_1_2_2_",),
    "8.2.1.2.3 SBO to an uninstalled point": ("8_2_1_2_3_",),
    "8.2.1.2.4 execute after timeout": ("8_2_1_2_4_",),
    "8.2.1.2.5 to 8.2.1.2.8 execute not matching select": ("8_2_1_2_5_to_8_",),
    "8.2.1.2.9 select and execute with different index sizes": ("8_2_1_2_9_",),
    "8.2.1.2.10 no binary outputs installed": ("8_2_1_2_10_",),
    "8.2.1.2.11 same sequence select retries": ("8_2_1_2_11_",),
    "8.2.1.2.12 incrementing sequence select retries": ("8_2_1_2_12_",),
    "8.2.1.2.13 same sequence operate retries": ("8_2_1_2_13_",),
    "8.2.1.2.14 incrementing sequence operate retries": ("8_2_1_2_14_",),
    "8.2.1.2.15 sequence number checking": ("8_2_1_2_15_",),
    "8.2.2.2.1 direct operate": ("8_2_2_2_1_",),
    "8.2.2.2.2 direct operate to an uninstalled point": ("8_2_2_2_2_",),
    "8.2.2.2.3 direct operate, no outputs installed": ("8_2_2_2_3_",),
    "8.2.3.2.1 direct operate, no acknowledge": ("8_2_3_2_1_",),
    "8.2.3.2.2 no acknowledge, uninstalled point": ("8_2_3_2_2_",),
    "8.2.3.2.3 no acknowledge, no outputs installed": ("8_2_3_2_3_",),
    "8.2.4.2 multiple control objects": ("8_2_4_2_",),
    "8.2.5.2.1 complementary control codes": ("8_2_5_2_1_",),
    "8.2.5.2.2 single function control codes": ("8_2_5_2_2_",),
    "8.2.6.2 no control when the status code is non-zero": ("8_2_6_2_",),
    "8.3.2 analog output status": ("8_3_2_",),
    "8.4.1.2.1 analog SBO, 16-bit index": ("8_4_1_2_1_",),
    "8.4.1.2.2 analog SBO, 8-bit index": ("8_4_1_2_2_",),
    "8.4.1.2.3 analog SBO to an uninstalled point": ("8_4_1_2_3_",),
    "8.4.1.2.4 analog execute after timeout": ("8_4_1_2_4_",),
    "8.4.1.2.5 analog execute with a different value": ("8_4_1_2_5_",),
    "8.4.1.2.6 analog select and execute with different index sizes": ("8_4_1_2_6_",),
    "8.4.1.2.7 no analog outputs installed": ("8_4_1_2_7_",),
    "8.4.1.2.8 analog same sequence select retries": ("8_4_1_2_8_",),
    "8.4.1.2.9 analog incrementing sequence select retries": ("8_4_1_2_9_",),
    "8.4.1.2.10 analog same sequence operate retries": ("8_4_1_2_10_",),
    "8.4.1.2.11 analog incrementing sequence operate retries": ("8_4_1_2_11_",),
    "8.4.1.2.12 analog sequence number checking": ("8_4_1_2_12_",),
    "8.4.1.2.13 analog SBO, 32-bit values": ("8_4_1_2_13_",),
    "8.4.2.2.1 analog direct operate": ("8_4_2_2_1_",),
    "8.4.2.2.2 analog direct operate to an uninstalled point": ("8_4_2_2_2_",),
    "8.4.2.2.3 analog direct operate, no outputs installed": ("8_4_2_2_3_",),
    "8.4.3.2.1 analog direct operate, no acknowledge": ("8_4_3_2_1_",),
    "8.4.3.2.2 analog no acknowledge, uninstalled point": ("8_4_3_2_2_",),
    "8.4.3.2.3 analog no acknowledge, no outputs installed": ("8_4_3_2_3_",),
    "8.4.4.2 multiple analog output objects": ("8_4_4_2_",),
    # 8.5: class data
    "8.5.1.2 class 0": ("8_5_1_2_",),
    "8.5.2 to 8.5.4, desired behavior": ("8_5_x_1_",),
    "8.5.2.2.1, 8.5.3.2.1, 8.5.4.2.1 class data, qualifier 06": ("8_5_x_2_1_",),
    "8.5.2.2.2 and .3, 8.5.3.2.2 and .3, 8.5.4.2.2 and .3 limited quantity": ("8_5_x_2_2_and_3_",),
    "8.5.2.2.4, 8.5.3.2.4, 8.5.4.2.4 class data without confirm": ("8_5_x_2_4_",),
    "8.5.5.1 multiple object request, desired behavior": ("8_5_5_1_",),
    "8.5.5.2.1 classes 1, 2 and 3": ("8_5_5_2_1_",),
    "8.5.5.2.2 classes 1, 2, 3 and 0": ("8_5_5_2_2_",),
    "8.5.6.2 class assignment verification": ("8_5_6_2_",),
    # 8.6 to 8.10
    "8.6.1.2 restart indication": ("8_6_1_2_",),
    "8.6.2.2 bad function": ("8_6_2_2_",),
    "8.6.3.2 object unknown": ("8_6_3_2_",),
    "8.6.5.1 broadcast, desired behavior": ("8_6_5_1_",),
    "8.6.5.2 broadcast address and all stations indication": ("8_6_5_2_",),
    "8.6.5.3 broadcast, confirmed response options": ("8_6_5_3_",),
    "8.6.6.2.1 buffer overflow, binary input events": ("8_6_6_2_1_",),
    "8.6.6.2.2 buffer overflow, analog input events": ("8_6_6_2_2_",),
    "8.7 time, a device that does not ask": ("8_7_a_",),
    "8.7.1.1.2 delay measurement": ("8_7_1_1_2_",),
    "8.7.1.2.2 time synchronization": ("8_7_1_2_2_",),
    "8.8.2 cold restart": ("8_8_2_",),
    "8.9.1.2 FIR, FIN and sequence in fragmentation": ("8_9_1_2_",),
    "8.9.2.1 confirmation in fragmentation, desired behavior": ("8_9_2_1_",),
    "8.9.2.2 confirmation in fragmentation": ("8_9_2_2_",),
    "8.10.2 multi-drop support": ("8_10_2_",),
    # 8.13 to 8.26
    "8.13.2.2 no binary inputs": ("8_13_2_2_",),
    "8.13.2.3 binary inputs": ("8_13_2_3_",),
    "8.13.2.4 binary inputs, none installed": ("8_13_2_4_",),
    "8.14.2.3 binary input change, qualifier 06": ("8_14_2_3_",),
    "8.14.2.4 and 8.14.2.5 binary input change, limited quantity": ("8_14_2_4_and_5_",),
    "8.14.2.6 binary input change without confirm": ("8_14_2_6_",),
    "8.14.2.7 without time, qualifier 06": ("8_14_2_7_",),
    "8.14.2.8 and 8.14.2.9 without time, limited quantity": ("8_14_2_8_and_9_",),
    "8.14.2.10 with time, qualifier 06": ("8_14_2_10_",),
    "8.14.2.11 and 8.14.2.12 with time, limited quantity": ("8_14_2_11_and_12_",),
    "8.14.2.13 to 8.14.2.15 with relative time": ("8_14_2_13_to_15_",),
    "8.15.2 relative time not supported": ("8_15_2_",),
    "8.16.1.2.2 no counters": ("8_16_1_2_2_",),
    "8.16.1.2.3 running counters": ("8_16_1_2_3_",),
    "8.16.1.2.4 counters, none installed": ("8_16_1_2_4_",),
    "8.16.2.1 frozen counters, desired behavior": ("8_16_2_1_",),
    "8.16.2.2.2 no frozen counters": ("8_16_2_2_2_",),
    "8.16.2.2.3 and 8.16.2.2.5 freeze, with and without acknowledge": ("8_16_2_2_3_",),
    "8.16.2.2.4 and 8.16.2.2.6 freeze and clear, with and without acknowledge": (
        "8_16_2_2_4_and_6_",
    ),
    "8.17.2.2 counter events not supported": ("8_17_2_2_",),
    "8.18.2.2 no analog inputs": ("8_18_2_2_",),
    "8.18.2.3 analog inputs": ("8_18_2_3_",),
    "8.19.1 analog change, desired behavior": ("8_19_1_",),
    "8.19.2.2 analog input change": ("8_19_2_2_",),
    "8.19.2.3 analog input change without confirm": ("8_19_2_3_",),
    "8.19.2.4 analog input change, value return": ("8_19_2_4_",),
    "8.20.2.2 multiple object types": ("8_20_2_2_",),
    "8.21.1 double-bit inputs disabled": ("8_21_1_",),
    "8.22.1 double-bit input changes disabled": ("8_22_1_",),
    "8.23.2.x.1 ranges, device without the point type": ("8_23_2_x_1_",),
    "8.23.2.x.2 ranges, valid request": ("8_23_2_x_2_",),
    "8.23.2.x.3 ranges, out of range request": ("8_23_2_x_3_",),
    "8.24.2.1 specific variations, binary inputs": ("8_24_2_1_",),
    "8.24.2.2 specific variations, double-bit inputs": ("8_24_2_2_",),
    "8.24.2.3 specific variations, binary output status": ("8_24_2_3_",),
    "8.24.2.4 specific variations, counters": ("8_24_2_4_",),
    "8.24.2.5 specific variations, frozen counters": ("8_24_2_5_",),
    "8.24.2.6 specific variations, analog inputs": ("8_24_2_6_",),
    "8.24.2.7 specific variations, analog output status": ("8_24_2_7_",),
    "8.25.2.3 specific event variations, counters": ("8_25_2_3_",),
    "8.25.2.4 specific event variations, frozen counters": ("8_25_2_4_",),
    "8.25.2.5 specific event variations, analog inputs": ("8_25_2_5_",),
    "8.26.2 assign class": ("8_26_2_",),
    # 9: network
    "9.5.1 TCP as the main method": ("9_5_1_a_",),
    "9.5.1.1 port 20000": ("9_5_1_1_",),
    "9.5.1.2 port other than 20000": ("9_5_1_2_",),
    "9.5.1.5 UDP unicast broadcast while using TCP": ("9_5_1_5_",),
    # 10: output events
    "10 output control events, not offered": ("10_",),
}

#: Sections that do not apply, and why. Each reason is a fact about this
#: outstation that the Device Profile it generates also states.
NOT_APPLICABLE: dict[str, str] = {
    "6.1.2 steps 22 to 31": "the outstation never requests data link confirmation",
    "6.2 test link": "deprecated by the procedures themselves",
    "6.4 link layer retries": "the outstation never requests data link confirmation",
    "6.5.2 steps 5 to 13": "the outstation never requests data link confirmation",
    "6.6.3 invalid secondary frames": "applies only to a device that requests link confirmations",
    "8.2.4.2 steps 7 to 12": "a request may carry as many controls as fit a fragment",
    "8.4.4.2 steps 7 to 12": "a request may carry as many controls as fit a fragment",
    "8.6.4 local": "no local or disabled state for outputs is modeled, so IIN1.5 is never set",
    "8.6.6.2.3 buffer overflow, counter events": "counter change events are not generated",
    "8.6.6.2.4 buffer overflow, double-bit events": "double-bit inputs are not supported",
    "8.7.2 LAN time sync": "not claimed; time is set by the write procedure",
    "8.11 unsolicited responses": "not supported, which is permitted at subset levels 1 and 2",
    "8.12 collision avoidance": "a serial multi-drop feature; the outstation is TCP only",
    "8.13.2.1": "for a level 1 device that cannot read binary inputs; this one can",
    "8.14.2.1": "for a level 1 device that cannot read binary input events; this one can",
    "8.14.2.2": "for a device without report by exception; this one has it",
    "8.14.2.16 relative time, long interval": "events are not reported with relative time",
    "8.15.3 common time of occurrence": "events are not reported with relative time",
    "8.16.1.2.1": "for a level 1 device that cannot read counters; this one can",
    "8.16.2.2.1": "for a level 1 device that cannot read frozen counters; this one can",
    "8.17.2.1": "for a level 1 device that cannot read counter events; this one answers",
    "8.17.2.3 to 8.17.2.6 counter events": "counter change events are not generated",
    "8.18.2.1": "for a level 1 device that cannot read analog inputs; this one can",
    "8.19.2.1": "for a level 1 device that cannot read analog events; this one can",
    "8.20.2.1": "for a level 1 device that cannot read individual objects; this one can",
    "8.21 and 8.22, other than 8.21.1 and 8.22.1": "double-bit inputs are not supported",
    "8.25.2.1 binary input event variations": "carried out as 8.14.2.7 to 8.14.2.15",
    "8.25.2.2 double-bit event variations": "double-bit inputs are not supported",
    "8.26.2 steps 20 to 58": "assign class is refused, which ends the procedure at step 19",
    "8.26.3 no-class assignment": "assign class is not implemented",
    "9.5.1.3 specific IP address": "optional; peers are admitted by TLS certificate, not address",
    "9.5.1.4 wildcard IP address": "optional; peers are admitted by TLS certificate, not address",
    "9.5.1.6 UDP multicast": "optional; not supported",
    "9.5.2 UDP solicited": "UDP is not offered as a main communication method",
    "9.5.3 UDP unsolicited": "UDP is not offered as a main communication method",
    "9.5.4 unsolicited with both UDP and TCP": "unsolicited responses are not supported",
    "10.3 and 10.4 output events": "output events are not supported, which needs no disabling",
}


def _test_names() -> dict[str, str]:
    """Every conformance test's name, without ``test_``, and the file it is in."""
    names: dict[str, str] = {}
    for path in sorted(_HERE.glob("test_ied_*.py")):
        if path.name == pathlib.Path(__file__).name:
            tree_names = ["10_output_event_groups_are_refused"]
        else:
            tree = ast.parse(path.read_text(encoding="utf-8"))
            tree_names = [
                node.name.removeprefix("test_")
                for node in ast.walk(tree)
                if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
                and node.name.startswith("test_")
            ]
        for name in tree_names:
            names[name] = path.name
    return names


def test_10_output_event_groups_are_refused():
    """Output events are not offered, so nothing about them needs to be disabled."""
    dut = Dut()
    for group in (11, 13, 42, 43):
        fragment = dut.master.read(header(group, 0)).fragment
        assert not fragment.body, group
        assert fragment.iin2 & IIN2_OBJECT_UNKNOWN, group
        assert not fragment.iin2 & IIN2_BAD_FUNCTION, group


@pytest.mark.parametrize("section", sorted(TESTED))
def test_every_section_marked_tested_has_a_test(section):
    names = _test_names()
    for prefix in TESTED[section]:
        assert any(name.startswith(prefix) for name in names), (
            f"{section} claims a test named test_{prefix}... and there is none"
        )


def test_every_conformance_test_is_accounted_for_in_the_catalog():
    prefixes = [prefix for claimed in TESTED.values() for prefix in claimed]
    orphans = sorted(
        f"{file}::test_{name}"
        for name, file in _test_names().items()
        if not any(name.startswith(prefix) for prefix in prefixes)
    )
    assert not orphans, f"tests naming a section the catalog does not list: {orphans}"


def test_no_section_is_both_tested_and_not_applicable():
    assert not set(TESTED) & set(NOT_APPLICABLE)


def test_every_exclusion_gives_a_reason():
    assert all(len(reason.split()) >= 3 for reason in NOT_APPLICABLE.values())
