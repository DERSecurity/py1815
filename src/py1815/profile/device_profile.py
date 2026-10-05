"""Write the DNP3 Device Profile document for an outstation built here.

IEEE Std 1815 has every device publish a Device Profile: a statement of what it
implements and how it is configured, in an XML form the DNP Users Group
maintains a schema for. This module writes that document, for schema version
2.12.00, from a built :class:`~py1815.profile.outstation.DerOutstation` and the
:class:`~py1815.session.Session` serving it.

**Everything in it is read from the objects it describes.** The point lists
come from what the outstation serves, the limits and options from the
session's own configuration, and the implementation table from the same facts
the session answers by. Nothing is restated by hand, because a profile that
can drift from its device is the usual kind, and the reason people distrust
them.

**What it does not claim.** A profile has places for figures only a
measurement can supply (clock drift, response time, timestamp error) and for a
conformance test result. None has been measured or run for this library, so
those elements are left out, which the schema permits. An absent element says
"not stated"; a guessed one would say something false.

The schema and its rendering stylesheet are the DNP Users Group's and are not
carried here. The document names them, as the standard has an instance do, and
validates against a copy the caller holds.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import datetime
import importlib.metadata
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any
from xml.etree import ElementTree

from py1815 import link
from py1815.control import CommandStatus
from py1815.profile.model import Kind, Point
from py1815.profile.outstation import DerOutstation
from py1815.session import Session, SessionFacts

#: The schema edition this module writes, and the names its files ship under.
SCHEMA_VERSION = "2.12.00"
NAMESPACE = "http://www.dnp.org/DNP3/DeviceProfile"
SCHEMA_FILE = "DNP3DeviceProfile021200.xsd"
STYLESHEET_FILE = "DNP3DeviceProfile021200.xslt"

_XSI = "http://www.w3.org/2001/XMLSchema-instance"

#: Qualifier codes, as the decimal numbers the schema writes them in.
_RANGE = [0x00, 0x01]
_ALL = [0x06]
_COUNT = [0x07, 0x08]
_INDEXED = [0x17, 0x28]

READ, WRITE, SELECT, OPERATE, DIRECT, DIRECT_NR = 1, 2, 3, 4, 5, 6
FREEZE, FREEZE_NR, FREEZE_CLEAR, FREEZE_CLEAR_NR = 7, 8, 9, 10
RECORD_CURRENT_TIME = 24
RESPONSE = 129

#: The schema spells variation numbers out.
_NUMBER_WORDS = {1: "one", 2: "two", 3: "three", 4: "four", 5: "five", 9: "nine"}
_CLASS_WORDS = {0: "none", 1: "one", 2: "two", 3: "three", None: "none"}

#: A nested description of child elements: a bare name is an empty element, a
#: pair is a name with either text or children of its own.
Items = Sequence[Any]


@dataclass(frozen=True)
class Identity:
    """Who made the device and what it is called: the facts no object holds."""

    vendor: str = "Not stated"
    device: str = "py1815 DER outstation"
    hardware_version: str = "Not applicable (software)"
    software_version: str = ""
    document_version: int = 1
    author: str = "py1815"
    #: Where the outstation listens, when that is known.
    host: str | None = None
    port: int | None = None

    def software(self) -> str:
        """The stated software version, or this library's own."""
        if self.software_version:
            return self.software_version
        try:
            return f"py1815 {importlib.metadata.version('py1815')}"
        except importlib.metadata.PackageNotFoundError:
            return "py1815"


@dataclass(frozen=True)
class Row:
    """One line of the implementation table."""

    group: int
    variation: int
    description: str
    #: The request function code and the qualifiers accepted with it.
    request: tuple[int, tuple[int, ...]] | None = None
    #: The response function code and the qualifiers it may be sent with.
    response: tuple[int, tuple[int, ...]] | None = None


@dataclass(frozen=True)
class Implementation:
    """What an outstation answers: object rows, and function codes that carry none."""

    rows: tuple[Row, ...]
    function_codes: tuple[int, ...] = field(default=())


def _served(outstation: DerOutstation) -> dict[Kind, list[Point]]:
    return {kind: outstation.served(kind) for kind in Kind}


def implementation(outstation: DerOutstation, facts: SessionFacts) -> Implementation:
    """The implementation table for an outstation as it is configured.

    Built from what is served and what the session was given, so a monitor
    with no outputs lists no controls and an outstation with no counters
    lists no freezes. The tests hold every row to the session's behavior.
    """
    served = _served(outstation)
    rows: list[Row] = []

    def static(group: int, default: str, variations: dict[int, str]) -> None:
        # A read by index is answered by index, and every other read by range.
        select = tuple(_RANGE + _ALL + _INDEXED)
        rows.append(Row(group, 0, f"{default} - any variation", request=(READ, select)))
        for variation, description in variations.items():
            rows.append(
                Row(
                    group,
                    variation,
                    description,
                    request=(READ, select),
                    response=(RESPONSE, tuple(_RANGE + _INDEXED)),
                )
            )

    def events(group: int, name: str, variations: dict[int, str]) -> None:
        if not facts.events:
            return
        if group == 23 and outstation.level2:
            # Read, and answered with nothing: a Level 2 outstation buffers none.
            variations = {}
        select = tuple(_ALL + _COUNT)
        rows.append(Row(group, 0, f"{name} - any variation", request=(READ, select)))
        for variation, description in variations.items():
            rows.append(
                Row(
                    group,
                    variation,
                    description,
                    request=(READ, select),
                    response=(RESPONSE, tuple(_INDEXED)),
                )
            )

    def controls(group: int, variations: dict[int, str]) -> None:
        for variation, description in variations.items():
            for function in (SELECT, OPERATE, DIRECT):
                rows.append(
                    Row(
                        group,
                        variation,
                        description,
                        request=(function, tuple(_INDEXED)),
                        response=(RESPONSE, tuple(_INDEXED)),
                    )
                )
            rows.append(Row(group, variation, description, request=(DIRECT_NR, tuple(_INDEXED))))

    if served[Kind.BI]:
        static(1, "Binary Input", {2: "Binary Input - with flags"})
        events(
            2,
            "Binary Input Event",
            {
                1: "Binary Input Event - without time",
                2: "Binary Input Event - with absolute time",
                3: "Binary Input Event - with relative time",
            },
        )
    if served[Kind.BO]:
        static(10, "Binary Output", {2: "Binary Output - output status with flags"})
        if facts.controls:
            controls(12, {1: "Binary Output Command - control relay output block"})
    if served[Kind.CTR]:
        static(20, "Counter", {1: "Counter - 32-bit with flag"})
        if facts.freezes:
            for function in (FREEZE, FREEZE_NR, FREEZE_CLEAR, FREEZE_CLEAR_NR):
                rows.append(
                    Row(20, 0, "Counter - any variation", request=(function, tuple(_RANGE + _ALL)))
                )
        static(
            21,
            "Frozen Counter",
            {
                1: "Frozen Counter - 32-bit with flag",
                5: "Frozen Counter - 32-bit with flag and time",
                9: "Frozen Counter - 32-bit without flag",
            },
        )
        if facts.events:
            for variation, description in (
                (0, "Counter Event - any variation"),
                (1, "Counter Event - 32-bit with flag"),
                (2, "Counter Event - 16-bit with flag"),
            ):
                # Read, and answered with nothing: none are ever buffered.
                rows.append(Row(22, variation, description, request=(READ, tuple(_ALL + _COUNT))))
        events(
            23,
            "Frozen Counter Event",
            {
                1: "Frozen Counter Event - 32-bit with flag",
                5: "Frozen Counter Event - 32-bit with flag and time",
            },
        )
    if served[Kind.AI]:
        static(
            30,
            "Analog Input",
            {
                1: "Analog Input - 32-bit with flag",
                2: "Analog Input - 16-bit with flag",
                3: "Analog Input - 32-bit without flag",
                4: "Analog Input - 16-bit without flag",
            },
        )
        events(
            32,
            "Analog Input Event",
            {
                1: "Analog Input Event - 32-bit without time",
                2: "Analog Input Event - 16-bit without time",
                3: "Analog Input Event - 32-bit with time",
                4: "Analog Input Event - 16-bit with time",
            },
        )
    if served[Kind.AO]:
        static(
            40,
            "Analog Output Status",
            {
                1: "Analog Output Status - 32-bit with flag",
                2: "Analog Output Status - 16-bit with flag",
            },
        )
        if facts.controls:
            controls(
                41,
                {
                    1: "Analog Output - 32-bit",
                    2: "Analog Output - 16-bit",
                    3: "Analog Output - single-precision floating point",
                    4: "Analog Output - double-precision floating point",
                },
            )
    if facts.time_write:
        rows.append(Row(50, 1, "Time and Date - absolute time", request=(WRITE, (0x07,))))
        rows.append(
            Row(
                50,
                3,
                "Time and Date - absolute time at last recorded time",
                request=(WRITE, (0x07,)),
            )
        )
    if facts.events and served[Kind.BI]:
        # What a binary event with relative time counts from, and whether the
        # clock that gave it had been set.
        rows.append(
            Row(
                51,
                1,
                "Time and Date CTO - absolute time, synchronized",
                response=(RESPONSE, (0x07,)),
            )
        )
        rows.append(
            Row(
                51,
                2,
                "Time and Date CTO - absolute time, unsynchronized",
                response=(RESPONSE, (0x07,)),
            )
        )
    rows.append(Row(52, 2, "Time Delay - fine", response=(RESPONSE, (0x07,))))
    rows.append(Row(60, 1, "Class Objects - class 0 data", request=(READ, tuple(_ALL))))
    if facts.events:
        for variation in (2, 3, 4):
            rows.append(
                Row(
                    60,
                    variation,
                    f"Class Objects - class {variation - 1} data",
                    request=(READ, tuple(_ALL + _COUNT)),
                )
            )
    rows.append(Row(80, 1, "Internal Indications - packed format", request=(WRITE, tuple(_RANGE))))
    # Function codes that carry no object: confirm, disable unsolicited (which
    # is agreed to because none are sent), delay measurement, and the two
    # that depend on how the session was built.
    codes = [0, 21, 23]
    if facts.cold_restart:
        codes.append(13)
    if facts.time_write:
        codes.append(RECORD_CURRENT_TIME)
    # What configuration has turned off is not something the device answers.
    off = facts.disabled_functions
    return Implementation(
        rows=tuple(r for r in rows if r.request is None or r.request[0] not in off),
        function_codes=tuple(sorted(code for code in codes if code not in off)),
    )


def _tag(name: str) -> str:
    return f"{{{NAMESPACE}}}{name}"


def _add(parent: ElementTree.Element, items: Items) -> None:
    for item in items:
        if item is None:
            continue
        if isinstance(item, str):
            ElementTree.SubElement(parent, _tag(item))
            continue
        name, content = item
        child = ElementTree.SubElement(parent, _tag(name))
        if isinstance(content, (list, tuple)):
            _add(child, content)
        else:
            child.text = _text(content)


def _text(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


def _setting(
    name: str, capabilities: Items | None = None, current: Items | None = None
) -> tuple[str, list[Any]]:
    """One profile parameter: what the device can do, and how it is set now."""
    children: list[Any] = []
    if capabilities is not None:
        children.append(("capabilities", list(capabilities)))
    if current is not None:
        children.append(("currentValue", list(current)))
    return (name, children)


def _both(name: str, items: Items) -> tuple[str, list[Any]]:
    """A parameter whose capability and current value are the same thing."""
    return _setting(name, items, items)


def _value(name: str, value: Any) -> tuple[str, list[Any]]:
    return _setting(name, current=[("value", value)])


def _device(identity: Identity) -> Items:
    return [
        _both("deviceFunction", ["outstation"]),
        _value("vendorName", identity.vendor),
        _value("deviceName", identity.device),
        _value("hardwareVersion", identity.hardware_version),
        _value("softwareVersion", identity.software()),
        _value("documentVersionNumber", identity.document_version),
        _both("dnpLevelSupported", [("outStation", ["level2"])]),
        # No function block beyond the level is implemented; the element is
        # one the schema requires, so it is present and empty.
        _both("supportedFunctionBlocks", []),
        _both(
            "notableAdditions",
            [
                ("notableAddition", text)
                for text in (
                    "Analog output commands in 32-bit (g41v1) and floating point (g41v3, g41v4)",
                    "Frozen counters with time (g21v5) and frozen counter events (g23v5)",
                    "Immediate freeze and freeze-and-clear, with and without acknowledgment",
                    "Event objects read by group as well as by class",
                    "Responses of several fragments, each confirmed",
                )
            ],
        ),
        _both(
            "configurationMethods",
            [("other", [("explanation", "Set in software when the outstation is constructed")])],
        ),
        _both("connectionsSupported", ["network"]),
    ]


def _network(identity: Identity, facts: SessionFacts) -> Items:
    return [
        _value("portName", "TCP listener"),
        _both("typeOfEndPoint", ["tcpListening"]),
        (
            _setting("ipAddress", current=[("address", identity.host)])
            if identity.host is not None
            else None
        ),
        _setting(
            "tcpConnectionEstablishment",
            [
                "allowsAll",
                (
                    "other",
                    [
                        (
                            "explanation",
                            "Over TLS, a client certificate on an explicit allow-list is required",
                        )
                    ],
                ),
            ],
            ["allowsAll"],
        ),
        _setting(
            "tcpListenPort",
            [("range", [("minimum", 1), ("maximum", 65535)])],
            [("value", identity.port)] if identity.port is not None else None,
        ),
        _both("tcpKeepAliveTimer", ["timerDisabled"]),
        _both("multipleMasterConnections", ["notSupported"]),
        _both(
            "timeSynchronization",
            ["dnpLANProcedure", "dnpWriteTimeProcedure"] if facts.time_write else ["notSupported"],
        ),
    ]


def _link(facts: SessionFacts) -> Items:
    return [
        _setting(
            "dataLinkAddress",
            [("range", [("minimum", 0), ("maximum", 65519)])],
            [("value", facts.outstation_address)],
        ),
        # Either is offered; which is in force is the session's. A session
        # built for one master validates every frame against it, and one
        # built for any master validates none.
        _setting(
            "sourceAddressValidation",
            ["never", "alwaysSingleAddress"],
            ["never" if facts.master_address is None else "alwaysSingleAddress"],
        ),
        _setting(
            "expectedSourceAddress",
            ["anyDataLinkAddress", ("range", [("minimum", 0), ("maximum", 65519)])],
            ["anyDataLinkAddress"]
            if facts.master_address is None
            else [("value", facts.master_address)],
        ),
        _both("selfAddressSupport", ["no"]),
        _both("sendsConfirmedUserDataFrames", ["never"]),
        _both("linkLayerConfirmTimeout", ["none"]),
        _both("maxDataLinkRetries", ["none"]),
        _setting(
            "maxTransmittedFrameSize", [("fixed", link.MAX_FRAME)], [("value", link.MAX_FRAME)]
        ),
        _setting("maxReceivedFrameSize", [("fixed", link.MAX_FRAME)], [("value", link.MAX_FRAME)]),
    ]


def _application(facts: SessionFacts, statuses: Sequence[int]) -> Items:
    configurable = [("configurableOther", [("description", "Set when the session is constructed")])]
    whole = [
        (
            "variable",
            [("explanation", "As many as fit a request whose echo also fits a response fragment")],
        )
    ]
    return [
        _setting("maxTransmittedFragmentSize", configurable, [("value", facts.max_response)]),
        _setting("maxReceivedFragmentSize", configurable, [("value", facts.max_request)]),
        _both("fragmentTimeout", ["none"]),
        _both("maxObjectsInCROBControlRequest", whole) if facts.controls else None,
        _both("maxObjectsInAnalogOutputControlRequest", whole) if facts.controls else None,
        _both(
            "supportsMixedObjectGroupsInControlRequest",
            ["yes" if facts.controls else "notApplicable"],
        ),
        (
            _setting("controlStatusCodesSupported", [f"code{code}" for code in statuses])
            if facts.controls
            else None
        ),
    ]


def _outstation(facts: SessionFacts) -> Items:
    capacity = facts.event_capacity
    return [
        (
            _setting(
                "applicationLayerConfirmTimeout",
                [("configurableOther", [("description", "Any period, set in software")])],
                [("value", round(facts.confirm_timeout * 1000))],
            )
            if facts.confirm_timeout is not None
            else _both("applicationLayerConfirmTimeout", ["none"])
        ),
        _both("timeSyncRequired", ["never"]),
        _both("deviceTroubleBit", ["neverUsed"]),
        _both("fileHandleTimeout", ["notApplicable"]),
        _both("eventBufferOverflowBehavior", ["discardOldest"]) if facts.events else None,
        (
            _setting(
                "eventBufferOrganization",
                [
                    (
                        "perClass",
                        [
                            (
                                name,
                                [
                                    (
                                        "configurableOther",
                                        [("description", "Any size of one or more")],
                                    )
                                ],
                            )
                            for name in ("class1", "class2", "class3")
                        ],
                    )
                ],
                [
                    (
                        "perClass",
                        [
                            ("class1Value", capacity),
                            ("class2Value", capacity),
                            ("class3Value", capacity),
                        ],
                    )
                ],
            )
            if capacity is not None
            else None
        ),
        _both("sendsMultiFragmentResponses", ["yes"]),
        _setting(
            "requestsLastFragmentConfirmation",
            [
                (
                    "sometimes",
                    [
                        (
                            "explanation",
                            "When the final fragment carries events, or ends a response of "
                            "more than one fragment",
                        )
                    ],
                )
            ],
        ),
        _both("configurationSignatureSupported", ["notSupported"]),
        _both(
            "requestsApplicationConfirmation",
            [("eventResponses", ["yes"]), ("nonFinalFragments", ["yes"])],
        ),
        _both("supportsDNP3ClockManagement", ["no"]),
    ]


def _unsolicited() -> Items:
    return [_setting("supportsUnsolicitedReporting", [("supported", ["no"])], ["off"])]


def _performance(facts: SessionFacts) -> Items:
    return [
        _setting(
            "outstationSetsIIN14",
            ["never", "atStartup"],
            ["atStartup"] if facts.asks_for_time else ["never"],
        )
    ]


def _variation(number: int) -> list[str]:
    return [_NUMBER_WORDS[number]]


def _class_0(points: Sequence[Point]) -> list[str]:
    """How a group answers class 0: always, never, or differently per point."""
    included = {point.in_class_0 for point in points}
    if included == {True}:
        return ["always"]
    if included == {False}:
        return ["never"]
    return ["basedOnPointIndex"]


def _select_timeout(facts: SessionFacts) -> tuple[str, list[Any]]:
    return _setting(
        "maxTimeBetweenSelectAndOperate",
        [("configurableOther", [("description", "Any number of seconds, set in software")])],
        [("value", round(facts.select_timeout))],
    )


def _database(
    served: dict[Kind, list[Point]], facts: SessionFacts, outstation: DerOutstation
) -> Items:
    groups: list[Any] = []
    level2 = outstation.level2
    frozen = outstation.default_variation(21)
    if served[Kind.BI]:
        groups.append(
            (
                "binaryInputGroup",
                [
                    (
                        "configuration",
                        [
                            _both("defaultStaticVariation", _variation(2)),
                            _both(
                                "defaultEventVariation", _variation(facts.binary_event_variation)
                            ),
                            _both("eventReportingMode", ["allEvents"]),
                            _both("class0ResponseMode", _class_0(served[Kind.BI])),
                        ],
                    )
                ],
            )
        )
    if served[Kind.BO]:
        ignored = "Pulse times are accepted and ignored: every output behaves as latched"
        groups.append(
            (
                "binaryOutputGroup",
                [
                    (
                        "configuration",
                        [
                            _setting(
                                "minimumPulseTime",
                                [("note", ignored), ("fixed", 0)],
                                [("fixed", 0)],
                            ),
                            _setting(
                                "maximumPulseTime",
                                [("note", ignored), ("fixed", 65535)],
                                [("fixed", 65535)],
                            ),
                            _both("class0ResponseMode", ["never"]),
                            _both("outputCommandEventObjects", ["never"]),
                            _both("defaultStaticVariation", _variation(2)),
                            _select_timeout(facts),
                        ],
                    )
                ],
            )
        )
    if served[Kind.CTR]:
        groups.append(
            (
                "counterGroup",
                [
                    (
                        "configuration",
                        [
                            _both("defaultCounterStaticVariation", _variation(1)),
                            _both("counterClass0ResponseMode", ["always"]),
                            _both("defaultFrozenCounterStaticVariation", _variation(frozen)),
                            *(
                                []
                                if level2
                                else [_both("defaultFrozenCounterEventVariation", _variation(5))]
                            ),
                            _both("frozenCounterClass0ResponseMode", ["always"]),
                            *(
                                []
                                if level2
                                else [_both("frozenCounterEventReportingMode", ["allEvents"])]
                            ),
                            _both("counterRollOver", ["thirtyTwoBits"]),
                            _setting(
                                "countersFrozen",
                                [
                                    "masterRequest" if facts.freezes else None,
                                    "localFreezeWithoutTimeOfDay",
                                ],
                                ["localFreezeWithoutTimeOfDay"],
                            ),
                            _both("reportValueChangeCounterEvents", ["no"]),
                        ],
                    )
                ],
            )
        )
    if served[Kind.AI]:
        groups.append(
            (
                "analogInputGroup",
                [
                    (
                        "configuration",
                        [
                            _both("defaultStaticVariation", _variation(1)),
                            _both(
                                "defaultEventVariation", _variation(facts.analog_event_variation)
                            ),
                            _both(
                                "analogEventReportingMode",
                                [
                                    "mostRecentEventTimeValue"
                                    if facts.analog_latest_only
                                    else "allEvents"
                                ],
                            ),
                            _both("analogInputClass0ResponseMode", _class_0(served[Kind.AI])),
                            _both("analogDeadbandAssignments", ["configurableViaOtherMeans"]),
                            _both("analogDeadbandAlgorithm", ["simple"]),
                        ],
                    )
                ],
            )
        )
    if served[Kind.AO]:
        groups.append(
            (
                "analogOutputGroup",
                [
                    (
                        "configuration",
                        [
                            _both(
                                "defaultStaticVariation",
                                _variation(outstation.default_variation(40)),
                            ),
                            _both("class0ResponseMode", ["never"]),
                            _both("outputCommandEventObjects", ["never"]),
                            _select_timeout(facts),
                        ],
                    )
                ],
            )
        )
    return groups


def _table(table: Implementation) -> Items:
    entries: list[Any] = []
    for row in table.rows:
        entry: list[Any] = [
            ("objectGroup", row.group),
            ("variation", row.variation),
            ("description", row.description),
        ]
        for name, part in (("request", row.request), ("response", row.response)):
            if part is not None:
                function, qualifiers = part
                entry.append(
                    (
                        name,
                        [("functionCode", function)] + [("qualifierCode", q) for q in qualifiers],
                    )
                )
        entries.append(("supportedVariation", entry))
    for function in table.function_codes:
        entries.append(("supportedFunctionCode", [("request", [("functionCode", function)])]))
    return [("table", entries)]


def _names(point: Point) -> list[Any]:
    """A point's name, and its description where the name is only the start of one.

    The tables give some points a sentence or three. The profile has a short
    name and a description, so the first sentence is the name and the whole
    text the description.
    """
    text = " ".join(point.name.split())
    head = text.split(". ", maxsplit=1)[0].rstrip(".")
    items: list[Any] = [("index", point.index), ("name", head)]
    if head != text.rstrip("."):
        items.append(("description", text))
    return items


def _states(point: Point) -> list[Any]:
    if point.states is None:
        return []
    return [("nameState0", point.states[0]), ("nameState1", point.states[1])]


def _included(point: Point) -> str:
    return "always" if point.in_class_0 else "never"


def _scaling(point: Point) -> list[Any]:
    items: list[Any] = []
    if point.offset:
        items.append(("scaleOffset", point.offset))
    if point.multiplier is not None:
        items.append(("scaleFactor", point.multiplier))
    if point.units and point.units.lower() not in ("none", "n/a"):
        items.append(("units", point.units))
    return items


def _points(served: dict[Kind, list[Point]], facts: SessionFacts) -> Items:
    definition = ("configuration", [("pointListDefinition", ["fixed"])])
    lists: list[Any] = []

    def section(name: str, element: str, kind: Kind, describe: Any) -> None:
        if served[kind]:
            points = [(element, describe(point)) for point in served[kind]]
            lists.append((name, [definition, ("dataPoints", points)]))

    def binary_input(point: Point) -> list[Any]:
        return [
            *_names(point),
            ("changeEventClass", _CLASS_WORDS[point.event_class]),
            ("includedInClass0Response", _included(point)),
            *_states(point),
        ]

    def binary_output(point: Point) -> list[Any]:
        operations = (
            [
                "supportSelectOperate",
                "supportDirectOperate",
                "supportDirectOperateNoAck",
                "supportPulseOn",
                "supportPulseOff",
                "supportLatchOn",
                "supportLatchOff",
                "supportTrip",
                "supportClose",
            ]
            if facts.controls
            else []
        )
        return [
            *_names(point),
            ("changeEventClass", "none"),
            ("commandEventClass", "none"),
            ("includedInClass0Response", "never"),
            ("supportedControlOperations", operations),
            *_states(point),
        ]

    def counter(point: Point) -> list[Any]:
        items: list[Any] = [
            *_names(point),
            ("countersIncludedInClass0", _included(point)),
            ("counterEventClass", "none"),
            ("frozenCounterExists", point.frozen),
        ]
        if point.frozen:
            items += [
                ("frozenCountersIncludedInClass0", _included(point)),
                ("frozenCounterEventClass", _CLASS_WORDS[point.frozen_event_class or 3]),
            ]
        return items

    def analog_input(point: Point) -> list[Any]:
        items: list[Any] = [
            *_names(point),
            ("changeEventClass", _CLASS_WORDS[point.event_class]),
            ("includedInClass0Response", _included(point)),
        ]
        if point.minimum is not None and point.maximum is not None:
            items += [
                ("minIntegerTransmittedValue", int(point.minimum)),
                ("maxIntegerTransmittedValue", int(point.maximum)),
            ]
        return items + _scaling(point)

    def analog_output(point: Point) -> list[Any]:
        operations = (
            ["supportSelectOperate", "supportDirectOperate", "supportDirectOperateNoAck"]
            if facts.controls
            else []
        )
        items: list[Any] = [
            *_names(point),
            ("changeEventClass", "none"),
            ("commandEventClass", "none"),
            ("includedInClass0Response", "never"),
            ("supportedControlOperations", operations),
        ]
        if point.minimum is not None:
            items.append(("minTransmittedValue", point.minimum))
        if point.maximum is not None:
            items.append(("maxTransmittedValue", point.maximum))
        return items + _scaling(point)

    section("binaryInputPoints", "binaryInput", Kind.BI, binary_input)
    section("binaryOutputPoints", "binaryOutput", Kind.BO, binary_output)
    section("counterPoints", "counter", Kind.CTR, counter)
    section("analogInputPoints", "analogInput", Kind.AI, analog_input)
    section("analogOutputPoints", "analogOutput", Kind.AO, analog_output)
    return lists


#: The command statuses an outstation built here can answer with on its own
#: account: the session's select checks and its refusal of a request that carries a
#: status of its own, and the builder's refusals. A binding
#: may return any other status the standard defines, and that is the binding's
#: to state.
_OWN_STATUSES = (
    CommandStatus.TIMEOUT,
    CommandStatus.NO_SELECT,
    CommandStatus.FORMAT_ERROR,
    CommandStatus.NOT_SUPPORTED,
    CommandStatus.OUT_OF_RANGE,
)


def build(
    outstation: DerOutstation,
    session: Session,
    identity: Identity | None = None,
    *,
    statuses: Sequence[CommandStatus] = (),
    today: datetime.date | None = None,
) -> ElementTree.Element:
    """The Device Profile document for an outstation and the session serving it.

    Args:
        outstation: What is served: the points, and each one's class and scaling.
        session: How it is served: addresses, fragment sizes, timeouts, and
            which of time, freezes, controls and events it was given.
        identity: The vendor, device and version strings, and where it listens.
        statuses: Command statuses the caller's bindings can return, beyond the
            ones the session and builder answer with themselves.
        today: The date written into the revision history.
    """
    identity = identity or Identity()
    facts = session.facts
    served = _served(outstation)
    codes = sorted({int(status) for status in (*_OWN_STATUSES, *statuses)} - {0})

    ElementTree.register_namespace("", NAMESPACE)
    ElementTree.register_namespace("xsi", _XSI)
    root = ElementTree.Element(
        _tag("DNP3DeviceProfileDocument"),
        {
            "schemaVersion": SCHEMA_VERSION,
            f"{{{_XSI}}}schemaLocation": f"{NAMESPACE} {SCHEMA_FILE}",
        },
    )
    header = ElementTree.SubElement(root, _tag("documentHeader"))
    _add(
        header,
        [
            ("documentName", f"{identity.device} Device Profile"),
            (
                "documentDescription",
                "Capabilities and current configuration, generated from the running outstation",
            ),
            ("documentType", "Both"),
        ],
    )
    revision = ElementTree.SubElement(
        header, _tag("revisionHistory"), {"version": str(identity.document_version)}
    )
    _add(
        revision,
        [
            ("date", (today or datetime.date.today()).isoformat()),
            ("author", identity.author),
            ("reason", "Generated"),
        ],
    )

    device = ElementTree.SubElement(root, _tag("referenceDevice"))
    _add(
        device,
        [
            (
                "configuration",
                [
                    ("deviceConfig", _device(identity)),
                    ("networkConfig", _network(identity, facts)),
                    ("linkConfig", _link(facts)),
                    ("applConfig", _application(facts, codes)),
                    ("outstationConfig", _outstation(facts)),
                    ("unsolicitedConfig", _unsolicited()),
                    ("outstationPerformance", _performance(facts)),
                ],
            ),
            ("database", _database(served, facts, outstation)),
            ("implementationTable", _table(implementation(outstation, facts))),
            ("dataPointsList", _points(served, facts)),
        ],
    )
    return root


def render(root: ElementTree.Element) -> str:
    """The document as text, with the declaration and stylesheet reference.

    The stylesheet instruction is what lets a browser, or any XSLT processor,
    show the profile in the Users Group's own layout when the stylesheet sits
    beside the file.
    """
    ElementTree.indent(root, space="  ")
    body = ElementTree.tostring(root, encoding="unicode")
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<?xml-stylesheet type="text/xsl" href="{STYLESHEET_FILE}"?>\n'
        f"{body}\n"
    )
