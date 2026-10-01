"""A simulated DER to stand behind the outstation, so it runs with nothing attached.

A three-phase, storage-coupled generator of modest size, modeled just far
enough to make every point the profile requires mean something: power that
follows a slowly varying source, a meter that reports it, energy counters that
accumulate it, a state of charge that moves when the storage is dispatched,
and six DER functions a controlling station can enable and watch take effect
-- active power limit, charge/discharge, constant vars, constant power
factor, and two that follow a curve of voltage: volt-var and volt-watt.

It is a stand-in, not a model of any product. What a real integration
replaces is this module and nothing else: it binds the same points to its own
device through the same :class:`~py1815.profile.binding.Binding`.

The indices below are the profile's fixed ones (IEEE 1815.2 clause 5.2 gives
the configuration and system blocks absolute indices), named for what this
simulation does with each. Names, units and scaling stay in the tables, which
are loaded at run time and not carried here.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import math
import random
from collections.abc import Callable
from dataclasses import dataclass

from py1815.control import CommandStatus
from py1815.profile import curves
from py1815.profile.binding import Binding, Reader
from py1815.profile.curves import CurveStore
from py1815.profile.model import Address, Kind, PointMap
from py1815.profile.outstation import DerOutstation

AI, AO, BI, BO, CTR = Kind.AI, Kind.AO, Kind.BI, Kind.BO, Kind.CTR

# Binary outputs.
BO_LOCKOUT = 0
BO_START = 1
BO_STOP = 2
BO_PERMIT_START = 3
BO_PERMIT_STOP = 4
BO_CONNECT = 5
BO_PF_ABSORB_GENERATING = 10
BO_PF_ABSORB_CHARGING = 11
BO_ENABLE_POWER_LIMIT = 17
BO_ENABLE_CHARGE_DISCHARGE = 18
BO_ENABLE_VOLT_WATT = 25
BO_ENABLE_CONSTANT_VARS = 27
BO_ENABLE_CONSTANT_PF = 28
BO_ENABLE_VOLT_VAR = 29

# Analog outputs: settings, then each supported function's block.
AO_REFERENCE_VOLTAGE = 0
AO_REFERENCE_VOLTAGE_OFFSET = 1
AO_NOMINAL_FREQUENCY = 2
AO_RESPONSE_TIME_PERCENT = 3
AO_PF_SIGN_CONVENTION = 4
AO_REACTIVE_REFERENCE = 5
AO_START_STOP_FIRST, AO_START_STOP_LAST = 6, 17
AO_FREEZE_INTERVAL = 20
AO_FREEZE_INTERVAL_UNITS = 21
AO_POWER_LIMIT_FIRST, AO_POWER_LIMIT_LAST = 82, 88
AO_POWER_LIMIT_MAXIMUM = 87
AO_CHARGE_DISCHARGE_FIRST, AO_CHARGE_DISCHARGE_LAST = 89, 101
AO_CHARGE_DISCHARGE_TARGET = 93
AO_VOLT_WATT_FIRST, AO_VOLT_WATT_LAST = 168, 180
AO_VOLT_WATT_CURVE = 173
AO_CONSTANT_VARS_FIRST, AO_CONSTANT_VARS_LAST = 199, 205
AO_CONSTANT_VARS_TARGET = 203
AO_CONSTANT_PF_FIRST, AO_CONSTANT_PF_LAST = 206, 211
AO_CONSTANT_PF_GENERATING = 210
AO_CONSTANT_PF_CHARGING = 211
AO_VOLT_VAR_FIRST, AO_VOLT_VAR_LAST = 212, 220
AO_VOLT_VAR_CURVE = 217
AO_CURVE_SELECTOR = 244
AO_METER_THRESHOLD_FIRST = 449
AO_COUNTER_UNITS = 600

# The multiplexed curve block: a selector, four fields, then X and Y for each
# of a hundred points. Inputs and outputs are laid out alike.
AI_CURVE_SELECTOR = 328
BI_CURVE_REFERENCED = 107
CURVE_FIELDS = curves.FIELDS
CURVE_POINTS = curves.MAX_POINTS
#: How many curves this DER stores. The profile leaves the number to the DER.
CURVE_COUNT = 10

# Curve types and units this simulation follows, from the enumerations the
# curve fields carry: a curve of voltage, in tenths of a percent of nominal,
# against vars or watts in tenths of a percent of rating.
CURVE_VOLT_VAR = 2
CURVE_VOLT_WATT = 5
X_PERCENT_VOLTAGE = 129
Y_PERCENT_MAX_VARS = 2
Y_PERCENT_AVAILABLE_VARS = 3
Y_PERCENT_MAX_WATTS = 5

# Analog inputs this simulation computes.
AI_RESPONSE_TIME_PERCENT = 40
AI_FREEZE_INTERVAL = 69
AI_POWER_LIMIT_REFERENCE = 147
AI_VOLT_WATT_VOLTAGE = 247
AI_VOLT_WATT_OUTPUT = 249
AI_VOLT_VAR_VOLTAGE = 295
AI_VOLT_VAR_REFERENCE = 296
AI_VOLT_VAR_OUTPUT = 301
AI_METER_FIRST = 533

#: Units a freeze interval may be given in, as seconds each. The calendar
#: units beyond a week are refused: "the same day of each month" is a
#: schedule, and this simulation freezes on a period.
_INTERVAL_SECONDS = {1: 0.001, 2: 1.0, 3: 60.0, 4: 3600.0, 5: 86400.0, 6: 604800.0}

#: How quickly output follows a new target: the time constant of a first-order
#: response, in seconds.
_RESPONSE_SECONDS = 2.0

#: How long a start or a stop takes. Long enough that a controlling station
#: reading straight after the command sees the DER on its way.
_TRANSITION_SECONDS = 1.0


@dataclass(frozen=True)
class Function:
    """One DER function this simulation implements, by the points it uses."""

    name: str
    #: The binary output that enables it.
    enable: int
    #: The first and last of its analog output settings.
    settings: tuple[int, int]
    #: Analog inputs it computes, beyond the ones that read its settings back.
    inputs: tuple[int, ...] = ()
    #: The setting that names its curve, and the curve types it follows.
    curve: int | None = None
    curve_types: tuple[int, ...] = ()


#: The functions the simulation implements. Every other function of the
#: profile is left unbound, and so reports "not supported".
FUNCTIONS: tuple[Function, ...] = (
    Function(
        "active power limit",
        BO_ENABLE_POWER_LIMIT,
        (AO_POWER_LIMIT_FIRST, AO_POWER_LIMIT_LAST),
        inputs=(AI_POWER_LIMIT_REFERENCE,),
    ),
    Function(
        "charge/discharge",
        BO_ENABLE_CHARGE_DISCHARGE,
        (AO_CHARGE_DISCHARGE_FIRST, AO_CHARGE_DISCHARGE_LAST),
    ),
    Function(
        "volt-watt",
        BO_ENABLE_VOLT_WATT,
        (AO_VOLT_WATT_FIRST, AO_VOLT_WATT_LAST),
        inputs=(AI_VOLT_WATT_VOLTAGE, AI_VOLT_WATT_OUTPUT),
        curve=AO_VOLT_WATT_CURVE,
        curve_types=(CURVE_VOLT_WATT,),
    ),
    Function(
        "constant vars",
        BO_ENABLE_CONSTANT_VARS,
        (AO_CONSTANT_VARS_FIRST, AO_CONSTANT_VARS_LAST),
    ),
    Function(
        "constant power factor",
        BO_ENABLE_CONSTANT_PF,
        (AO_CONSTANT_PF_FIRST, AO_CONSTANT_PF_LAST),
    ),
    Function(
        "volt-var",
        BO_ENABLE_VOLT_VAR,
        (AO_VOLT_VAR_FIRST, AO_VOLT_VAR_LAST),
        inputs=(AI_VOLT_VAR_VOLTAGE, AI_VOLT_VAR_REFERENCE, AI_VOLT_VAR_OUTPUT),
        curve=AO_VOLT_VAR_CURVE,
        curve_types=(CURVE_VOLT_VAR,),
    ),
)


@dataclass(frozen=True)
class Ratings:
    """The nameplate of the simulated DER."""

    watts: float = 50_000.0
    volt_amperes: float = 55_000.0
    vars: float = 27_500.0
    #: Nominal line-to-line voltage; each phase is this over the root of three.
    volts: float = 480.0
    hertz: float = 60.0
    storage_watt_hours: float = 200_000.0

    @property
    def phase_volts(self) -> float:
        """Nominal line-to-neutral voltage."""
        return self.volts / math.sqrt(3)

    @property
    def amperes(self) -> float:
        """Rated current per phase."""
        return self.volt_amperes / (math.sqrt(3) * self.volts)


class ReferenceDer:
    """The simulated device: its state, how it moves, and how it is bound."""

    def __init__(self, ratings: Ratings | None = None, *, seed: int = 0) -> None:
        self.ratings = ratings or Ratings()
        self._random = random.Random(seed)
        #: Every setting a controlling station can write, by address, in
        #: engineering units. Seeded by :meth:`bind` with each one's default.
        self.settings: dict[Address, float | bool] = {}
        self.elapsed = 0.0
        self.started = True
        #: A start or stop under way: where it is headed, and the seconds left.
        self._transition: tuple[bool, float] | None = None
        self.watts = 0.0
        self.vars = 0.0
        self.phase_volts = self.ratings.phase_volts
        self.hertz = self.ratings.hertz
        self.state_of_charge = 60.0
        #: Running energy totals: watt-hours delivered and received, then
        #: var-hours delivered and received.
        self.energy = [0.0, 0.0, 0.0, 0.0]
        #: The curves, the window onto them, and which function names which.
        self.curves = CurveStore(CURVE_COUNT)
        #: How to get the curve each curve-following function names, by the
        #: index of the setting that names it. Filled in by :meth:`bind`.
        self._curve_of: dict[int, Callable[[], curves.Curve | None]] = {}

    # ------------------------------------------------------------- behavior

    def _on(self, index: int) -> bool:
        return bool(self.settings.get((BO, index), False))

    def _setting(self, index: int) -> float:
        return float(self.settings.get((AO, index), 0.0))

    @property
    def selected_curve(self) -> int:
        """The number of the curve the edit window is showing."""
        return self.curves.selected

    @property
    def line_volts(self) -> float:
        """Measured line-to-line voltage at the connection point."""
        return self.phase_volts * math.sqrt(3)

    @property
    def nominal_volts(self) -> float:
        """What a curve's percent voltage is a percentage of: the reference plus its offset."""
        return self._setting(AO_REFERENCE_VOLTAGE) + self._setting(AO_REFERENCE_VOLTAGE_OFFSET)

    def _along(self, setting: int, y_units: tuple[int, ...]) -> float | None:
        """Where the measured voltage falls on a function's curve, as a fraction of rating.

        None when the function names no curve, or one in units this
        simulation does not follow, or the nominal voltage is not set.
        """
        named = self._curve_of.get(setting)
        curve = named() if named is not None else None
        nominal = self.nominal_volts
        if curve is None or nominal <= 0:
            return None
        if curve.x_units != X_PERCENT_VOLTAGE or curve.y_units not in y_units:
            return None
        # Both axes travel in tenths of a percent.
        value = curve.at(self.line_volts / nominal * 1000.0)
        return None if value is None else value / 1000.0

    def volt_watt_limit(self) -> float | None:
        """The active power volt-watt allows at this voltage, or None when it sets no limit."""
        if not self._on(BO_ENABLE_VOLT_WATT):
            return None
        share = self._along(AO_VOLT_WATT_CURVE, (Y_PERCENT_MAX_WATTS,))
        return None if share is None else share * self.ratings.watts

    def volt_var_target(self) -> float | None:
        """The reactive power volt-var calls for at this voltage, or None when it calls for none."""
        if not self._on(BO_ENABLE_VOLT_VAR):
            return None
        share = self._along(AO_VOLT_VAR_CURVE, (Y_PERCENT_MAX_VARS, Y_PERCENT_AVAILABLE_VARS))
        return None if share is None else share * self.ratings.vars

    @property
    def connected(self) -> bool:
        """Whether the connect switch is closed."""
        return self._on(BO_CONNECT)

    @property
    def starting(self) -> bool:
        """Whether a start has been commanded and is not yet complete."""
        return self._transition is not None and self._transition[0]

    @property
    def stopping(self) -> bool:
        """Whether a stop has been commanded and is not yet complete."""
        return self._transition is not None and not self._transition[0]

    @property
    def energized(self) -> bool:
        """Whether the DER is started and connected, and so exchanging power."""
        return self.started and self.connected

    def available_watts(self) -> float:
        """What the primary source could deliver now: a slow swell around 75%."""
        return self.ratings.watts * (0.75 + 0.2 * math.sin(2 * math.pi * self.elapsed / 600.0))

    def _targets(self) -> tuple[float, float]:
        """The active and reactive power the enabled functions call for."""
        ratings = self.ratings
        if not self.energized:
            return 0.0, 0.0
        watts = self.available_watts()
        if self._on(BO_ENABLE_CHARGE_DISCHARGE):
            watts = self._setting(AO_CHARGE_DISCHARGE_TARGET) / 100.0 * ratings.watts
            full = self.state_of_charge >= 100.0
            empty = self.state_of_charge <= 0.0
            if (watts < 0 and full) or (watts > 0 and empty):
                watts = 0.0
        if self._on(BO_ENABLE_POWER_LIMIT):
            watts = min(watts, self._setting(AO_POWER_LIMIT_MAXIMUM) / 100.0 * ratings.watts)
        limit = self.volt_watt_limit()
        if limit is not None:
            watts = min(watts, limit)
        watts = max(-ratings.watts, min(ratings.watts, watts))

        reactive = 0.0
        if self._on(BO_ENABLE_CONSTANT_PF):
            charging = watts < 0
            factor = self._setting(
                AO_CONSTANT_PF_CHARGING if charging else AO_CONSTANT_PF_GENERATING
            )
            factor = min(1.0, max(0.01, abs(factor)))
            absorbing = self._on(BO_PF_ABSORB_CHARGING if charging else BO_PF_ABSORB_GENERATING)
            reactive = abs(watts) * math.tan(math.acos(factor)) * (-1.0 if absorbing else 1.0)
        elif self._on(BO_ENABLE_CONSTANT_VARS):
            reactive = self._setting(AO_CONSTANT_VARS_TARGET) / 100.0 * ratings.vars
        else:
            # Volt-var gives way to either fixed reactive function.
            reactive = self.volt_var_target() or 0.0
        reactive = max(-ratings.vars, min(ratings.vars, reactive))
        # Active power has priority: reactive gives way at the apparent limit.
        headroom = math.sqrt(max(0.0, ratings.volt_amperes**2 - watts**2))
        return watts, max(-headroom, min(headroom, reactive))

    def step(self, seconds: float) -> None:
        """Move the simulation forward."""
        if seconds <= 0:
            return
        self.elapsed += seconds
        if self._transition is not None:
            target, remaining = self._transition
            if remaining <= seconds:
                self.started, self._transition = target, None
            else:
                self._transition = (target, remaining - seconds)
        target_watts, target_vars = self._targets()
        share = 1.0 - math.exp(-seconds / _RESPONSE_SECONDS)
        self.watts += (target_watts - self.watts) * share
        self.vars += (target_vars - self.vars) * share

        ratings = self.ratings
        self.phase_volts = ratings.phase_volts * (
            1.0 + 0.004 * math.sin(self.elapsed / 37.0) + self._random.gauss(0.0, 0.0004)
        )
        self.hertz = (
            ratings.hertz + 0.01 * math.sin(self.elapsed / 53.0) + self._random.gauss(0.0, 0.002)
        )

        hours = seconds / 3600.0
        self.energy[0] += max(self.watts, 0.0) * hours
        self.energy[1] += max(-self.watts, 0.0) * hours
        self.energy[2] += max(self.vars, 0.0) * hours
        self.energy[3] += max(-self.vars, 0.0) * hours
        if self._on(BO_ENABLE_CHARGE_DISCHARGE):
            moved = -self.watts * hours / ratings.storage_watt_hours * 100.0
            self.state_of_charge = max(0.0, min(100.0, self.state_of_charge + moved))

    # ------------------------------------------------------- derived values

    @property
    def volt_amperes(self) -> float:
        """Apparent power at the connection point."""
        return math.hypot(self.watts, self.vars)

    @property
    def power_factor(self) -> float:
        """Power factor magnitude; unity when nothing is flowing."""
        apparent = self.volt_amperes
        return 1.0 if apparent < 1.0 else abs(self.watts) / apparent

    @property
    def amperes(self) -> float:
        """Current per phase."""
        return self.volt_amperes / (3.0 * self.phase_volts)

    def freeze_interval_seconds(self) -> float | None:
        """How often the counters freeze, or None when they are not to repeat."""
        unit = _INTERVAL_SECONDS.get(round(self._setting(AO_FREEZE_INTERVAL_UNITS)))
        interval = self._setting(AO_FREEZE_INTERVAL)
        if unit is None or interval <= 0:
            return None
        return interval * unit

    # ---------------------------------------------------------------- binding

    def bind(self, point_map: PointMap) -> Binding:
        """This DER's binding: every point it serves, and how."""
        binding = Binding()
        self._bind_state(binding)
        self._bind_settings(binding)
        self._bind_functions(binding)
        self._bind_curves(binding)
        self._bind_nameplate(binding, point_map)
        self._bind_meter(binding)
        return binding

    def _blocked(self, _value: float) -> CommandStatus | None:
        """Refuse a command while the system is locked out."""
        return CommandStatus.BLOCKED if self._on(BO_LOCKOUT) else None

    def _output(
        self,
        binding: Binding,
        kind: Kind,
        index: int,
        initial: float | bool,
        apply: Callable[[float], CommandStatus | None] | None = None,
        *,
        lockable: bool = True,
    ) -> None:
        """Bind one output as a stored setting, optionally with a side effect."""
        address = (kind, index)
        self.settings[address] = initial

        def store(value: float) -> CommandStatus | None:
            if apply is not None:
                answer = apply(value)
                if answer is not None and answer is not CommandStatus.SUCCESS:
                    return answer
            self.settings[address] = value
            return None

        binding.output(
            kind, index, store, initial=initial, check=self._blocked if lockable else None
        )

    def _start(self, value: float) -> CommandStatus | None:
        if not value:
            return None
        if not self._on(BO_PERMIT_START):
            return CommandStatus.BLOCKED
        if not self.started or self.stopping:
            self._transition = (True, _TRANSITION_SECONDS)
        return None

    def _stop(self, value: float) -> None:
        if value and (self.started or self.starting):
            self._transition = (False, _TRANSITION_SECONDS)

    def _bind_state(self, binding: Binding) -> None:
        # The lockout itself stays commandable while locked out: it is how a
        # controlling station releases it.
        self._output(binding, BO, BO_LOCKOUT, False, lockable=False)
        self._output(binding, BO, BO_START, False, self._start)
        self._output(binding, BO, BO_STOP, False, self._stop)
        self._output(binding, BO, BO_PERMIT_START, True)
        self._output(binding, BO, BO_PERMIT_STOP, True)
        self._output(binding, BO, BO_CONNECT, True)
        self._output(binding, BO, BO_PF_ABSORB_GENERATING, False)
        self._output(binding, BO, BO_PF_ABSORB_CHARGING, False)

        def idle() -> bool:
            return self.energized and abs(self.watts) < 0.01 * self.ratings.watts

        states: dict[int, Reader] = {
            # Alarms: a healthy simulated system raises none but the storage ones.
            0: lambda: False,
            1: lambda: False,
            2: lambda: False,
            3: lambda: False,
            4: lambda: self.state_of_charge >= 100.0,
            5: lambda: self.state_of_charge > 95.0,
            6: lambda: self.state_of_charge < 5.0,
            7: lambda: self.state_of_charge <= 0.0,
            8: lambda: False,
            9: lambda: False,
            # State.
            10: lambda: False,
            12: lambda: self.starting,
            13: lambda: self.stopping,
            14: lambda: self.started,
            15: lambda: not self.started,
            18: idle,
            19: lambda: self.energized and not idle() and self.watts > 0,
            20: lambda: self.energized and not idle() and self.watts < 0,
            21: lambda: not self.started and self._on(BO_PERMIT_START),
            22: lambda: not self.started and not self._on(BO_PERMIT_START),
            23: lambda: self.connected,
            24: lambda: False,
            # Storage capacity is stated in watt-hours.
            27: lambda: True,
        }
        # The disconnect protections: none blocked, started or operated.
        states.update({index: (lambda: False) for index in range(52, 64)})
        for index, reader in states.items():
            binding.read(BI, index, reader)

    def _bind_settings(self, binding: Binding) -> None:
        ratings = self.ratings
        defaults = {
            AO_REFERENCE_VOLTAGE: ratings.volts,
            AO_REFERENCE_VOLTAGE_OFFSET: 0.0,
            AO_NOMINAL_FREQUENCY: ratings.hertz,
            AO_RESPONSE_TIME_PERCENT: 90.0,
            AO_PF_SIGN_CONVENTION: 2.0,
            AO_REACTIVE_REFERENCE: 2.0,
            # Return to service: voltage window in percent of reference, the
            # frequency window in hertz, then delays and ramps in seconds.
            6: 105.0,
            7: 91.7,
            8: ratings.hertz + 0.1,
            9: ratings.hertz - 0.5,
            10: 300.0,
            11: 0.0,
            12: 300.0,
            13: 0.0,
            14: 0.0,
            15: 0.0,
            16: 0.0,
            17: 0.0,
            # Counters freeze every five minutes until told otherwise.
            AO_FREEZE_INTERVAL: 300_000.0,
        }
        for index, value in defaults.items():
            self._output(binding, AO, index, value)

        def interval_units(value: float) -> CommandStatus | None:
            if round(value) != 0 and round(value) not in _INTERVAL_SECONDS:
                return CommandStatus.NOT_SUPPORTED
            return None

        self._output(binding, AO, AO_FREEZE_INTERVAL_UNITS, 1.0, interval_units)

        def counter_units(value: float) -> CommandStatus | None:
            # The counters count watt-hours and var-hours and nothing coarser.
            return None if round(value) == 1 else CommandStatus.NOT_SUPPORTED

        self._output(binding, AO, AO_COUNTER_UNITS, 1.0, counter_units)

        # Two settings whose inputs the tables do not pair with their outputs.
        binding.read(AI, AI_RESPONSE_TIME_PERCENT, lambda: self._setting(AO_RESPONSE_TIME_PERCENT))
        binding.read(AI, AI_FREEZE_INTERVAL, lambda: self._setting(AO_FREEZE_INTERVAL))

        # System meter alarm thresholds: active and reactive power, power
        # factor, then each phase voltage, high before low. A low threshold of
        # zero is one that is not set.
        phase = ratings.phase_volts
        thresholds = [
            1.1 * ratings.watts,
            0.0,
            1.1 * ratings.vars,
            0.0,
            1.0,
            0.0,
            *([1.1 * phase, 0.88 * phase] * 3),
        ]
        for offset, value in enumerate(thresholds):
            self._output(binding, AO, AO_METER_THRESHOLD_FIRST + offset, value)

    def _bind_functions(self, binding: Binding) -> None:
        self._output(binding, BO, BO_ENABLE_POWER_LIMIT, False)
        self._output(binding, BO, BO_ENABLE_CHARGE_DISCHARGE, False)
        self._output(binding, BO, BO_ENABLE_CONSTANT_VARS, False)
        self._output(binding, BO, BO_ENABLE_CONSTANT_PF, False)
        self._output(binding, BO, BO_ENABLE_VOLT_WATT, False)
        self._output(binding, BO, BO_ENABLE_VOLT_VAR, False)

        defaults = {
            AO_POWER_LIMIT_MAXIMUM: 100.0,
            AO_CONSTANT_PF_GENERATING: 1.0,
            AO_CONSTANT_PF_CHARGING: 1.0,
        }
        for function in FUNCTIONS:
            first, last = function.settings
            for index in range(first, last + 1):
                if index != function.curve:
                    self._output(binding, AO, index, defaults.get(index, 0.0))
        binding.read(AI, AI_POWER_LIMIT_REFERENCE, lambda: self.watts)

        # The two functions that follow a curve report the voltage they act
        # on and what they are asking for; with nothing asked, that is what
        # the DER is doing anyway.
        binding.read(AI, AI_VOLT_WATT_VOLTAGE, lambda: self.line_volts, deadband=10)
        binding.read(AI, AI_VOLT_VAR_VOLTAGE, lambda: self.line_volts, deadband=10)
        binding.read(AI, AI_VOLT_VAR_REFERENCE, lambda: self.nominal_volts)

        def volt_watt_output() -> float:
            limit = self.volt_watt_limit()
            return self.ratings.watts if limit is None else limit

        binding.read(AI, AI_VOLT_WATT_OUTPUT, volt_watt_output)
        binding.read(AI, AI_VOLT_VAR_OUTPUT, lambda: self.volt_var_target() or 0.0)

    def _bind_curves(self, binding: Binding) -> None:
        """The curve block, and the functions that name a curve from it."""
        self.curves.bind(
            binding,
            output=AO_CURVE_SELECTOR,
            readback=AI_CURVE_SELECTOR,
            referenced=BI_CURVE_REFERENCED,
            check=self._blocked,
        )
        for function in FUNCTIONS:
            if function.curve is None:
                continue
            enable = function.enable
            self._curve_of[function.curve] = self.curves.reference(
                binding,
                function.curve,
                types=function.curve_types,
                enabled=lambda enable=enable: self._on(enable),  # type: ignore[misc]
                check=self._blocked,
            )

    def _bind_nameplate(self, binding: Binding, point_map: PointMap) -> None:
        ratings = self.ratings
        composition = point_map.composition
        fixed = {
            # The implementation level is left at "ignore": this is a simulation.
            1: 0.0,
            2: 0.88 * ratings.volts,
            3: 1.1 * ratings.volts,
            4: ratings.watts,
            5: -ratings.watts,
            6: ratings.watts,
            7: -ratings.watts,
            8: 0.9,
            9: ratings.watts,
            10: -ratings.watts,
            11: 0.9,
            12: ratings.vars,
            13: -ratings.vars,
            14: ratings.volt_amperes,
            15: -ratings.volt_amperes,
            16: ratings.storage_watt_hours,
            17: ratings.storage_watt_hours,
            18: ratings.storage_watt_hours,
            19: ratings.amperes,
            20: -ratings.amperes,
            # IEEE 1547 performance categories: B, and III.
            22: 2.0,
            23: 3.0,
            # No schedules; equipment counts from the composition served.
            24: 0.0,
            25: float(composition.meters),
            26: float(composition.inverters),
            27: float(composition.batteries),
            28: float(composition.der_units),
            32: ratings.watts,
            33: -ratings.watts,
            34: ratings.vars,
            35: -ratings.vars,
            36: ratings.volt_amperes,
            37: -ratings.volt_amperes,
            38: 0.88 * ratings.volts,
            39: 1.1 * ratings.volts,
            # Ramp rate limits, in percent of rating per second.
            62: 100.0,
            63: 100.0,
            64: 100.0,
            65: 100.0,
        }
        for index, value in fixed.items():
            binding.read(AI, index, _fixed(value))

        available_vars = self.ratings.vars
        binding.read(
            AI, 43, lambda: self.available_watts() if self.energized else 0.0, deadband=500
        )
        binding.read(
            AI,
            44,
            lambda: -ratings.watts if self.energized and self.state_of_charge < 100.0 else 0.0,
        )
        binding.read(AI, 45, lambda: available_vars if self.energized else 0.0)
        binding.read(AI, 46, lambda: -available_vars if self.energized else 0.0)
        binding.read(AI, 47, lambda: self.state_of_charge, deadband=5)
        binding.read(AI, 48, lambda: self.state_of_charge, deadband=5)
        # Start-up status: zero while stopped, complete once started.
        binding.read(AI, 49, lambda: 99.0 if self.started else 0.0)

    def _bind_meter(self, binding: Binding) -> None:
        """The system meter at the connection point, alarms and counters."""
        ratings = self.ratings
        power_band = 0.01 * ratings.watts
        meter: list[tuple[Reader, float | None]] = [
            (lambda: 1.0, None),  # connection point: the DER to the local system
            (lambda: 6.0, None),  # three-phase wye, grounded
            (lambda: 1.0, None),  # apparent power as the vector sum
            (lambda: self.hertz, 20),
            (lambda: self.watts, power_band),
            (lambda: self.watts / 3.0, power_band),
            (lambda: self.watts / 3.0, power_band),
            (lambda: self.watts / 3.0, power_band),
            (lambda: self.vars, power_band),
            (lambda: self.vars / 3.0, power_band),
            (lambda: self.vars / 3.0, power_band),
            (lambda: self.vars / 3.0, power_band),
            (lambda: self.power_factor, 2),
            (lambda: self.volt_amperes, power_band),
            (lambda: self.phase_volts, 10),
            (lambda: 0.0, None),
            (lambda: self.phase_volts, 10),
            (lambda: -120.0, None),
            (lambda: self.phase_volts, 10),
            (lambda: 120.0, None),
            (lambda: self.phase_volts * math.sqrt(3), 10),
            (lambda: self.amperes, 10),
            (lambda: self.amperes, 10),
            (lambda: self.amperes, 10),
        ]
        for offset, (reader, deadband) in enumerate(meter):
            binding.read(AI, AI_METER_FIRST + offset, reader, deadband=deadband)

        def threshold(offset: int) -> float:
            return self._setting(AO_METER_THRESHOLD_FIRST + offset)

        def high(value: Callable[[], float], offset: int) -> Reader:
            return lambda: value() > threshold(offset)

        def low(value: Callable[[], float], offset: int) -> Reader:
            return lambda: threshold(offset) > 0.0 and value() < threshold(offset)

        measured: list[Callable[[], float]] = [
            lambda: self.watts,
            lambda: self.vars,
            lambda: self.power_factor,
            lambda: self.phase_volts,
            lambda: self.phase_volts,
            lambda: self.phase_volts,
        ]
        for position, value in enumerate(measured):
            binding.read(BI, 94 + 2 * position, high(value, 2 * position))
            binding.read(BI, 95 + 2 * position, low(value, 2 * position + 1))
        binding.read(BI, 106, lambda: False)

        for index in range(4):
            binding.read(CTR, index, _energy(self, index))


def _fixed(value: float) -> Reader:
    return lambda: value


def _energy(der: ReferenceDer, index: int) -> Reader:
    return lambda: der.energy[index]


class Simulation:
    """A simulated DER and its outstation, advanced together.

    Kept apart from any event loop so it can be stepped by a test as easily as
    by a timer: each step moves the device, freezes the counters when their
    interval has passed, and buffers whatever changed.
    """

    def __init__(self, der: ReferenceDer, outstation: DerOutstation) -> None:
        self.der = der
        self.outstation = outstation
        self._since_freeze = 0.0
        # The profile has the counters freeze "beginning at startup", which is
        # also what gives every frozen counter a value to report from the
        # first integrity poll.
        outstation.freeze_all()
        outstation.poll()

    def advance(self, seconds: float) -> None:
        """Move the device forward, freeze if the interval has passed, and poll."""
        self.der.step(seconds)
        self._since_freeze += seconds
        interval = self.der.freeze_interval_seconds()
        if interval is not None and self._since_freeze >= interval:
            self.outstation.freeze_all()
            self._since_freeze = 0.0
        self.outstation.poll()


def build(point_map: PointMap, *, seed: int = 0) -> Simulation:
    """A ready simulation: the reference DER bound to an outstation for *point_map*."""
    der = ReferenceDer(seed=seed)
    outstation = DerOutstation(point_map, der.bind(point_map))
    return Simulation(der, outstation)
