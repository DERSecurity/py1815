"""Coverage: how much of the profile a built outstation serves.

A deployment that starts from a partial map needs to see what it has and what
it has left. :meth:`~py1815.profile.outstation.DerOutstation.coverage` answers
with one :class:`Entry` for every point of the resolved map: where the point's
value comes from, or that it has none, and how it stood when the report was
made. Mandatory points are told apart from optional ones, so the report also
says how far the map is from one a strict build would accept.

It is a report and nothing else. No request is answered from it, and taking
one buffers no event and changes no output (D67).

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from py1815.profile.binding import Quality
from py1815.profile.model import Kind, MapError, Point

#: How many missing mandatory points the text names before it counts the rest.
_NAMED = 20


class Source(Enum):
    """Where a point's value comes from, which is fixed when the outstation is built.

    The first four are the ways the builder serves a point, in the order it
    tries them for an input. An output has only the first: it is served when
    it is bound, and not otherwise.
    """

    #: The caller bound it: a reader for an input, an output for an output.
    BOUND = "bound"
    #: An input paired with a bound output, reporting what that output last
    #: accepted.
    MIRROR = "mirror"
    #: A "supports" input, reporting whether its function's enable output is
    #: bound. Served whether or not it is, since "not supported" is an answer.
    SUPPORTS = "supports"
    #: A value the tables themselves fix, such as the profile version or a
    #: block's starting index.
    FIXED = "fixed"
    #: Nothing serves it. A class 0 read does not carry it and a read of its
    #: index is refused.
    ABSENT = "absent"


@dataclass(frozen=True)
class Entry:
    """One point of the map, and how this outstation stands on it."""

    point: Point
    source: Source
    #: What the point's source said of it when the report was made, after the
    #: builder's own rules: a source that raised is ``COMM_LOST``, and an input
    #: of a disabled function is ``OFFLINE``. None for a point that is absent.
    quality: Quality | None = None
    #: Whether the point was being sent with its ONLINE flag set. Taken from
    #: what goes on the wire and not from the quality alone: a good source can
    #: hand over a value with no number, which is sent with ONLINE clear.
    online: bool = False

    @property
    def served(self) -> bool:
        """Whether a master can read the point at all."""
        return self.source is not Source.ABSENT

    @property
    def address(self) -> str:
        """The point as the tables and the command line write it: ``AI537``."""
        return f"{self.point.kind.value}{self.point.index}"


@dataclass(frozen=True)
class Coverage:
    """Every point of the map against what an outstation serves.

    Two reports compare equal when every point stands alike in both, so a
    deployment can keep one and see what a new binding changed.
    """

    #: One entry per point of the map, by kind and then by index.
    entries: tuple[Entry, ...]

    def entry(self, kind: Kind, index: int) -> Entry:
        """The entry for one point, or the error that says the map has none."""
        for found in self.entries:
            if found.point.address == (kind, index):
                return found
        raise MapError(f"the map holds no {kind.value}{index}")

    def of(self, *sources: Source) -> tuple[Entry, ...]:
        """The entries whose value comes from any of the sources named."""
        return tuple(entry for entry in self.entries if entry.source in sources)

    @property
    def served(self) -> tuple[Entry, ...]:
        """The points a master can read, however each is served."""
        return tuple(entry for entry in self.entries if entry.served)

    @property
    def absent(self) -> tuple[Entry, ...]:
        """The points nothing serves, mandatory and optional alike."""
        return self.of(Source.ABSENT)

    @property
    def offline(self) -> tuple[Entry, ...]:
        """The served points that were not online when the report was made.

        Each is on the wire, with its ONLINE flag clear: its source could not
        be reached, it has never been read or written, or it belongs to a
        function that is disabled. The entry's quality says which.
        """
        return tuple(entry for entry in self.entries if entry.served and not entry.online)

    @property
    def missing(self) -> tuple[Entry, ...]:
        """The mandatory points nothing serves: what a strict build refuses over."""
        return tuple(entry for entry in self.absent if entry.point.mandatory)

    @property
    def conformant(self) -> bool:
        """Whether every mandatory point is served, which is what ``strict`` requires."""
        return not self.missing

    def changed_since(self, earlier: Coverage) -> tuple[Entry, ...]:
        """The entries that differ from an earlier report of the same map.

        Each is returned as it stands now. A point the earlier report did not
        hold counts as changed.
        """
        before = {entry.point.address: entry for entry in earlier.entries}
        return tuple(entry for entry in self.entries if before.get(entry.point.address) != entry)

    def render(self) -> str:
        """The report as text: a summary, a count by source, and a line per point.

        A point's line holds its address, ``M`` if it is mandatory, where its
        value comes from, its quality, and its name. The lines do not depend
        on one another, so comparing two renderings line by line shows the
        points that moved.
        """
        mandatory = [entry for entry in self.entries if entry.point.mandatory]
        optional = [entry for entry in self.entries if not entry.point.mandatory]
        served = len(self.served)
        lines = [
            f"{served} of {len(self.entries)} points served, {len(self.absent)} absent",
            f"  {_served(mandatory)} of {len(mandatory)} mandatory points served",
            f"  {_served(optional)} of {len(optional)} optional points served",
            f"  {len(self.offline)} served point(s) offline when this was reported",
        ]
        if self.missing:
            named = ", ".join(entry.address for entry in self.missing[:_NAMED])
            more = len(self.missing) - _NAMED
            lines.append(
                "not conformant; mandatory points not served: "
                + named
                + (f" and {more} more" if more > 0 else "")
            )
        else:
            lines.append("conformant: every mandatory point is served")
        lines += ["", f"{'':<10}{'mandatory':>10}{'optional':>10}"]
        for source in Source:
            lines.append(
                f"{source.value:<10}"
                f"{sum(1 for entry in mandatory if entry.source is source):>10}"
                f"{sum(1 for entry in optional if entry.source is source):>10}"
            )
        lines.append("")
        for entry in self.entries:
            marker = "M" if entry.point.mandatory else " "
            quality = "-" if entry.quality is None else entry.quality.value
            lines.append(
                f"{entry.address:<8} {marker} {entry.source.value:<8} {quality:<10} "
                f"{entry.point.name}"
            )
        return "\n".join(lines)

    def __str__(self) -> str:
        return self.render()


def _served(entries: list[Entry]) -> int:
    return sum(1 for entry in entries if entry.served)
