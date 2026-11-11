"""The DNP3 subset level an outstation is held to.

IEEE 1815-2012 clause 14 defines Subset Levels 1 to 4, each adding objects,
variations and functions to the one before. This library implements Levels 2,
3 and 4. An outstation claims one of them, answers with what that level allows,
and says so in its Device Profile.
"""

from __future__ import annotations

import enum
from typing import Any


class SubsetLevel(enum.IntEnum):
    """A DNP3 subset level this library can be held to.

    Members compare as integers, so ``level >= SubsetLevel.LEVEL_3`` asks
    whether Level 3 features apply.
    """

    LEVEL_2 = 2
    LEVEL_3 = 3
    LEVEL_4 = 4

    @classmethod
    def parse(cls, value: Any, where: str = "level") -> SubsetLevel:
        """Return the level for 2, 3 or 4, or a member of this class.

        Raises:
            ValueError: ``value`` is anything else, including a boolean, a
                float and a string. The message names ``where``.
        """
        if isinstance(value, cls):
            return value
        if isinstance(value, int) and not isinstance(value, bool) and value in {2, 3, 4}:
            return cls(value)
        raise ValueError(f"{where} must be 2, 3 or 4, not {value!r}")
