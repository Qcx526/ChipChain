"""Project vocabulary only; membership does not declare backend support."""

from enum import Enum


class Architecture(str, Enum):
    """Explicit architecture labels; new labels require deliberate extension."""

    RISC_V = "riscv"
    ARM = "arm"
