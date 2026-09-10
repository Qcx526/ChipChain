"""Safe local-format rejection; errors do not echo source payloads."""


class HardwareCaseFormatError(ValueError):
    """The supplied bytes do not satisfy the explicit confirmed local profile."""
