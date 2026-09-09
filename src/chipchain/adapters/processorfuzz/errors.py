"""Safe, bounded failures without source lines, paths or testcase dumps."""


class ProcessorFuzzSIError(ValueError):
    """Base class for structural SI adapter failures."""


class ProcessorFuzzSIParseError(ProcessorFuzzSIError):
    """The bytes do not satisfy the explicitly selected syntax profile."""


class ProcessorFuzzSIIntegrityError(ProcessorFuzzSIError):
    """A detached raw snapshot or source binding is inconsistent."""


class UnsupportedSIProfileError(ProcessorFuzzSIError):
    """The requested local syntax profile is not implemented."""
