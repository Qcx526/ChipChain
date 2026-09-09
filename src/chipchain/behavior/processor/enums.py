"""Architecture-neutral v1 vocabulary, not backend capability declarations."""

from enum import Enum


class BehaviorFactNature(str, Enum):
    """How a fact is declared to have been obtained; never implicitly runtime."""

    SOURCE_DECLARED = "source_declared"
    STATIC_DECODED = "static_decoded"
    STATIC_INFERRED = "static_inferred"
    RUNTIME_OBSERVED = "runtime_observed"
    SYNTHETIC_FIXTURE = "synthetic_fixture"


class BehaviorSourceKind(str, Enum):
    """Explicit source categories whose provenance is checked, not authenticated."""

    DECLARED_ARTIFACT = "declared_artifact"
    PROCESSORFUZZ_SI = "processorfuzz_si"
    FIRMWARE_ARTIFACT = "firmware_artifact"
    STATIC_ANALYSIS_ARTIFACT = "static_analysis_artifact"
    RUNTIME_OBSERVATION_ARTIFACT = "runtime_observation_artifact"
    SYNTHETIC_FIXTURE = "synthetic_fixture"


class RegisterClass(str, Enum):
    """CSR can be a SYSTEM namespace; it is not a universal register class."""

    GPR = "gpr"
    SYSTEM = "system"
    FLOATING_POINT = "floating_point"
    VECTOR = "vector"
    SPECIAL = "special"


class AccessKind(str, Enum):
    """Access semantics without concrete values; READ_WRITE need not be atomic."""

    READ = "read"
    WRITE = "write"
    READ_WRITE = "read_write"


class ControlTransferKind(str, Enum):
    """Declared control semantics, not evidence of a taken transition."""

    CONDITIONAL_BRANCH = "conditional_branch"
    UNCONDITIONAL_JUMP = "unconditional_jump"
    CALL = "call"
    RETURN = "return"
    INDIRECT_TRANSFER = "indirect_transfer"
    EXCEPTION_RETURN = "exception_return"


class ProcessorEventKind(str, Enum):
    """Generic event semantics; cause identifiers remain architecture/profile scoped."""

    EXCEPTION = "exception"
    INTERRUPT = "interrupt"
    TRAP = "trap"
    ENVIRONMENT_CALL = "environment_call"
    EXCEPTION_RETURN = "exception_return"
    OTHER_DECLARED = "other_declared"


class BehaviorRelationKind(str, Enum):
    """Separate source, static, dependency and runtime meanings of edges."""

    SOURCE_SEQUENCE = "source_sequence"
    STATIC_CFG_SUCCESSOR = "static_cfg_successor"
    DATA_DEPENDENCY = "data_dependency"
    CONTROL_DEPENDENCY = "control_dependency"
    RUNTIME_PRECEDES = "runtime_precedes"
