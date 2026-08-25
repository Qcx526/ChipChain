"""Closed Phase 10A benchmark configuration enums."""

from __future__ import annotations

from enum import Enum


class BenchmarkSourceKind(str, Enum):
    """Auditable, non-interchangeable benchmark source categories."""

    OWNED_SYNTHETIC = "owned_synthetic"
    PUBLIC_BENCHMARK = "public_benchmark"
    PUBLIC_DOCUMENTED = "public_documented"
    FIXTURE = "fixture"


class BenchmarkCaseLabel(str, Enum):
    """Ground Truth shape for one benchmark case."""

    POSITIVE_FEASIBLE = "positive_feasible"
    NEGATIVE_CONTROL = "negative_control"


class EvaluationScope(str, Enum):
    """Predeclared metric scope, fixed before candidate outcomes exist."""

    PRIMARY_TARGET = "primary_target"
    SECONDARY_ONLY = "secondary_only"
    EXCLUDED_UNSUPPORTED = "excluded_unsupported"
