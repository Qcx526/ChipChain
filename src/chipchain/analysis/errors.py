"""Stable public exceptions for program analysis and ingestion."""


class ProgramAnalysisError(Exception):
    """Base class for failures in a ProgramAnalyzer workflow."""


class UnsupportedArtifactError(ProgramAnalysisError):
    """Raised when an analyzer does not support an artifact type."""


class InvalidAnalysisInputError(ProgramAnalysisError):
    """Raised when an artifact or analyzer-specific input is invalid."""


class AnalysisIngestionError(ProgramAnalysisError):
    """Raised when an analysis result cannot be atomically ingested."""
