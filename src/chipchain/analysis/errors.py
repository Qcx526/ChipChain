"""Stable public exceptions for program analysis and ingestion."""


class ProgramAnalysisError(Exception):
    """Base class for failures in a ProgramAnalyzer workflow."""


class UnsupportedArtifactError(ProgramAnalysisError):
    """Raised when an analyzer does not support an artifact type."""


class InvalidAnalysisInputError(ProgramAnalysisError):
    """Raised when an artifact or analyzer-specific input is invalid."""


class AnalysisIngestionError(ProgramAnalysisError):
    """Raised when an analysis result cannot be atomically ingested."""


class AArch64StaticSemanticDecoderError(ProgramAnalysisError):
    """Base class for plan-independent AArch64 decoder failures."""


class AArch64StaticSemanticBackendError(AArch64StaticSemanticDecoderError):
    """Raised when the optional decoder backend is unavailable or fails."""


class AArch64StaticProgramStructureExtractorError(ProgramAnalysisError):
    """Base class for plan-independent AArch64 structure extraction failures."""


class AArch64StaticProgramStructureBackendError(
    AArch64StaticProgramStructureExtractorError
):
    """Raised when the optional structure-extraction backend fails."""
