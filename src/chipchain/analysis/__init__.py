"""Public storage-independent program analysis API."""

from chipchain.analysis.analyzer import ProgramAnalyzer
from chipchain.analysis.angr_analyzer import AngrAnalyzer
from chipchain.analysis.demo_analyzer import DemoAnalyzer
from chipchain.analysis.errors import (
    AnalysisIngestionError,
    InvalidAnalysisInputError,
    ProgramAnalysisError,
    UnsupportedArtifactError,
)
from chipchain.analysis.ingestion import ingest_analysis_result
from chipchain.analysis.memory_map import MemoryMap, MemoryRegion, MemoryRegionKind
from chipchain.analysis.models import ProgramAnalysisResult, ProgramArtifact

__all__ = [
    "AnalysisIngestionError",
    "AngrAnalyzer",
    "DemoAnalyzer",
    "InvalidAnalysisInputError",
    "MemoryMap",
    "MemoryRegion",
    "MemoryRegionKind",
    "ProgramAnalysisError",
    "ProgramAnalysisResult",
    "ProgramAnalyzer",
    "ProgramArtifact",
    "UnsupportedArtifactError",
    "ingest_analysis_result",
]
