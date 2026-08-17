"""Storage-independent ProgramAnalyzer abstraction."""

from __future__ import annotations

from abc import ABC, abstractmethod

from chipchain.analysis.models import ProgramAnalysisResult, ProgramArtifact


class ProgramAnalyzer(ABC):
    """Extract observable program behavior without producing security conclusions."""

    @abstractmethod
    def analyze(self, artifact: ProgramArtifact) -> ProgramAnalysisResult:
        """Analyze one artifact and return validated nodes, edges, and evidence."""
