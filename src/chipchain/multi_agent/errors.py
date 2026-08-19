"""Public Phase 8 failure types with safe deterministic trace retention."""

from __future__ import annotations

from typing import TYPE_CHECKING

from chipchain.reasoning.errors import ReasoningError

if TYPE_CHECKING:
    from chipchain.multi_agent.enums import AgentRole
    from chipchain.multi_agent.models import AgentExecutionRecord


class AgentOutputValidationError(ReasoningError):
    """Raised when one typed agent crosses identity, citation, or condition bounds."""


class AgentExecutionError(ReasoningError):
    """Stop the fixed pipeline immediately and retain only safe trace records."""

    def __init__(
        self,
        message: str,
        *,
        failed_role: "AgentRole",
        stage: str,
        execution_trace: tuple["AgentExecutionRecord", ...],
        validation_detail: str | None = None,
    ) -> None:
        super().__init__(message)
        self.failed_role = failed_role
        self.stage = stage
        self.execution_trace = execution_trace
        self.validation_detail = validation_detail
