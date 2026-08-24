"""Bounded failures for provider-backed Phase 9B2C agent execution."""

from __future__ import annotations

from chipchain.reasoning.enums import ReasoningAgentType


class ProviderBackedWorkflowExecutionError(RuntimeError):
    """Report one failed role without retaining provider or prompt content."""

    def __init__(
        self,
        *,
        failed_role: ReasoningAgentType | str,
        completed_roles: list[ReasoningAgentType] | tuple[ReasoningAgentType, ...],
        error: Exception,
    ) -> None:
        normalized_role = ReasoningAgentType(failed_role)
        self.failed_role = normalized_role
        self.completed_roles = tuple(
            ReasoningAgentType(item) for item in completed_roles
        )
        self.error_type = type(error).__name__
        self.stage = str(getattr(error, "stage", "agent_execution"))
        status_code = getattr(error, "status_code", None)
        self.status_code = status_code if isinstance(status_code, int) else None
        super().__init__(
            "provider-backed reasoning workflow failed at role "
            f"{normalized_role.value} ({self.error_type})"
        )
