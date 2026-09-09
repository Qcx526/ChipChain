"""Explicit required order between local step nodes; no source-order conversion."""

from typing import Literal, Self

from pydantic import model_validator

from chipchain.core import Identifier
from chipchain.trigger.base import _SourceBoundModel
from chipchain.trigger.enums import TriggerOrderKind


class TriggerOrderRequirement(_SourceBoundModel):
    """Normative precedence/adjacency, not observed execution or causality."""

    _namespace = "v2-trigger-order-requirement-v1"
    kind: Literal[
        TriggerOrderKind.REQUIRED_PRECEDES, TriggerOrderKind.REQUIRED_IMMEDIATELY_PRECEDES,
    ]
    before_id: Identifier
    after_id: Identifier

    @model_validator(mode="after")
    def validate_endpoints(self) -> Self:
        """A requirement cannot precede itself."""

        if self.before_id == self.after_id:
            raise ValueError("self order is not permitted")
        return self
