"""Typed relations with fail-closed source-nature gates, not graph analysis."""

from typing import Self

from pydantic import model_validator

from chipchain.core import Identifier
from chipchain.behavior.processor.base import _BehaviorRecord
from chipchain.behavior.processor.enums import BehaviorFactNature, BehaviorRelationKind


class BehaviorRelation(_BehaviorRecord):
    """Explicit relation endpoints; no constructor derives edges from addresses."""

    _namespace = "v2-processor-relation-v1"
    relation: BehaviorRelationKind
    source_id: Identifier
    target_id: Identifier

    @model_validator(mode="after")
    def validate_nature(self) -> Self:
        """Synthetic fixtures may exercise vocabulary but cannot be client evidence."""

        n, r = BehaviorFactNature, BehaviorRelationKind
        allowed = {
            r.SOURCE_SEQUENCE: {n.SOURCE_DECLARED, n.STATIC_DECODED, n.STATIC_INFERRED},
            r.STATIC_CFG_SUCCESSOR: {n.STATIC_INFERRED},
            r.DATA_DEPENDENCY: {n.STATIC_INFERRED},
            r.CONTROL_DEPENDENCY: {n.STATIC_INFERRED},
            r.RUNTIME_PRECEDES: {n.RUNTIME_OBSERVED},
        }
        if self.nature != n.SYNTHETIC_FIXTURE and self.nature not in allowed[self.relation]:
            raise ValueError("relation is incompatible with source semantic nature")
        if self.relation in {r.SOURCE_SEQUENCE, r.RUNTIME_PRECEDES} and self.source_id == self.target_id:
            raise ValueError("strict sequence/order cannot reference itself")
        return self
