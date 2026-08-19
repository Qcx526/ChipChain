"""Configuration-backed deterministic verification support scoring."""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import ValidationError

from chipchain.verification.enums import ConditionStatus, VerificationStatus
from chipchain.verification.errors import VerificationConfigurationError
from chipchain.verification.models import (
    ConditionAssessment,
    VerificationRecord,
    VerificationScoreConfig,
    VerificationScoreResult,
)


def load_verification_score_config(path: str | Path) -> VerificationScoreConfig:
    """Load and strictly validate one JSON score profile."""

    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return VerificationScoreConfig.model_validate(data)
    except (OSError, json.JSONDecodeError, ValidationError) as exc:
        raise VerificationConfigurationError("invalid verification score configuration") from exc


class VerificationScorer:
    """Compute evidence completeness from objective records only."""

    def __init__(self, config: VerificationScoreConfig) -> None:
        self._config = config

    def score(
        self,
        *,
        behavior: list[VerificationRecord],
        entity_link: VerificationRecord,
        knowledge: list[VerificationRecord],
        triggers: list[ConditionAssessment],
        preconditions: list[ConditionAssessment],
        architecture: list[VerificationRecord],
    ) -> VerificationScoreResult:
        components = {
            "behavior_evidence": _record_ratio(behavior),
            "entity_link": 1.0 if entity_link.status is VerificationStatus.VERIFIED else 0.0,
            "knowledge_evidence": _record_ratio(knowledge),
            "conditions": _condition_ratio([*triggers, *preconditions]),
            "architecture_rules": _record_ratio(architecture),
        }
        weighted = sum(
            components[name] * float(getattr(self._config, name))
            for name in sorted(components)
        )
        return VerificationScoreResult(
            verification_score=round(weighted, 12),
            score_components=components,
            metadata={
                "meaning": "evidence_support_not_attack_probability",
                "profile": self._config.metadata["profile"],
                "llm_weight": 0.0,
            },
        )


def _record_ratio(records: list[VerificationRecord]) -> float:
    return 1.0 if not records else sum(
        item.status is VerificationStatus.VERIFIED for item in records
    ) / len(records)


def _condition_ratio(records: list[ConditionAssessment]) -> float:
    return 1.0 if not records else sum(
        item.status is ConditionStatus.SATISFIED for item in records
    ) / len(records)

