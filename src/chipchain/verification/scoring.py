"""Configuration-backed, type-aware objective evidence support scoring."""

import json
from pathlib import Path

from pydantic import ValidationError

from chipchain.models import CrossLayerInteractionType
from chipchain.verification.enums import VerificationStatus
from chipchain.verification.errors import VerificationConfigurationError
from chipchain.verification.models import VerificationScoreConfig, VerificationScoreResult


def load_verification_score_config(path: str | Path) -> VerificationScoreConfig:
    try: return VerificationScoreConfig.model_validate(json.loads(Path(path).read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError, ValidationError) as exc:
        raise VerificationConfigurationError("invalid verification score configuration") from exc


class VerificationScorer:
    def __init__(self, config: VerificationScoreConfig) -> None: self._config = config

    def score(self, interaction_type: CrossLayerInteractionType,
              component_statuses: dict[str, list[VerificationStatus]]) -> VerificationScoreResult:
        profile = self._config.profiles[interaction_type]
        if not profile.enabled:
            return VerificationScoreResult(verification_score=None, score_components={},
                metadata={"score_available": False, "profile": self._config.profile})
        components = {name: _record_ratio(component_statuses.get(name, [])) for name in profile.weights}
        value = round(sum(components[name] * profile.weights[name] for name in sorted(profile.weights)), 12)
        return VerificationScoreResult(verification_score=value, score_components=components,
            metadata={"meaning": "objective_evidence_support_not_probability", "profile": self._config.profile,
                      "llm_objective_weight": 0.0})


def _record_ratio(statuses: list[VerificationStatus]) -> float:
    """Missing required evidence is zero support, never a perfect score."""
    return 0.0 if not statuses else sum(s is VerificationStatus.VERIFIED for s in statuses) / len(statuses)
