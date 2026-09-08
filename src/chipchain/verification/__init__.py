"""Public Phase 9A-R objective interaction verification API."""

from chipchain.verification.adapter import LegacyCandidateVerificationAdapter
from chipchain.verification.behavior import BehaviorEdgeVerifier
from chipchain.verification.bindings import validate_reference_bindings
from chipchain.verification.entity_link import EntityLinkVerifier
from chipchain.verification.enums import *
from chipchain.verification.errors import *
from chipchain.verification.evidence import EvidenceCatalog, merge_evidence
from chipchain.verification.models import *
from chipchain.verification.pipeline import InteractionVerificationPipeline
from chipchain.verification.requirements import InteractionVerificationRequirements, build_interaction_requirements
from chipchain.verification.scoring import VerificationScorer, load_verification_score_config
from chipchain.verification.cross_layer_requirement_models import *
from chipchain.verification.cross_layer_requirements import *
from chipchain.verification.cross_layer_requirement_artifact_export import *
from chipchain.verification.candidate_state_observation_models import *
from chipchain.verification.candidate_state_observation_artifact_export import *
from chipchain.verification.candidate_state_requirement_binding_models import *
from chipchain.verification.candidate_state_requirement_binding import *
from chipchain.verification.candidate_state_requirement_binding_artifact_export import *
_CANDIDATE_RUNTIME_EXPORT_MODULES = {
    "CandidateRuntimeEvidenceBindingRole": (
        "chipchain.verification.candidate_runtime_evidence_models"
    ),
    "CandidateRuntimeEvidenceBindingSemantics": (
        "chipchain.verification.candidate_runtime_evidence_models"
    ),
    "CandidateRuntimeEvidenceGap": (
        "chipchain.verification.candidate_runtime_evidence_models"
    ),
    "CandidateRuntimeEvidenceGapReason": (
        "chipchain.verification.candidate_runtime_evidence_models"
    ),
    "CandidateRuntimeEvidenceKind": (
        "chipchain.verification.candidate_runtime_evidence_models"
    ),
    "CandidateRuntimeEvidenceMaterialization": (
        "chipchain.verification.candidate_runtime_evidence_binding"
    ),
    "CandidateRuntimeEvidenceProjection": (
        "chipchain.verification.candidate_runtime_evidence_models"
    ),
    "CandidateRuntimeEvidenceSemantics": (
        "chipchain.verification.candidate_runtime_evidence_models"
    ),
    "CandidateRuntimeInstructionEvidence": (
        "chipchain.verification.candidate_runtime_evidence_models"
    ),
    "CandidateRuntimeOrderEvidence": (
        "chipchain.verification.candidate_runtime_evidence_models"
    ),
    "CandidateRuntimeRequirementEvidenceBinding": (
        "chipchain.verification.candidate_runtime_evidence_models"
    ),
    "CandidateRuntimeTraceIncompatibility": (
        "chipchain.verification.candidate_runtime_evidence_models"
    ),
    "CandidateRuntimeTraceIncompatibilityReason": (
        "chipchain.verification.candidate_runtime_evidence_models"
    ),
    "bind_candidate_runtime_evidence": (
        "chipchain.verification.candidate_runtime_evidence_binding"
    ),
    "candidate_runtime_evidence_materialization_id": (
        "chipchain.verification.candidate_runtime_evidence_binding"
    ),
    "CandidateRuntimeEvidenceArtifactBundleResult": (
        "chipchain.verification.candidate_runtime_evidence_artifact_export"
    ),
    "export_candidate_runtime_evidence_artifact_bundle": (
        "chipchain.verification.candidate_runtime_evidence_artifact_export"
    ),
    "render_candidate_runtime_evidence_graph_dot": (
        "chipchain.verification.candidate_runtime_evidence_artifact_export"
    ),
    "render_candidate_runtime_evidence_projection_json": (
        "chipchain.verification.candidate_runtime_evidence_artifact_export"
    ),
    "render_candidate_runtime_evidence_summary_markdown": (
        "chipchain.verification.candidate_runtime_evidence_artifact_export"
    ),
}


def __getattr__(name: str):
    module_name = _CANDIDATE_RUNTIME_EXPORT_MODULES.get(name)
    if module_name is None:
        raise AttributeError(name)
    from importlib import import_module

    value = getattr(import_module(module_name), name)
    globals()[name] = value
    return value


__all__ = [name for name in globals() if not name.startswith("_")]
__all__.extend(sorted(_CANDIDATE_RUNTIME_EXPORT_MODULES))
