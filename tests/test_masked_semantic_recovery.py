"""Phase 10D Step 8B-1E offline semantic diagnostic regressions."""

from __future__ import annotations

import ast
from collections import Counter
import hashlib
from pathlib import Path
import subprocess
import sys

import pytest
from pydantic import ValidationError

from chipchain.corpus import load_public_cve_source
from chipchain.evaluation import (
    AblationConditionKind,
    InteractionTypeRecoveryStatus,
    MaskedSemanticRecoveryDiagnosticArtifact,
    MaskedSemanticRecoveryError,
    ModelClaimBindingReason,
    ModelClaimBindingStatus,
    PHASE10D_MASKED_SEMANTIC_RECOVERY_DIAGNOSTIC_CONTRACT,
    PHASE10D_SEMANTIC_TOKENIZATION_CONTRACT,
    ParticipantGroundingDiagnostic,
    PublicKnowledgeExecutionArchive,
    ReferenceCoverageScope,
    SemanticDiagnosticMode,
    SemanticDiagnosticTextSource,
    SemanticReferenceField,
    build_masked_semantic_recovery_diagnostic_from_files,
    build_reference_content_coverage,
    extract_attack_chain_diagnostic_text,
    interaction_type_recovery_status,
    materialize_masked_semantic_recovery_diagnostic,
    participant_grounding_diagnostic,
    semantic_tokens,
    serialize_masked_semantic_recovery_diagnostic,
)
from chipchain.evaluation.semantic_recovery import (
    PHASE10D_STEP8B1D_ARCHIVE_ID,
    PHASE10D_STEP8B1D_ARCHIVE_SHA256,
)
from chipchain.models.cross_layer import CrossLayerInteractionType
from chipchain.reasoning import ReasoningResult


ROOT = Path(__file__).resolve().parents[1]
ARCHIVE_PATH = (
    ROOT
    / "data/evaluation/runs/"
    "phase10d_step8b1d_public_deepseek_20260831_one_shot.json"
)
SUMMARY_PATH = (
    ROOT
    / "data/evaluation/runs/"
    "phase10d_step8b1d_public_deepseek_20260831_offline_summary.json"
)
SOURCE_PATH = (
    ROOT / "data/public_cve/source/arm_cross_layer_seed_v1.source.json"
)
READINESS_PATH = (
    ROOT
    / "data/evaluation/public_documented_arm_secondary_knowledge_projection_v1.json"
)
ARTIFACT_PATH = (
    ROOT
    / "data/evaluation/"
    "public_documented_arm_secondary_masked_semantic_recovery_v1.json"
)
SCRIPT_PATH = ROOT / "scripts/build_masked_semantic_recovery_diagnostic.py"
FROZEN_SHA256 = {
    ARCHIVE_PATH: PHASE10D_STEP8B1D_ARCHIVE_SHA256,
    SUMMARY_PATH: (
        "d022b22be95269a601c5a263e7e4cd5844f93b53fec93055c3aac089a053df99"
    ),
    READINESS_PATH: (
        "c802a70e0554e0f7686f895fe8cec209ceb96220e51c7375fa07b46f3890e026"
    ),
    SOURCE_PATH: (
        "32a1f9782a2c966123f7f7bc141adb2d82a7ee8452705e06b1d4835e00f0e848"
    ),
}


@pytest.fixture(scope="module")
def source_archive() -> PublicKnowledgeExecutionArchive:
    return PublicKnowledgeExecutionArchive.model_validate_json(
        ARCHIVE_PATH.read_bytes()
    )


@pytest.fixture(scope="module")
def diagnostic() -> MaskedSemanticRecoveryDiagnosticArtifact:
    return build_masked_semantic_recovery_diagnostic_from_files(
        source_archive_path=ARCHIVE_PATH,
        public_source_path=SOURCE_PATH,
    )


def _case(diagnostic, cve_id: str):
    return next(item for item in diagnostic.case_diagnostics if item.cve_id == cve_id)


def _session(source_archive, condition, case_id):
    return next(
        item.reasoning_session
        for item in source_archive.real_model_execution_archive.reasoning_sessions
        if item.condition_kind is condition and item.benchmark_case_id == case_id
    )


def _all_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value).union(*(_all_keys(item) for item in value.values()))
    if isinstance(value, list):
        return set().union(*(_all_keys(item) for item in value))
    return set()


def test_contract_mode_exact_archive_and_five_cases(diagnostic) -> None:
    assert diagnostic.contract == (
        PHASE10D_MASKED_SEMANTIC_RECOVERY_DIAGNOSTIC_CONTRACT
    )
    assert diagnostic.contract == "phase10d_masked_semantic_recovery_diagnostic_v1"
    assert diagnostic.tokenization_contract == PHASE10D_SEMANTIC_TOKENIZATION_CONTRACT
    assert diagnostic.diagnostic_mode is SemanticDiagnosticMode.RETROSPECTIVE_DIAGNOSTIC
    assert diagnostic.prospective_metric_eligible is False
    assert diagnostic.source_archive_id == PHASE10D_STEP8B1D_ARCHIVE_ID
    assert diagnostic.source_archive_sha256 == PHASE10D_STEP8B1D_ARCHIVE_SHA256
    assert [item.cve_id for item in diagnostic.case_diagnostics] == [
        "CVE-2022-23960",
        "CVE-2023-34320",
        "CVE-2023-52481",
        "CVE-2024-26670",
        "CVE-2025-10263",
    ]


def test_current_archive_uses_exact_hypothesis_only_provenance(
    diagnostic, source_archive
) -> None:
    binding_by_cve = {
        item.cve_id: item
        for item in source_archive.public_knowledge_execution_binding.case_bindings
    }
    for item in diagnostic.case_diagnostics:
        session = _session(
            source_archive,
            AblationConditionKind.MASKED_CHAIN_CONTEXT_MODEL,
            item.benchmark_case_id,
        )
        hypothesis, result, text = extract_attack_chain_diagnostic_text(session)
        assert item.reasoning_context_id == (
            binding_by_cve[item.cve_id].reasoning_context_id
        )
        assert item.masked_reasoning_session_id == session.session_id
        assert item.attack_chain_hypothesis_id == hypothesis.id
        assert item.model_authored_chain_claim_id == (
            hypothesis.model_authored_chain_claim.id
        )
        assert item.attack_chain_reasoning_result_id is None
        assert item.attack_chain_reasoning_steps_available is False
        assert item.diagnostic_text_source is (
            SemanticDiagnosticTextSource.ATTACK_CHAIN_HYPOTHESIS_DESCRIPTION_ONLY
        )
        assert result is None
        assert text == hypothesis.description


def test_exact_matching_future_reasoning_result_is_optional(source_archive) -> None:
    case_id = (
        source_archive.public_knowledge_execution_binding.case_bindings[0]
        .benchmark_case_id
    )
    session = _session(
        source_archive,
        AblationConditionKind.MASKED_CHAIN_CONTEXT_MODEL,
        case_id,
    )
    hypothesis = next(
        item
        for item in session.hypotheses
        if item.model_authored_chain_claim is not None
    )
    exact = ReasoningResult.create(
        hypothesis,
        reasoning_steps=["exact ATTACK_CHAIN-only future step"],
        supporting_evidence_ids=[],
        missing_evidence=[],
        confidence=0.1,
    )
    future = session.model_copy(
        update={"reasoning_results": [*session.reasoning_results, exact]}
    )
    selected, result, text = extract_attack_chain_diagnostic_text(future)
    assert selected.id == hypothesis.id
    assert result == exact
    assert text == f"{hypothesis.description}\nexact ATTACK_CHAIN-only future step"


def test_wrong_hypothesis_merged_final_and_other_role_text_never_used(
    source_archive,
) -> None:
    case_id = (
        source_archive.public_knowledge_execution_binding.case_bindings[0]
        .benchmark_case_id
    )
    session = _session(
        source_archive,
        AblationConditionKind.MASKED_CHAIN_CONTEXT_MODEL,
        case_id,
    )
    hypothesis, result, text = extract_attack_chain_diagnostic_text(session)
    forbidden = {
        step
        for item in (*session.reasoning_results, session.final_reasoning_result)
        for step in item.reasoning_steps
    }
    assert result is None
    assert text == hypothesis.description
    assert all(step not in text for step in forbidden)
    assert session.merged_hypothesis.description not in text


def test_missing_result_requires_hypothesis_only_workflow_provenance(
    source_archive,
) -> None:
    case_id = (
        source_archive.public_knowledge_execution_binding.case_bindings[0]
        .benchmark_case_id
    )
    session = _session(
        source_archive,
        AblationConditionKind.MASKED_CHAIN_CONTEXT_MODEL,
        case_id,
    )
    poisoned = session.model_copy(update={"metadata": {}})
    with pytest.raises(MaskedSemanticRecoveryError, match="hypothesis-only"):
        extract_attack_chain_diagnostic_text(poisoned)


def test_type_recovery_is_exact_and_claim_missing_is_retained(diagnostic) -> None:
    counts = Counter(
        item.interaction_type_recovery_status for item in diagnostic.case_diagnostics
    )
    assert counts == {
        InteractionTypeRecoveryStatus.MATCH: 4,
        InteractionTypeRecoveryStatus.MISMATCH: 1,
    }
    item = _case(diagnostic, "CVE-2023-52481")
    assert item.expected_interaction_type is (
        CrossLayerInteractionType.FIRMWARE_BEHAVIOR_TO_HARDWARE
    )
    assert item.claimed_interaction_type is (
        CrossLayerInteractionType.HARDWARE_VULNERABILITY_TO_FIRMWARE
    )
    assert item.interaction_type_recovery_status is (
        InteractionTypeRecoveryStatus.MISMATCH
    )
    assert interaction_type_recovery_status(
        expected=item.expected_interaction_type,
        claim=None,
    ) is InteractionTypeRecoveryStatus.CLAIM_MISSING


def test_participant_diagnostics_derive_from_existing_binder(diagnostic) -> None:
    assert Counter(
        item.exact_binding_status for item in diagnostic.case_diagnostics
    ) == {
        ModelClaimBindingStatus.INCOMPLETE: 3,
        ModelClaimBindingStatus.MISMATCHED: 2,
    }
    assert Counter(
        item.participant_grounding_diagnostic
        for item in diagnostic.case_diagnostics
    ) == {
        ParticipantGroundingDiagnostic.VISIBLE_KNOWLEDGE_REFERENCE_SUBSTITUTION: 2,
        ParticipantGroundingDiagnostic.REQUIRED_REFERENCES_MISSING: 1,
        ParticipantGroundingDiagnostic.TYPE_SHAPE_CONFLICT: 1,
        ParticipantGroundingDiagnostic.INTERACTION_TYPE_MISMATCH: 1,
    }


def test_participant_claim_missing_and_hidden_mismatch_helpers(source_archive) -> None:
    binding = source_archive.public_knowledge_execution_binding.case_bindings[-1]
    case_input = next(
        item
        for item in source_archive.real_model_execution_archive.input_set.case_inputs
        if item.benchmark_case_id == binding.benchmark_case_id
    )
    interaction = case_input.reasoning_context.cross_layer_interaction
    session = _session(
        source_archive,
        AblationConditionKind.MASKED_CHAIN_CONTEXT_MODEL,
        binding.benchmark_case_id,
    )
    claim = next(
        item.model_authored_chain_claim
        for item in session.hypotheses
        if item.model_authored_chain_claim is not None
    )
    assert participant_grounding_diagnostic(
        binding_status=ModelClaimBindingStatus.MISSING,
        binding_reasons=[ModelClaimBindingReason.MODEL_AUTHORED_CLAIM_MISSING],
        interaction=interaction,
        claim=None,
        visible_knowledge_entry_id=binding.knowledge_entry_id,
        hidden_reference_ids=[],
    ) is ParticipantGroundingDiagnostic.CLAIM_MISSING
    assert participant_grounding_diagnostic(
        binding_status=ModelClaimBindingStatus.MISMATCHED,
        binding_reasons=[ModelClaimBindingReason.CLAIM_TARGET_VULNERABILITY_MISMATCH],
        interaction=interaction,
        claim=claim,
        visible_knowledge_entry_id=binding.knowledge_entry_id,
        hidden_reference_ids=[],
    ) is ParticipantGroundingDiagnostic.HIDDEN_REFERENCE_MISMATCH


def test_tokenization_is_deterministic_nfkc_and_architecture_aware() -> None:
    text = "The ＥＬ０ and EL1 use PAR-EL1, PAR_EL1, ERET, TLBI, DSB, BHB and LDR."
    expected = {
        "el0",
        "el1",
        "par_el1",
        "eret",
        "tlbi",
        "dsb",
        "bhb",
        "ldr",
        "use",
    }
    assert semantic_tokens(text) == expected
    assert semantic_tokens(text) == semantic_tokens(text)
    assert "public" not in semantic_tokens("public reports and evidence available")
    assert "spectre_bhb" in semantic_tokens("Spectre-BHB")
    assert not any(
        token.startswith("cve_")
        for token in semantic_tokens("CVE-2023-52481")
    )


def test_content_and_held_out_coverage_are_exact_rationals(diagnostic) -> None:
    for item in diagnostic.case_diagnostics:
        for coverage in (
            item.trigger_content_coverage,
            item.precondition_content_coverage,
            item.hardware_effect_content_coverage,
            item.trigger_held_out_coverage,
            item.precondition_held_out_coverage,
            item.hardware_effect_held_out_coverage,
        ):
            assert coverage.numerator == coverage.matched_token_count
            assert coverage.denominator == coverage.reference_token_count
            assert coverage.numerator <= coverage.denominator
            assert coverage.defined == (coverage.denominator > 0)


def test_held_out_zero_denominator_is_explicitly_undefined() -> None:
    coverage = build_reference_content_coverage(
        reference_field=SemanticReferenceField.TRIGGER_SUMMARY,
        scope=ReferenceCoverageScope.HELD_OUT,
        reference_tokens=frozenset(),
        diagnostic_tokens={"anything"},
    )
    assert (coverage.numerator, coverage.denominator, coverage.defined) == (0, 0, False)


def test_no_threshold_score_success_or_verdict_fields(diagnostic) -> None:
    keys = _all_keys(diagnostic.model_dump(mode="json"))
    assert not keys.intersection(
        {
            "pass",
            "fail",
            "score",
            "semantic_success",
            "semantic_recovery_rate",
            "verification_status",
            "vulnerability_verdict",
        }
    )


def test_curator_fields_are_not_structural_provider_projection(
    source_archive,
) -> None:
    forbidden = {"trigger_summary", "precondition_summary", "hardware_effect_summary"}
    for item in source_archive.public_knowledge_execution_binding.case_bindings:
        projection_keys = _all_keys(
            item.knowledge_projection.model_dump(mode="json")
        )
        assert not forbidden.intersection(projection_keys)


def test_source_record_and_case_crosswires_fail_closed(source_archive) -> None:
    source = load_public_cve_source(SOURCE_PATH)
    payload = source.model_dump(mode="json")
    payload["records"][0]["trigger_summary"] = payload["records"][1]["trigger_summary"]
    poisoned_source = type(source).model_validate(payload)
    with pytest.raises(MaskedSemanticRecoveryError, match="source record"):
        materialize_masked_semantic_recovery_diagnostic(
            archive=source_archive,
            source_archive_sha256=PHASE10D_STEP8B1D_ARCHIVE_SHA256,
            public_source=poisoned_source,
        )

    archive_payload = source_archive.model_dump(mode="json")
    case_bindings = archive_payload["public_knowledge_execution_binding"][
        "case_bindings"
    ]
    case_bindings[0]["reasoning_context_id"] = case_bindings[1]["reasoning_context_id"]
    with pytest.raises((ValidationError, ValueError)):
        PublicKnowledgeExecutionArchive.model_validate(archive_payload)


def test_artifact_identity_bytes_and_check_mode_are_deterministic(diagnostic) -> None:
    committed = MaskedSemanticRecoveryDiagnosticArtifact.model_validate_json(
        ARTIFACT_PATH.read_bytes()
    )
    expected = serialize_masked_semantic_recovery_diagnostic(diagnostic)
    assert committed == diagnostic
    assert ARTIFACT_PATH.read_bytes() == expected
    assert diagnostic.id == (
        "masked-semantic-recovery-diagnostic:"
        "d32018c3bbc375564a74d6dda9332cb8d863a06677f496450a2884b83aaedccd"
    )
    assert hashlib.sha256(expected).hexdigest() == (
        "425cb9c29a2ce21114938e63d917e815f3aeef917395199d1e914ca6d86bc9e5"
    )
    completed = subprocess.run(
        [sys.executable, str(SCRIPT_PATH), "--check"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr


def test_frozen_input_bytes_remain_exact() -> None:
    for path, expected in FROZEN_SHA256.items():
        assert hashlib.sha256(path.read_bytes()).hexdigest() == expected


def test_evaluator_has_no_provider_network_qemu_or_ground_truth_imports() -> None:
    path = ROOT / "src/chipchain/evaluation/semantic_recovery.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imports = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    serialized = "\n".join(sorted(imports)).lower()
    assert "provider" not in serialized
    assert "qemu" not in serialized
    assert "groundtruth" not in serialized
    assert "ground_truth" not in serialized
    source = path.read_text(encoding="utf-8").lower()
    assert "requests." not in source
    assert "urllib" not in source


def test_model_rejects_inconsistent_reasoning_result_provenance(diagnostic) -> None:
    payload = diagnostic.model_dump(mode="json")
    payload["case_diagnostics"][0]["attack_chain_reasoning_steps_available"] = True
    with pytest.raises(ValidationError, match="provenance"):
        MaskedSemanticRecoveryDiagnosticArtifact.model_validate(payload)


def test_current_per_case_exact_fractions(diagnostic) -> None:
    expected = {
        "CVE-2022-23960": ((5, 6), (0, 5), (3, 6), (0, 1), (0, 5), (0, 1)),
        "CVE-2023-34320": ((3, 12), (1, 12), (5, 6), (0, 9), (1, 12), (0, 1)),
        "CVE-2023-52481": ((3, 9), (3, 17), (5, 8), (0, 1), (1, 12), (0, 2)),
        "CVE-2024-26670": ((4, 7), (5, 10), (3, 9), (3, 3), (2, 6), (3, 9)),
        "CVE-2025-10263": ((7, 9), (5, 12), (6, 7), (3, 5), (1, 7), (0, 1)),
    }
    for item in diagnostic.case_diagnostics:
        actual = tuple(
            (coverage.numerator, coverage.denominator)
            for coverage in (
                item.trigger_content_coverage,
                item.precondition_content_coverage,
                item.hardware_effect_content_coverage,
                item.trigger_held_out_coverage,
                item.precondition_held_out_coverage,
                item.hardware_effect_held_out_coverage,
            )
        )
        assert actual == expected[item.cve_id]


def test_full_session_text_cannot_change_masked_artifact(
    source_archive,
    diagnostic,
) -> None:
    payload = source_archive.model_dump(mode="json")
    full = next(
        item
        for item in payload["real_model_execution_archive"]["reasoning_sessions"]
        if item["condition_kind"] == AblationConditionKind.FULL_CONTEXT_MODEL.value
    )
    full["reasoning_session"]["hypotheses"][0]["description"] = "FULL ONLY POISON"
    # Frozen archive identity validation rejects mutation before diagnostic use.
    with pytest.raises((ValidationError, ValueError)):
        PublicKnowledgeExecutionArchive.model_validate(payload)
    rebuilt = build_masked_semantic_recovery_diagnostic_from_files(
        source_archive_path=ARCHIVE_PATH,
        public_source_path=SOURCE_PATH,
    )
    assert rebuilt.id == diagnostic.id
