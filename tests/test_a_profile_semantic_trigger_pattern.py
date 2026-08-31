"""Phase 10D Step 8B-2B1 A-profile semantic pattern tests."""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest
from pydantic import ValidationError

from chipchain.hardware_trigger import (
    PHASE10D_A_PROFILE_SEMANTIC_TRIGGER_PATTERN_CONTRACT,
    PHASE10D_DOCUMENTED_HARDWARE_ERRATUM_CONTRACT,
    AProfileAdditionalTimingPrecision,
    AProfileDocumentedEffectKind,
    AProfileDocumentedEffectModality,
    AProfileExecutionApplicability,
    AProfileMemoryType,
    AProfileMemoryTypeSemantics,
    AProfileMitigationReferenceKind,
    AProfileMitigationReferenceSemantics,
    AProfileRelationPrecision,
    AProfileRevisionDisposition,
    AProfileSemanticEventKind,
    AProfileSemanticEventPredicate,
    AProfileSemanticPatternUse,
    AProfileSemanticRelation,
    AProfileSemanticTriggerPattern,
    AProfileSystemRegister,
    AdditionalTimingConditionRequirement,
    ArmExecutionMode,
    HardwareTriggerSignature,
    MemoryTypeObservationRequirement,
    SemanticAlternativeSemantics,
    SemanticPositionOrder,
    SemanticRelationEvaluability,
    TriggerabilityStatus,
    build_a_profile_semantic_trigger_pattern,
    hardware_trigger_signature_id,
    serialize_a_profile_semantic_trigger_pattern,
    translate_documented_erratum_to_a_profile_pattern,
)
from chipchain.hardware_trigger.documented_erratum_models import (
    DocumentedHardwareErratumContract,
)


ROOT = Path(__file__).resolve().parents[1]
SOURCE_PATH = (
    ROOT
    / "data/evaluation/"
    "cve_2023_34320_documented_erratum_1508412_v1.json"
)
GENERATED_PATH = (
    ROOT
    / "data/evaluation/"
    "cve_2023_34320_a_profile_semantic_trigger_pattern_v1.json"
)
EXPECTED_SOURCE_ID = (
    "documented-hardware-erratum:"
    "8ad52bee747242179997fd58989c92f419ff051f618682e07e158d00a787096c"
)
EXPECTED_SOURCE_SHA256 = (
    "bd50b8b50313041c3d5245cccaf51a0d4d479914033ad233d79a740180b0c5a1"
)
EXPECTED_PATTERN_ID = (
    "a-profile-semantic-trigger-pattern:"
    "25599b751ead0dc36a39787000fad60aa0cea6485913cdf52b248e037ec21d77"
)
EXPECTED_ARTIFACT_SHA256 = (
    "6a56e75078475fd5133524c8aef28233a431283b151960ea9389d2430ce2ceb0"
)
FROZEN_FILE_HASHES = {
    "data/evaluation/cve_2023_34320_documented_erratum_1508412_v1.json": (
        EXPECTED_SOURCE_SHA256
    ),
    "data/public_cve/objective/cve_2023_34320_erratum_1508412.source.json": (
        "fea66e7375087e543fd4a1fc5ab5d2789f8825880ed624e6a0eca28b1c8e73dd"
    ),
    "data/evaluation/runs/phase10d_step8b1d_public_deepseek_20260831_one_shot.json": (
        "5bf1f1268b90a8a7eaf17bb52846ae64f2edc752ec904b3db3125fc0efafdedd"
    ),
    "data/evaluation/runs/phase10d_step8b1d_public_deepseek_20260831_offline_summary.json": (
        "d022b22be95269a601c5a263e7e4cd5844f93b53fec93055c3aac089a053df99"
    ),
    "data/evaluation/public_documented_arm_secondary_masked_semantic_recovery_v1.json": (
        "425cb9c29a2ce21114938e63d917e815f3aeef917395199d1e914ca6d86bc9e5"
    ),
    "data/public_cve/source/arm_cross_layer_seed_v1.source.json": (
        "32a1f9782a2c966123f7f7bc141adb2d82a7ee8452705e06b1d4835e00f0e848"
    ),
    "data/public_cve/arm_cross_layer_seed_v1.json": (
        "f8c79abadf98e2a6a36f5e85fc6701136ba44769c22b326a7a528f45cac63d14"
    ),
    "data/public_cve/evaluation/arm_secondary_v1.json": (
        "ad4b500e004d5ccfce127df4ff918498a520485bc7891d5cb028e1837dcffa00"
    ),
    "data/evaluation/public_documented_arm_secondary_v1.json": (
        "893944a10820ac91abd15ee176894e2caa9f1ac0c774b2ef9124b2e76c3f3ae7"
    ),
    "data/evaluation/public_documented_arm_secondary_knowledge_projection_v1.json": (
        "c802a70e0554e0f7686f895fe8cec209ceb96220e51c7375fa07b46f3890e026"
    ),
}


@pytest.fixture(scope="module")
def source() -> DocumentedHardwareErratumContract:
    return DocumentedHardwareErratumContract.model_validate_json(
        SOURCE_PATH.read_bytes()
    )


@pytest.fixture(scope="module")
def pattern() -> AProfileSemanticTriggerPattern:
    return build_a_profile_semantic_trigger_pattern(
        documented_erratum_bytes=SOURCE_PATH.read_bytes()
    )


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _pattern_payload() -> dict[str, object]:
    return json.loads(GENERATED_PATH.read_text(encoding="utf-8"))


def _case(
    pattern: AProfileSemanticTriggerPattern,
    case_id: str,
):
    return next(item for item in pattern.cases if item.case_id == case_id)


def test_exact_contract_source_binding_and_identity(
    pattern: AProfileSemanticTriggerPattern,
) -> None:
    assert pattern.contract == (
        PHASE10D_A_PROFILE_SEMANTIC_TRIGGER_PATTERN_CONTRACT
    )
    assert pattern.id == EXPECTED_PATTERN_ID
    assert pattern.source_documented_erratum_id == EXPECTED_SOURCE_ID
    assert pattern.source_documented_erratum_sha256 == EXPECTED_SOURCE_SHA256
    assert pattern.source_documented_erratum_contract == (
        PHASE10D_DOCUMENTED_HARDWARE_ERRATUM_CONTRACT
    )
    assert pattern.cve_id == "CVE-2023-34320"
    assert pattern.processor == "Cortex-A77"
    assert pattern.erratum_id == "1508412"


def test_revision_scope_is_translated_exactly(
    source: DocumentedHardwareErratumContract,
    pattern: AProfileSemanticTriggerPattern,
) -> None:
    assert [
        (item.processor, item.revision, item.disposition.value)
        for item in pattern.revision_scope
    ] == [
        (item.processor, item.revision, item.disposition.value)
        for item in source.revision_records
    ]
    assert {item.revision for item in pattern.revision_scope if item.disposition is (
        AProfileRevisionDisposition.AFFECTED
    )} == {"r0p0", "r1p0"}
    assert {item.revision for item in pattern.revision_scope if item.disposition is (
        AProfileRevisionDisposition.FIXED
    )} == {"r1p1"}


def test_exactly_two_cases_with_ordered_or_positions(
    pattern: AProfileSemanticTriggerPattern,
) -> None:
    assert [item.case_id for item in pattern.cases] == ["case_a", "case_b"]
    for case in pattern.cases:
        assert case.position_order is SemanticPositionOrder.PROGRAM_ORDER
        assert [item.position_index for item in case.positions] == [1, 2]
        assert all(
            item.alternative_semantics is SemanticAlternativeSemantics.OR
            for item in case.positions
        )


def test_case_a_exact_translation(
    pattern: AProfileSemanticTriggerPattern,
) -> None:
    case = _case(pattern, "case_a")
    first, second = case.positions

    assert {item.kind for item in first.alternatives} == {
        AProfileSemanticEventKind.STORE_EXCLUSIVE,
        AProfileSemanticEventKind.SYSTEM_REGISTER_READ,
    }
    assert len(second.alternatives) == 1
    load = second.alternatives[0]
    assert load.kind is AProfileSemanticEventKind.MEMORY_LOAD
    assert set(load.memory_type_constraints) == {
        AProfileMemoryType.DEVICE,
        AProfileMemoryType.NORMAL_NON_CACHEABLE,
    }


def test_case_b_exact_translation_and_normal_nc_exclusion(
    pattern: AProfileSemanticTriggerPattern,
) -> None:
    case = _case(pattern, "case_b")
    first, second = case.positions

    assert len(first.alternatives) == 1
    load = first.alternatives[0]
    assert load.kind is AProfileSemanticEventKind.MEMORY_LOAD
    assert load.memory_type_constraints == [AProfileMemoryType.DEVICE]
    assert AProfileMemoryType.NORMAL_NON_CACHEABLE not in (
        load.memory_type_constraints
    )
    assert {item.kind for item in second.alternatives} == {
        AProfileSemanticEventKind.STORE_EXCLUSIVE,
        AProfileSemanticEventKind.SYSTEM_REGISTER_READ,
    }


def test_event_applicability_and_system_register_are_exact(
    pattern: AProfileSemanticTriggerPattern,
) -> None:
    events = [
        event
        for case in pattern.cases
        for position in case.positions
        for event in position.alternatives
    ]
    par_reads = [
        item
        for item in events
        if item.kind is AProfileSemanticEventKind.SYSTEM_REGISTER_READ
    ]
    ordinary = [item for item in events if item not in par_reads]

    assert par_reads
    assert all(item.system_register is AProfileSystemRegister.PAR_EL1 for item in par_reads)
    assert all(
        item.applicability is AProfileExecutionApplicability.PRIVILEGED_AARCH64
        for item in par_reads
    )
    assert all(item.system_register is None for item in ordinary)
    assert all(
        item.applicability is AProfileExecutionApplicability.ARM_A_PROFILE
        for item in ordinary
    )


def test_memory_type_semantics_and_obligation_are_exact(
    pattern: AProfileSemanticTriggerPattern,
) -> None:
    events = [
        event
        for case in pattern.cases
        for position in case.positions
        for event in position.alternatives
    ]
    loads = [item for item in events if item.kind is AProfileSemanticEventKind.MEMORY_LOAD]
    non_loads = [item for item in events if item not in loads]

    assert loads
    assert all(
        item.memory_type_semantics is (
            AProfileMemoryTypeSemantics.EFFECTIVE_ARCHITECTURAL_MEMORY_TYPE
        )
        for item in loads
    )
    assert all(
        item.memory_type_observation_requirement is (
            MemoryTypeObservationRequirement.OBJECTIVE_EFFECTIVE_MEMORY_TYPE_REQUIRED
        )
        for item in loads
    )
    assert all(item.memory_type_constraints for item in loads)
    assert all(not item.memory_type_constraints for item in non_loads)
    assert all(item.memory_type_semantics is None for item in non_loads)
    assert all(
        item.memory_type_observation_requirement is None for item in non_loads
    )


def test_relation_precision_evaluability_and_timing_obligation(
    pattern: AProfileSemanticTriggerPattern,
) -> None:
    for case in pattern.cases:
        assert case.relation is AProfileSemanticRelation.CLOSE_PROXIMITY
        assert case.relation_precision is AProfileRelationPrecision.QUALITATIVE_ONLY
        assert case.quantitative_bound is None
        assert case.relation_evaluability is (
            SemanticRelationEvaluability.SOURCE_INSUFFICIENT_FOR_EXACT_SOFTWARE_ONLY_SATISFACTION
        )
    assert pattern.source_additional_timing_precision is (
        AProfileAdditionalTimingPrecision.UNSPECIFIED_BY_PUBLIC_SOURCE
    )
    assert pattern.additional_timing_condition_requirement is (
        AdditionalTimingConditionRequirement.UNRESOLVED_FROM_PUBLIC_DOCUMENTATION
    )


def test_effect_and_mitigation_references_are_documentation_only(
    pattern: AProfileSemanticTriggerPattern,
) -> None:
    assert pattern.documented_effect_reference.kind is (
        AProfileDocumentedEffectKind.CORE_DEADLOCK
    )
    assert pattern.documented_effect_reference.modality is (
        AProfileDocumentedEffectModality.POSSIBLE
    )
    assert {item.kind for item in pattern.mitigation_references} == set(
        AProfileMitigationReferenceKind
    )
    assert all(
        item.semantics is (
            AProfileMitigationReferenceSemantics.DOCUMENTED_MITIGATION_REFERENCE
        )
        for item in pattern.mitigation_references
    )
    assert pattern.pattern_use is (
        AProfileSemanticPatternUse.OBJECTIVE_ANALYZER_PREDICATES_ONLY
    )


def test_source_precision_obligations_translate_without_broadening(
    source: DocumentedHardwareErratumContract,
    pattern: AProfileSemanticTriggerPattern,
) -> None:
    source_precision = source.source_precision
    obligations = pattern.source_precision_obligations

    assert obligations.program_order_source_defined is (
        source_precision.program_order_defined
    )
    assert obligations.quantitative_proximity_source_defined is (
        source_precision.quantitative_proximity_bound_defined
    )
    assert obligations.additional_timing_conditions_source_defined is (
        source_precision.additional_timing_conditions_fully_defined
    )
    assert obligations.machine_code_sequence_source_defined is (
        source_precision.unique_machine_code_sequence_defined
    )
    assert obligations.effective_memory_type_resolution_source_defined is (
        source_precision.effective_memory_type_resolution_defined
    )
    assert obligations.runtime_environment_source_defined is (
        source_precision.runtime_environment_defined
    )
    assert obligations.hardware_effect_empirical_source_defined is (
        source_precision.hardware_failure_observation_present
    )


def test_translation_completeness_for_every_source_event(
    source: DocumentedHardwareErratumContract,
    pattern: AProfileSemanticTriggerPattern,
) -> None:
    source_cases = {item.case_id: item for item in source.program_order_cases}
    pattern_cases = {item.case_id: item for item in pattern.cases}

    assert set(source_cases) == set(pattern_cases)
    for case_id, source_case in source_cases.items():
        output = pattern_cases[case_id]
        for position_index, source_position in enumerate(
            (source_case.event_1, source_case.event_2), start=1
        ):
            translated = output.positions[position_index - 1]
            assert translated.position_index == position_index
            assert [item.kind.value for item in translated.alternatives] == [
                item.kind.value for item in source_position.alternatives
            ]
            assert [item.applicability.value for item in translated.alternatives] == [
                item.applicability.value for item in source_position.alternatives
            ]
            assert [
                [memory_type.value for memory_type in item.memory_type_constraints]
                for item in translated.alternatives
            ] == [
                [memory_type.value for memory_type in item.memory_types]
                for item in source_position.alternatives
            ]


def test_deterministic_id_and_artifact_bytes(
    pattern: AProfileSemanticTriggerPattern,
) -> None:
    rebuilt = build_a_profile_semantic_trigger_pattern(
        documented_erratum_bytes=SOURCE_PATH.read_bytes()
    )

    assert rebuilt == pattern
    assert rebuilt.id == EXPECTED_PATTERN_ID
    assert serialize_a_profile_semantic_trigger_pattern(rebuilt) == (
        GENERATED_PATH.read_text(encoding="utf-8")
    )
    assert _sha256(GENERATED_PATH) == EXPECTED_ARTIFACT_SHA256


@pytest.mark.parametrize(
    ("updates", "message"),
    [
        (
            {
                "kind": "memory_load",
                "applicability": "arm_a_profile",
                "memory_type_constraints": [],
                "memory_type_semantics": "effective_architectural_memory_type",
                "memory_type_observation_requirement": (
                    "objective_effective_memory_type_required"
                ),
            },
            "requires memory-type constraints",
        ),
        (
            {
                "kind": "store_exclusive",
                "applicability": "arm_a_profile",
                "memory_type_constraints": ["device"],
                "memory_type_semantics": "effective_architectural_memory_type",
                "memory_type_observation_requirement": (
                    "objective_effective_memory_type_required"
                ),
            },
            "non-load predicates",
        ),
        (
            {
                "kind": "store_exclusive",
                "applicability": "arm_a_profile",
                "system_register": "PAR_EL1",
            },
            "cannot carry a system register",
        ),
        (
            {
                "kind": "system_register_read",
                "applicability": "privileged_aarch64",
            },
            "requires PAR_EL1",
        ),
        (
            {
                "kind": "system_register_read",
                "applicability": "arm_a_profile",
                "system_register": "PAR_EL1",
            },
            "requires privileged AArch64",
        ),
    ],
)
def test_event_predicate_shape_fails_closed(
    updates: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(ValidationError, match=message):
        AProfileSemanticEventPredicate.model_validate(updates)


def test_numeric_proximity_bound_is_rejected() -> None:
    payload = _pattern_payload()
    payload["cases"][0]["quantitative_bound"] = 4

    with pytest.raises(ValidationError, match="numeric bound"):
        AProfileSemanticTriggerPattern.model_validate(payload)


def test_case_b_normal_nc_tamper_is_rejected() -> None:
    payload = _pattern_payload()
    payload["cases"][1]["positions"][0]["alternatives"][0][
        "memory_type_constraints"
    ].append("normal_non_cacheable")

    with pytest.raises(ValidationError, match="ID does not match"):
        AProfileSemanticTriggerPattern.model_validate(payload)


@pytest.mark.parametrize(
    "forbidden_field",
    [
        "observed",
        "matched",
        "executed",
        "satisfied",
        "triggered",
        "pc",
        "instruction_address",
        "machine_code_word",
        "effective_address",
        "artifact_path",
        "runtime_register_value",
        "trace_position",
        "triggerability_status",
        "feasibility_status",
        "verification_status",
        "primary_ready",
        "score",
        "confidence",
    ],
)
def test_pattern_rejects_observation_and_outcome_fields(
    forbidden_field: str,
) -> None:
    payload = _pattern_payload()
    payload[forbidden_field] = True

    with pytest.raises(ValidationError):
        AProfileSemanticTriggerPattern.model_validate(payload)


def test_artifact_contains_no_observation_or_outcome_field_names() -> None:
    forbidden = {
        "observed",
        "matched",
        "executed",
        "satisfied",
        "triggered",
        "pc",
        "instruction_address",
        "machine_code_word",
        "effective_address",
        "artifact_path",
        "runtime_register_value",
        "trace_position",
        "triggerable",
        "triggerability_status",
        "feasibility_status",
        "verified",
        "verification_status",
        "primary_ready",
        "success",
        "pass",
        "fail",
        "score",
        "confidence",
    }

    def keys(value: object) -> set[str]:
        if isinstance(value, dict):
            return set(value).union(*(keys(item) for item in value.values()))
        if isinstance(value, list):
            return set().union(*(keys(item) for item in value))
        return set()

    assert forbidden.isdisjoint(keys(_pattern_payload()))


def test_source_artifact_byte_drift_fails_closed() -> None:
    changed = SOURCE_PATH.read_bytes().replace(b'{\n  "curation_basis"', b'{\n\n  "curation_basis"', 1)

    with pytest.raises(ValueError, match="artifact SHA-256 mismatch"):
        build_a_profile_semantic_trigger_pattern(
            documented_erratum_bytes=changed
        )


def test_source_identity_drift_fails_closed(
    source: DocumentedHardwareErratumContract,
) -> None:
    changed = source.model_copy(deep=True)
    object.__setattr__(
        changed,
        "id",
        "documented-hardware-erratum:" + "0" * 64,
    )

    with pytest.raises(ValidationError, match="ID does not match"):
        translate_documented_erratum_to_a_profile_pattern(
            changed,
            source_artifact_sha256=EXPECTED_SOURCE_SHA256,
        )


def test_source_contract_drift_fails_closed(
    source: DocumentedHardwareErratumContract,
) -> None:
    changed = source.model_copy(deep=True)
    object.__setattr__(changed, "contract", "unexpected_contract")

    with pytest.raises(ValidationError):
        translate_documented_erratum_to_a_profile_pattern(
            changed,
            source_artifact_sha256=EXPECTED_SOURCE_SHA256,
        )


def test_unexpected_source_case_count_fails_closed(
    source: DocumentedHardwareErratumContract,
) -> None:
    changed = source.model_copy(deep=True)
    object.__setattr__(
        changed,
        "program_order_cases",
        changed.program_order_cases[:1],
    )

    with pytest.raises(ValidationError):
        translate_documented_erratum_to_a_profile_pattern(
            changed,
            source_artifact_sha256=EXPECTED_SOURCE_SHA256,
        )


def test_unsupported_source_event_kind_fails_closed(
    source: DocumentedHardwareErratumContract,
) -> None:
    payload = source.model_dump(mode="json")
    payload["program_order_cases"][0]["event_1"]["alternatives"][0][
        "kind"
    ] = "branch"

    with pytest.raises(ValidationError):
        DocumentedHardwareErratumContract.model_validate(payload)


@pytest.mark.parametrize(
    "precision_field",
    [
        "unique_machine_code_sequence_defined",
        "hardware_failure_observation_present",
    ],
)
def test_translation_rejects_unsupported_source_precision_claims(
    source: DocumentedHardwareErratumContract,
    precision_field: str,
) -> None:
    changed = source.model_copy(deep=True)
    object.__setattr__(changed.source_precision, precision_field, True)

    with pytest.raises(ValidationError):
        translate_documented_erratum_to_a_profile_pattern(
            changed,
            source_artifact_sha256=EXPECTED_SOURCE_SHA256,
        )


def test_builder_reads_only_frozen_2b0_artifact() -> None:
    script = (
        ROOT
        / "scripts/build_cve_2023_34320_a_profile_semantic_trigger_pattern.py"
    ).read_text(encoding="utf-8")

    assert "cve_2023_34320_documented_erratum_1508412_v1.json" in script
    assert "public_cve/objective" not in script
    assert "erratum_1508412.source.json" not in script


def test_new_production_modules_have_dependency_firewalls() -> None:
    paths = [
        ROOT / "src/chipchain/hardware_trigger/a_profile_semantic_models.py",
        ROOT / "src/chipchain/hardware_trigger/a_profile_semantic.py",
        ROOT
        / "scripts/build_cve_2023_34320_a_profile_semantic_trigger_pattern.py",
    ]
    forbidden_import_roots = {"httpx", "requests", "socket", "urllib"}
    forbidden_contracts = (
        "TriggerabilityStatus",
        "TriggerabilityAggregationResult",
        "ChainFeasibilityStatus",
        "ChainFeasibilityAssessment",
        "VerificationRecord",
        "GroundTruth",
        "ReasoningProvider",
        "chipchain.runtime",
        "chipchain.qemu",
        "chipchain.evaluation",
    )
    for path in paths:
        text = path.read_text(encoding="utf-8")
        tree = ast.parse(text)
        imports = {
            node.names[0].name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
        }
        imports.update(
            (node.module or "").split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
        )
        assert imports.isdisjoint(forbidden_import_roots)
        assert all(item not in text for item in forbidden_contracts)


def test_no_occurrence_models_are_defined() -> None:
    from chipchain.hardware_trigger import a_profile_semantic_models

    assert not hasattr(a_profile_semantic_models, "StaticSemanticEventOccurrence")
    assert not hasattr(
        a_profile_semantic_models, "RuntimeSemanticEventObservation"
    )


def test_builder_check_accepts_committed_artifact() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "scripts/build_cve_2023_34320_a_profile_semantic_trigger_pattern.py",
            "--check",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert result.stdout == ""
    assert result.stderr == ""


def test_old_a32_contract_and_algorithm_are_unchanged() -> None:
    fixture = (
        ROOT
        / "tests/fixtures/phase9c/arm_a32_trigger_runtime/"
        "hardware_trigger_signature.json"
    )
    signature = HardwareTriggerSignature.model_validate_json(fixture.read_bytes())

    assert [item.value for item in ArmExecutionMode] == ["arm_a32"]
    assert signature.id == (
        "hardware-trigger-signature:"
        "6c40f20a04baf56570c4f2994f1859e4b4012371300c78b43143829d16bd26ba"
    )
    assert hardware_trigger_signature_id(
        architecture=signature.architecture,
        execution_mode=signature.execution_mode,
        hardware_vulnerability_id=signature.hardware_vulnerability_id,
        instruction_sequence=signature.instruction_sequence,
        preconditions=signature.preconditions,
        expected_effect=signature.expected_effect,
    ) == signature.id
    assert {item.value for item in TriggerabilityStatus} == {
        "triggerable",
        "insufficient_precondition_evidence",
        "not_observed_in_runtime",
        "no_static_trigger_match",
    }
    assert _sha256(fixture) == (
        "f770f8352d489b83c30b98dde65c5ac3f07feecac86f871b1bfa042036f9437b"
    )


def test_frozen_2b0_public_and_step8b1_artifacts_are_byte_exact() -> None:
    for relative_path, expected_sha256 in FROZEN_FILE_HASHES.items():
        assert _sha256(ROOT / relative_path) == expected_sha256
