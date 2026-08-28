"""Phase 10D Step 8B-1A public SECONDARY cohort regressions."""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from chipchain.corpus import (
    PublicCveSourceDocument,
    load_public_cve_corpus,
    load_public_cve_source,
)
from chipchain.evaluation import (
    BenchmarkCaseRunRecord,
    BenchmarkEvaluationRunner,
    BenchmarkSourceKind,
    CandidateEvaluationBundle,
    ChainFeasibilityOracle,
    ChainFeasibilityReason,
    ChainFeasibilityStatus,
    EvaluationScope,
    FinalizedCandidateRecord,
    ModelClaimBinder,
    PromptVisibilityAuditStatus,
    PublicPromptReadinessResult,
    finalized_candidate_id,
    load_public_secondary_cohort,
    load_public_secondary_selection,
    materialize_public_secondary_cohort,
    public_cve_source_record_sha256,
    public_documented_participant_id,
    serialize_public_secondary_cohort,
)
from chipchain.evaluation.experiment_models import (
    PHASE10D_PROVIDER_ROLE_ORDER,
    structured_prompt_request_sha256,
)
from chipchain.models.cross_layer import CrossLayerInteractionType
from chipchain.reasoning.enums import ReasoningPromptVisibility
from chipchain.reasoning.prompt_view import masked_chain_hidden_reference_ids
from chipchain.reasoning.prompts import RoleBasedReasoningPromptBuilder


ROOT = Path(__file__).resolve().parents[1]
SOURCE_PATH = (
    ROOT / "data/public_cve/source/arm_cross_layer_seed_v1.source.json"
)
CORPUS_PATH = ROOT / "data/public_cve/arm_cross_layer_seed_v1.json"
SELECTION_PATH = ROOT / "data/public_cve/evaluation/arm_secondary_v1.json"
COHORT_PATH = (
    ROOT / "data/evaluation/public_documented_arm_secondary_v1.json"
)
SELECTED_CVES = [
    "CVE-2022-23960",
    "CVE-2023-34320",
    "CVE-2023-52481",
    "CVE-2024-26670",
    "CVE-2025-10263",
]
FROZEN_FILE_SHA256 = {
    "data/public_cve/arm_cross_layer_seed_v1.json": (
        "f8c79abadf98e2a6a36f5e85fc6701136ba44769c22b326a7a528f45cac63d14"
    ),
    "data/public_cve/source/arm_cross_layer_seed_v1.source.json": (
        "32a1f9782a2c966123f7f7bc141adb2d82a7ee8452705e06b1d4835e00f0e848"
    ),
    "tests/fixtures/evaluation/phase10a_owned_arm.json": (
        "3adaf15659487ab4171a7765e23413d11b42093fc5760cee15c4b4ef6dab8ee4"
    ),
    "tests/fixtures/evaluation/phase10d_owned_objective_inputs.json": (
        "de3b50d6e039d1ce867d5409f6f3855bbc43f27e7670f5965f355bb0680cd9a3"
    ),
}


def _materialize():
    return materialize_public_secondary_cohort(
        source=load_public_cve_source(SOURCE_PATH),
        corpus=load_public_cve_corpus(CORPUS_PATH),
        selection=load_public_secondary_selection(SELECTION_PATH),
    )


def _candidate(case, materialized) -> FinalizedCandidateRecord:
    interaction = materialized.documented_interaction
    values = {
        "benchmark_case_id": case.id,
        "architecture": materialized.reasoning_context.architecture,
        "reasoning_session_id": f"public-secondary-session:{materialized.cve_id}",
        "reasoning_context_id": materialized.reasoning_context.id,
        "workflow_contract": "public-secondary-test-unverified-v1",
        "merged_hypothesis_id": (
            f"public-secondary-unverified-hypothesis:{materialized.cve_id}"
        ),
        "subject_id": materialized.cve_id,
        "cross_layer_interaction_id": interaction.id,
        "interaction_type": interaction.interaction_type,
        "direction": interaction.direction,
        "attack_pattern_reference": None,
        "affected_components": materialized.reasoning_context.affected_components,
        "model_authored_chain_claim": None,
    }
    identity_values = dict(values)
    identity_values.pop("model_authored_chain_claim")
    identity_values["model_authored_chain_claim_id"] = None
    return FinalizedCandidateRecord(
        id=finalized_candidate_id(**identity_values),
        model_confidence=0.0,
        metadata={},
        **values,
    )


def test_selection_is_exact_and_contains_no_technical_fact_duplication() -> None:
    raw = json.loads(SELECTION_PATH.read_text(encoding="utf-8"))
    selection = load_public_secondary_selection(SELECTION_PATH)

    assert [item.cve_id for item in selection.records] == SELECTED_CVES
    assert "CVE-2023-34321" not in SELECTED_CVES
    assert "CVE-2024-7883" not in SELECTED_CVES
    assert set(raw) == {"contract", "cohort_name", "records"}
    assert all(
        set(item) == {"cve_id", "software_source_layer"}
        for item in raw["records"]
    )
    forbidden = {
        "title",
        "summary",
        "trigger_summary",
        "precondition_summary",
        "hardware_effect_summary",
        "affected_components",
        "source_references",
        "cross_layer_classification",
    }
    assert forbidden.isdisjoint(
        key for item in raw["records"] for key in item
    )


def test_exact_source_knowledge_case_and_artifact_bindings() -> None:
    source = load_public_cve_source(SOURCE_PATH)
    corpus = load_public_cve_corpus(CORPUS_PATH)
    cohort = _materialize()
    source_by_cve = {item.cve_id: item for item in source.records}
    sample_by_cve = {item.cve_id: item for item in corpus.records}
    cases = {item.id: item for item in cohort.benchmark_manifest.cases}

    assert cohort.selected_cve_ids == SELECTED_CVES
    assert len(cohort.case_materializations) == 5
    assert cohort.source_corpus_id == corpus.id
    for materialized in cohort.case_materializations:
        record = source_by_cve[materialized.cve_id]
        sample = sample_by_cve[materialized.cve_id]
        case = cases[materialized.benchmark_case_id]
        assert materialized.knowledge_entry_id == sample.knowledge_entry_id
        assert materialized.reasoning_context.knowledge_entry_ids == [
            sample.knowledge_entry_id
        ]
        assert case.source_kind is BenchmarkSourceKind.PUBLIC_DOCUMENTED
        assert case.evaluation_scope is EvaluationScope.SECONDARY_ONLY
        assert case.artifact.artifact_type == "public_cve_source_record"
        assert case.artifact.artifact_sha256 == (
            public_cve_source_record_sha256(record)
        )
        assert case.artifact.artifact_reference.endswith(
            f"#record={record.cve_id}"
        )
        assert not case.artifact.artifact_reference.startswith(("/", "~", "\\"))
        assert case.source_reference_ids == record.source_references


def test_source_record_hash_is_canonical_and_order_independent() -> None:
    source = load_public_cve_source(SOURCE_PATH)
    record = source.records[0]
    payload = record.model_dump(mode="json")
    payload["affected_components"] = list(
        reversed(payload["affected_components"])
    )
    payload["source_references"] = list(reversed(payload["source_references"]))
    reordered = type(record).model_validate(payload)

    assert reordered == record
    assert public_cve_source_record_sha256(reordered) == (
        public_cve_source_record_sha256(record)
    )


def test_documented_interactions_are_exact_minimal_and_opaque() -> None:
    cohort = _materialize()
    expected_source_layers = {
        "CVE-2022-23960": "interface",
        "CVE-2023-34320": "interface",
        "CVE-2023-52481": "interface",
        "CVE-2024-26670": "driver",
        "CVE-2025-10263": "interface",
    }
    for materialized in cohort.case_materializations:
        interaction = materialized.documented_interaction
        expected_type = (
            CrossLayerInteractionType.FIRMWARE_VULNERABILITY_TO_HARDWARE
            if materialized.cve_id == "CVE-2024-26670"
            else CrossLayerInteractionType.FIRMWARE_BEHAVIOR_TO_HARDWARE
        )
        assert interaction.interaction_type is expected_type
        assert interaction.source_layer.value == expected_source_layers[
            materialized.cve_id
        ]
        assert bool(interaction.initiating_vulnerability_ids) is (
            materialized.cve_id == "CVE-2024-26670"
        )
        assert len(interaction.target_vulnerability_ids) == 1
        assert len(interaction.trigger_behavior_ids) == 1
        assert interaction.metadata == {}
        assert interaction.evidence_ids == []
        assert interaction.propagation_behavior_ids == []
        assert interaction.affected_execution_ids == []
        assert interaction.fault_state_ids == []
        assert interaction.hardware_resource_ids == []
        assert interaction.security_mechanism_ids == []
        participants = (
            interaction.initiating_vulnerability_ids
            + interaction.target_vulnerability_ids
            + interaction.trigger_behavior_ids
        )
        assert all(
            item.startswith("public-documented-participant:")
            and materialized.cve_id not in item
            and materialized.knowledge_entry_id != item
            for item in participants
        )
        assert public_documented_participant_id(
            materialized.cve_id, "target"
        ) == interaction.target_vulnerability_ids[0]


def test_context_and_truth_do_not_invent_objective_inputs() -> None:
    cohort = _materialize()
    cases = {item.id: item for item in cohort.benchmark_manifest.cases}
    for materialized in cohort.case_materializations:
        context = materialized.reasoning_context
        truth = cases[materialized.benchmark_case_id].ground_truth_chains[0]
        assert context.subject_id == materialized.cve_id
        assert context.cross_layer_interaction == (
            materialized.documented_interaction
        )
        assert context.runtime_observations == []
        assert context.observed_fact_ids == []
        assert context.available_evidence_ids == []
        assert context.dynamic_trigger_fact_reference is None
        assert context.attack_pattern_reference is None
        assert context.knowledge_retrieval_result is None
        assert truth.hardware_trigger_signature_id is None
        assert truth.expected_attack_pattern_reference is None
        assert truth.metadata == {
            "metric_scope": "secondary_only",
            "truth_basis": "public_documentation",
        }
        payload = materialized.model_dump(mode="json")
        assert "triggerability" not in payload
        assert "objective_materialization" not in payload


def test_full_and_masked_prompts_are_exactly_audited_from_payloads() -> None:
    source = load_public_cve_source(SOURCE_PATH)
    source_by_cve = {item.cve_id: item for item in source.records}
    cohort = _materialize()
    builder = RoleBasedReasoningPromptBuilder()

    assert cohort.readiness_result is (
        PublicPromptReadinessResult.REFERENCE_CONTENT_INSUFFICIENT
    )
    assert sum(
        assessment.visibility is ReasoningPromptVisibility.FULL_CONTEXT
        for case in cohort.case_materializations
        for assessment in case.prompt_assessments
    ) == 20
    assert sum(
        assessment.visibility
        is ReasoningPromptVisibility.MASKED_CHAIN_CONTEXT
        for case in cohort.case_materializations
        for assessment in case.prompt_assessments
    ) == 20
    for materialized in cohort.case_materializations:
        record = source_by_cve[materialized.cve_id]
        by_key = {
            (item.visibility, item.role): item
            for item in materialized.prompt_assessments
        }
        hidden = masked_chain_hidden_reference_ids(
            materialized.reasoning_context
        )
        for visibility in ReasoningPromptVisibility:
            for role in PHASE10D_PROVIDER_ROLE_ORDER:
                prompt = builder.build(
                    materialized.reasoning_context,
                    role=role,
                    visibility=visibility,
                )
                serialized = prompt.system_prompt + "\n" + prompt.user_prompt
                assessment = by_key[(visibility, role)]
                assert assessment.prompt_sha256 == (
                    structured_prompt_request_sha256(prompt)
                )
                assert assessment.cve_id_visible is (
                    record.cve_id in serialized
                )
                assert assessment.affected_components_visible is all(
                    item in serialized for item in record.affected_components
                )
                assert assessment.knowledge_entry_reference_visible is (
                    materialized.knowledge_entry_id in serialized
                )
                assert assessment.public_source_references_visible is all(
                    item in serialized for item in record.source_references
                )
                assert assessment.descriptive_public_content_visible is any(
                    item in serialized
                    for item in (
                        record.summary,
                        record.trigger_summary,
                        record.precondition_summary,
                        record.hardware_effect_summary,
                    )
                )
                assert assessment.cve_id_visible is True
                assert assessment.affected_components_visible is True
                assert assessment.knowledge_entry_reference_visible is True
                assert assessment.public_source_references_visible is False
                assert assessment.descriptive_public_content_visible is False
                if visibility is ReasoningPromptVisibility.MASKED_CHAIN_CONTEXT:
                    assert assessment.visibility_audit is not None
                    assert assessment.visibility_audit.status is (
                        PromptVisibilityAuditStatus.PASS
                    )
                    assert assessment.visibility_audit.leaked_reference_ids == []
                    assert all(item not in serialized for item in hidden)
                else:
                    assert assessment.visibility_audit is None


def test_missing_triggerability_keeps_all_public_cases_unresolved() -> None:
    cohort = _materialize()
    cases = {item.id: item for item in cohort.benchmark_manifest.cases}
    oracle = ChainFeasibilityOracle()

    for materialized in cohort.case_materializations:
        case = cases[materialized.benchmark_case_id]
        assessment = oracle.assess(
            _candidate(case, materialized),
            case.artifact,
            candidate_interaction=materialized.documented_interaction,
            triggerability=None,
        )
        assert assessment.status is ChainFeasibilityStatus.UNRESOLVED
        assert ChainFeasibilityReason.TRIGGERABILITY_RESULT_MISSING in (
            assessment.reason_codes
        )
        if materialized.cve_id == "CVE-2024-26670":
            type_i_gap = (
                ChainFeasibilityReason.TYPE_I_SOFTWARE_VULNERABILITY_TO_TRIGGER_LINK_NOT_IMPLEMENTED
            )
            assert type_i_gap in assessment.reason_codes
        else:
            assert assessment.reason_codes == [
                ChainFeasibilityReason.TRIGGERABILITY_RESULT_MISSING
            ]


def test_secondary_cases_never_enter_primary_metrics_or_flags() -> None:
    cohort = _materialize()
    cases = {item.id: item for item in cohort.benchmark_manifest.cases}
    oracle = ChainFeasibilityOracle()
    binder = ModelClaimBinder()
    runs: list[BenchmarkCaseRunRecord] = []

    for materialized in cohort.case_materializations:
        case = cases[materialized.benchmark_case_id]
        candidate = _candidate(case, materialized)
        feasibility = oracle.assess(
            candidate,
            case.artifact,
            candidate_interaction=materialized.documented_interaction,
        )
        bundle = CandidateEvaluationBundle.create(
            candidate=candidate,
            claim_binding=binder.assess(
                candidate,
                materialized.documented_interaction,
            ),
            feasibility=feasibility,
        )
        runs.append(BenchmarkCaseRunRecord.from_candidate(bundle))

    report = BenchmarkEvaluationRunner().evaluate(
        cohort.benchmark_manifest,
        runs,
    )
    assert len(report.candidate_assessments) == 5
    assert all(not item.strict_hit for item in report.candidate_assessments)
    assert all(
        not item.negative_control_false_positive
        for item in report.candidate_assessments
    )
    assert report.verification_hit_rate.denominator == 0
    assert report.ground_truth_chain_recall.denominator == 0
    assert report.negative_control_false_positive_rate.denominator == 0
    assert report.primary_case_coverage.denominator == 0


def test_generated_artifact_is_deterministic_and_script_check_passes() -> None:
    first = _materialize()
    second = _materialize()
    committed = load_public_secondary_cohort(COHORT_PATH)
    selection = load_public_secondary_selection(SELECTION_PATH)
    selection_payload = selection.model_dump(mode="json")
    selection_payload["records"] = list(
        reversed(selection_payload["records"])
    )
    reordered = materialize_public_secondary_cohort(
        source=load_public_cve_source(SOURCE_PATH),
        corpus=load_public_cve_corpus(CORPUS_PATH),
        selection=type(selection).model_validate(selection_payload),
    )
    result = subprocess.run(
        [
            sys.executable,
            "scripts/build_public_secondary_cohort.py",
            "--check",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert first == second == reordered == committed
    assert serialize_public_secondary_cohort(first) == (
        COHORT_PATH.read_text(encoding="utf-8")
    )
    assert result.returncode == 0
    assert result.stdout == ""
    assert result.stderr == ""


def test_materializer_has_no_provider_network_or_qemu_dependency() -> None:
    paths = [
        ROOT / "src/chipchain/evaluation/public_secondary.py",
        ROOT / "src/chipchain/evaluation/public_secondary_models.py",
        ROOT / "scripts/build_public_secondary_cohort.py",
    ]
    forbidden_import_fragments = (
        "chipchain.reasoning.provider",
        "chipchain.runtime.qemu",
        "requests",
        "urllib",
        "httpx",
        "socket",
    )
    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imports = [
            node.module or ""
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
        ] + [
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        ]
        assert all(
            fragment not in imported
            for imported in imports
            for fragment in forbidden_import_fragments
        )


def test_frozen_source_corpus_and_owned_fixtures_are_byte_unchanged() -> None:
    for relative_path, expected in FROZEN_FILE_SHA256.items():
        actual = hashlib.sha256((ROOT / relative_path).read_bytes()).hexdigest()
        assert actual == expected
