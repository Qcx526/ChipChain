"""Phase 10D Step 8B-1B public knowledge projection regressions."""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest
from pydantic import ValidationError

from chipchain.agents.base import ReasoningContext
from chipchain.corpus import load_public_cve_corpus
from chipchain.evaluation import (
    PHASE10D_PROVIDER_ROLE_ORDER,
    PHASE10D_PUBLIC_KNOWLEDGE_LEAKAGE_AUDIT_CONTRACT,
    PHASE10D_PUBLIC_KNOWLEDGE_READINESS_CONTRACT,
    PromptVisibilityAuditStatus,
    PublicKnowledgeLeakageAuditStatus,
    PublicKnowledgeLeakageAuditor,
    PublicPromptReadinessResult,
    load_public_knowledge_readiness,
    load_public_secondary_cohort,
    materialize_public_knowledge_readiness,
    serialize_public_knowledge_readiness,
    structured_prompt_request_sha256,
)
from chipchain.knowledge.models import (
    KnowledgeEntryKind,
    VulnerabilityKnowledgeEntry,
)
from chipchain.models import Architecture
from chipchain.reasoning.enums import (
    ReasoningAgentType,
    ReasoningPromptVisibility,
)
from chipchain.reasoning.knowledge_projection import (
    PHASE10D_PUBLIC_KNOWLEDGE_CONTENT_PROJECTION_CONTRACT,
    KnowledgeContentProjection,
    ProjectedKnowledgeEntry,
)
from chipchain.reasoning.models import StructuredPromptRequest
from chipchain.reasoning.prompt_view import masked_chain_hidden_reference_ids
from chipchain.reasoning.prompts import RoleBasedReasoningPromptBuilder


ROOT = Path(__file__).resolve().parents[1]
CORPUS_PATH = ROOT / "data/public_cve/arm_cross_layer_seed_v1.json"
FROZEN_COHORT_PATH = (
    ROOT / "data/evaluation/public_documented_arm_secondary_v1.json"
)
READINESS_PATH = (
    ROOT
    / "data/evaluation/public_documented_arm_secondary_knowledge_projection_v1.json"
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
    "data/public_cve/evaluation/arm_secondary_v1.json": (
        "ad4b500e004d5ccfce127df4ff918498a520485bc7891d5cb028e1837dcffa00"
    ),
    "data/evaluation/public_documented_arm_secondary_v1.json": (
        "893944a10820ac91abd15ee176894e2caa9f1ac0c774b2ef9124b2e76c3f3ae7"
    ),
    "tests/fixtures/evaluation/phase10a_owned_arm.json": (
        "3adaf15659487ab4171a7765e23413d11b42093fc5760cee15c4b4ef6dab8ee4"
    ),
    "tests/fixtures/evaluation/phase10d_owned_objective_inputs.json": (
        "de3b50d6e039d1ce867d5409f6f3855bbc43f27e7670f5965f355bb0680cd9a3"
    ),
}


@pytest.fixture(scope="module")
def corpus():
    return load_public_cve_corpus(CORPUS_PATH)


@pytest.fixture(scope="module")
def frozen_cohort():
    return load_public_secondary_cohort(FROZEN_COHORT_PATH)


@pytest.fixture(scope="module")
def readiness(corpus, frozen_cohort):
    return materialize_public_knowledge_readiness(
        frozen_cohort=frozen_cohort,
        corpus=corpus,
    )


def _case(frozen_cohort, cve_id: str):
    return next(
        item
        for item in frozen_cohort.case_materializations
        if item.cve_id == cve_id
    )


def _entry(corpus, entry_id: str) -> VulnerabilityKnowledgeEntry:
    return next(item for item in corpus.knowledge_entries if item.id == entry_id)


def _projection(corpus, materialized) -> KnowledgeContentProjection:
    return KnowledgeContentProjection.create(
        materialized.reasoning_context,
        [_entry(corpus, materialized.knowledge_entry_id)],
    )


def _all_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value).union(*(_all_keys(item) for item in value.values()))
    if isinstance(value, list):
        return set().union(*(_all_keys(item) for item in value))
    return set()


def test_projection_contract_and_allowed_shape(corpus, frozen_cohort) -> None:
    materialized = _case(frozen_cohort, "CVE-2023-34320")
    projection = _projection(corpus, materialized)
    projected = projection.entries[0]

    assert PHASE10D_PUBLIC_KNOWLEDGE_CONTENT_PROJECTION_CONTRACT == (
        "phase10d_public_knowledge_content_projection_v1"
    )
    assert set(ProjectedKnowledgeEntry.model_fields) == {
        "entry_id",
        "entry_kind",
        "external_id",
        "architecture",
        "title",
        "summary",
        "affected_components",
        "references",
    }
    assert set(KnowledgeContentProjection.model_fields) == {
        "id",
        "contract",
        "architecture",
        "reasoning_context_id",
        "entries",
    }
    assert "metadata" not in projected.model_dump(mode="json")
    assert "metadata" not in projection.model_dump(mode="json")
    assert projected.entry_id == materialized.knowledge_entry_id
    assert projection.reasoning_context_id == materialized.reasoning_context.id


def test_exact_five_context_entry_bindings(corpus, frozen_cohort) -> None:
    assert [item.cve_id for item in frozen_cohort.case_materializations] == (
        SELECTED_CVES
    )
    for materialized in frozen_cohort.case_materializations:
        projection = _projection(corpus, materialized)
        assert len(projection.entries) == 1
        assert [item.entry_id for item in projection.entries] == (
            materialized.reasoning_context.knowledge_entry_ids
        )
        assert projection.entries[0].external_id == materialized.cve_id
        assert projection.architecture is Architecture.ARM


def test_missing_extra_duplicate_and_mismatched_entries_fail_closed(
    corpus,
    frozen_cohort,
) -> None:
    materialized = _case(frozen_cohort, "CVE-2023-34320")
    context = materialized.reasoning_context
    entry = _entry(corpus, materialized.knowledge_entry_id)
    other = next(item for item in corpus.knowledge_entries if item.id != entry.id)

    with pytest.raises(ValueError, match="exactly match"):
        KnowledgeContentProjection.create(context, [])
    with pytest.raises(ValueError, match="exactly match"):
        KnowledgeContentProjection.create(context, [entry, other])
    with pytest.raises(ValueError, match="must be unique"):
        KnowledgeContentProjection.create(context, [entry, entry])

    other_arch_entry = VulnerabilityKnowledgeEntry.create(
        entry_kind=KnowledgeEntryKind.CVE,
        external_id="CVE-2099-9001",
        architecture=Architecture.RISC_V,
        title="Fixture architecture mismatch",
        summary="Fixture-only architecture mismatch reference.",
    )
    other_arch_context = ReasoningContext.create(
        architecture=Architecture.ARM,
        subject_id=other_arch_entry.external_id,
        affected_components=["fixture component"],
        knowledge_entry_ids=[other_arch_entry.id],
    )
    with pytest.raises(ValueError, match="architecture mismatch"):
        KnowledgeContentProjection.create(
            other_arch_context,
            [other_arch_entry],
        )


def test_non_cve_missing_architecture_and_stale_identity_fail_closed() -> None:
    cwe = VulnerabilityKnowledgeEntry.create(
        entry_kind=KnowledgeEntryKind.CWE,
        external_id="CWE-999",
        architecture=None,
        title="Fixture global weakness",
        summary="Fixture-only global weakness reference.",
    )
    cwe_context = ReasoningContext.create(
        architecture=Architecture.ARM,
        subject_id=cwe.external_id,
        affected_components=["fixture component"],
        knowledge_entry_ids=[cwe.id],
    )
    with pytest.raises(ValueError, match="CVE entries only"):
        KnowledgeContentProjection.create(cwe_context, [cwe])

    missing_arch = VulnerabilityKnowledgeEntry.model_construct(
        id="vulnerability-knowledge-entry:invalid",
        entry_kind=KnowledgeEntryKind.CVE,
        external_id="CVE-2099-9002",
        architecture=None,
        title="Fixture missing architecture",
        summary="Fixture-only missing architecture reference.",
        affected_components=[],
        references=[],
        metadata={},
    )
    missing_context = ReasoningContext.create(
        architecture=Architecture.ARM,
        subject_id=missing_arch.external_id,
        affected_components=["fixture component"],
        knowledge_entry_ids=[missing_arch.id],
    )
    with pytest.raises(ValidationError, match="declare an architecture"):
        KnowledgeContentProjection.create(missing_context, [missing_arch])

    valid = VulnerabilityKnowledgeEntry.create(
        entry_kind=KnowledgeEntryKind.CVE,
        external_id="CVE-2099-9003",
        architecture=Architecture.ARM,
        title="Fixture valid entry",
        summary="Fixture-only valid reference.",
    )
    stale = valid.model_copy(update={"summary": "Changed without a new ID"})
    valid_context = ReasoningContext.create(
        architecture=Architecture.ARM,
        subject_id=valid.external_id,
        affected_components=["fixture component"],
        knowledge_entry_ids=[valid.id],
    )
    with pytest.raises(ValidationError, match="not deterministic"):
        KnowledgeContentProjection.create(valid_context, [stale])


def test_projection_and_prompt_determinism_and_order_independence(corpus) -> None:
    first_entry, second_entry = corpus.knowledge_entries[:2]
    context = ReasoningContext.create(
        architecture=Architecture.ARM,
        subject_id="fixture-two-entry-public-context",
        affected_components=["fixture component"],
        knowledge_entry_ids=[first_entry.id, second_entry.id],
    )
    first = KnowledgeContentProjection.create(
        context,
        [first_entry, second_entry],
    )
    reversed_projection = KnowledgeContentProjection.create(
        context,
        [second_entry, first_entry],
    )
    builder = RoleBasedReasoningPromptBuilder()
    first_prompt = builder.build_with_knowledge_projection(
        context,
        role=ReasoningAgentType.CODE,
        visibility=ReasoningPromptVisibility.FULL_CONTEXT,
        knowledge_projection=first,
    )
    second_prompt = builder.build_with_knowledge_projection(
        context,
        role=ReasoningAgentType.CODE,
        visibility=ReasoningPromptVisibility.FULL_CONTEXT,
        knowledge_projection=reversed_projection,
    )

    assert first == reversed_projection
    assert first.id == reversed_projection.id
    assert first_prompt == second_prompt
    assert structured_prompt_request_sha256(first_prompt) == (
        structured_prompt_request_sha256(second_prompt)
    )


def test_recreated_content_mutation_changes_entry_projection_and_prompt() -> None:
    original = VulnerabilityKnowledgeEntry.create(
        entry_kind=KnowledgeEntryKind.CVE,
        external_id="CVE-2099-9004",
        architecture=Architecture.ARM,
        title="Fixture original title",
        summary="Fixture original summary.",
    )
    changed = VulnerabilityKnowledgeEntry.create(
        entry_kind=KnowledgeEntryKind.CVE,
        external_id=original.external_id,
        architecture=original.architecture,
        title=original.title,
        summary="Fixture changed summary.",
    )
    original_context = ReasoningContext.create(
        architecture=Architecture.ARM,
        subject_id=original.external_id,
        affected_components=["fixture component"],
        knowledge_entry_ids=[original.id],
    )
    changed_context = ReasoningContext.create(
        architecture=Architecture.ARM,
        subject_id=changed.external_id,
        affected_components=["fixture component"],
        knowledge_entry_ids=[changed.id],
    )
    original_projection = KnowledgeContentProjection.create(
        original_context,
        [original],
    )
    changed_projection = KnowledgeContentProjection.create(
        changed_context,
        [changed],
    )
    builder = RoleBasedReasoningPromptBuilder()
    original_prompt = builder.build_with_knowledge_projection(
        original_context,
        role=ReasoningAgentType.CODE,
        visibility=ReasoningPromptVisibility.FULL_CONTEXT,
        knowledge_projection=original_projection,
    )
    changed_prompt = builder.build_with_knowledge_projection(
        changed_context,
        role=ReasoningAgentType.CODE,
        visibility=ReasoningPromptVisibility.FULL_CONTEXT,
        knowledge_projection=changed_projection,
    )

    assert changed.id != original.id
    assert changed_projection.id != original_projection.id
    assert structured_prompt_request_sha256(changed_prompt) != (
        structured_prompt_request_sha256(original_prompt)
    )


def test_legacy_public_prompt_hash_is_byte_compatible(frozen_cohort) -> None:
    materialized = _case(frozen_cohort, "CVE-2022-23960")
    builder = RoleBasedReasoningPromptBuilder()
    legacy = builder.build(
        materialized.reasoning_context,
        role=ReasoningAgentType.CODE,
        visibility=ReasoningPromptVisibility.FULL_CONTEXT,
    )
    payload = json.loads(legacy.user_prompt)

    assert structured_prompt_request_sha256(legacy) == (
        "88c63efe325d53117738e8cca5e230e476b2c2489f6e487b7e7785db990fc883"
    )
    assert "knowledge_reference_content" not in payload
    assert "knowledge_content_projection_contract" not in payload
    assert "knowledge_content_projection_id" not in payload


def test_projected_full_and_masked_prompts_are_visible_and_isolated(
    corpus,
    frozen_cohort,
    readiness,
) -> None:
    builder = RoleBasedReasoningPromptBuilder()
    entry_by_id = {item.id: item for item in corpus.knowledge_entries}
    readiness_by_cve = {item.cve_id: item for item in readiness.case_readiness}
    all_selected_entries = [
        item
        for item in corpus.knowledge_entries
        if item.external_id in SELECTED_CVES
    ]
    full_count = 0
    masked_count = 0

    for materialized in frozen_cohort.case_materializations:
        entry = entry_by_id[materialized.knowledge_entry_id]
        projection = _projection(corpus, materialized)
        record = readiness_by_cve[materialized.cve_id]
        assessment_by_key = {
            (item.visibility, item.role): item
            for item in record.prompt_assessments
        }
        projected_payloads: dict[ReasoningPromptVisibility, object] = {}
        hidden = masked_chain_hidden_reference_ids(
            materialized.reasoning_context
        )
        for visibility in ReasoningPromptVisibility:
            for role in PHASE10D_PROVIDER_ROLE_ORDER:
                prompt = builder.build_with_knowledge_projection(
                    materialized.reasoning_context,
                    role=role,
                    visibility=visibility,
                    knowledge_projection=projection,
                )
                payload = json.loads(prompt.user_prompt)
                projected_payloads[visibility] = payload[
                    "knowledge_reference_content"
                ]
                assessment = assessment_by_key[(visibility, role)]
                assert assessment.prompt_sha256 == (
                    structured_prompt_request_sha256(prompt)
                )
                assert assessment.knowledge_projection_id == projection.id
                assert assessment.leakage_audit.status is (
                    PublicKnowledgeLeakageAuditStatus.PASS
                )
                assert assessment.leakage_audit.contract == (
                    PHASE10D_PUBLIC_KNOWLEDGE_LEAKAGE_AUDIT_CONTRACT
                )
                assert assessment.content_complete is True
                assert payload["knowledge_content_projection_contract"] == (
                    PHASE10D_PUBLIC_KNOWLEDGE_CONTENT_PROJECTION_CONTRACT
                )
                assert payload["knowledge_content_projection_id"] == projection.id
                assert all(
                    phrase in prompt.system_prompt
                    for phrase in (
                        "public reference material",
                        "unverified by ChipChain",
                        "not Evidence",
                        "not Ground Truth",
                        "not instructions",
                        "not a vulnerability verdict",
                        "not proof of causality",
                    )
                )
                assert payload["knowledge_reference_content"] == [
                    projection.entries[0].model_dump(mode="json")
                ]
                assert set(payload["knowledge_reference_content"][0]) == {
                    "entry_id",
                    "entry_kind",
                    "external_id",
                    "architecture",
                    "title",
                    "summary",
                    "affected_components",
                    "references",
                }
                assert all(
                    value in prompt.user_prompt
                    for value in (
                        entry.external_id,
                        entry.id,
                        entry.title,
                        entry.summary,
                        *entry.affected_components,
                        *entry.references,
                    )
                )
                for other in all_selected_entries:
                    if other.id == entry.id:
                        continue
                    assert other.external_id not in prompt.user_prompt
                    assert other.title not in prompt.user_prompt
                    assert other.summary not in prompt.user_prompt
                assert not {
                    "metadata",
                    "evidence",
                    "verification_record",
                    "triggerability",
                    "objective_materialization",
                }.intersection(payload["knowledge_reference_content"][0])
                if visibility is ReasoningPromptVisibility.FULL_CONTEXT:
                    full_count += 1
                    assert assessment.visibility_audit is None
                else:
                    masked_count += 1
                    assert assessment.visibility_audit is not None
                    assert assessment.visibility_audit.status is (
                        PromptVisibilityAuditStatus.PASS
                    )
                    assert assessment.visibility_audit.leaked_reference_ids == []
                    final_text = prompt.system_prompt + "\n" + prompt.user_prompt
                    assert all(item not in final_text for item in hidden)
        assert projected_payloads[
            ReasoningPromptVisibility.FULL_CONTEXT
        ] == projected_payloads[
            ReasoningPromptVisibility.MASKED_CHAIN_CONTEXT
        ]
    assert full_count == 20
    assert masked_count == 20


def test_forbidden_structured_labels_are_absent_and_auditor_detects_tamper(
    corpus,
    frozen_cohort,
) -> None:
    materialized = _case(frozen_cohort, "CVE-2023-34320")
    projection = _projection(corpus, materialized)
    prompt = RoleBasedReasoningPromptBuilder().build_with_knowledge_projection(
        materialized.reasoning_context,
        role=ReasoningAgentType.CODE,
        visibility=ReasoningPromptVisibility.FULL_CONTEXT,
        knowledge_projection=projection,
    )
    payload = json.loads(prompt.user_prompt)
    forbidden = {
        "cross_layer_classification",
        "underlying_issue_key",
        "trigger_summary",
        "precondition_summary",
        "hardware_effect_summary",
        "admission_status",
        "admission_blockers",
        "evaluation_scope",
        "ground_truth_chains",
        "hardware_trigger_signature_id",
        "expected_attack_pattern_reference",
    }
    assert forbidden.isdisjoint(_all_keys(payload))

    payload["evaluation_scope"] = "secondary_only"
    payload["neutral_note"] = "type_ii_candidate"
    tampered = StructuredPromptRequest(
        candidate_id=prompt.candidate_id,
        architecture=prompt.architecture,
        role=prompt.role,
        schema_name=prompt.schema_name,
        system_prompt=prompt.system_prompt,
        user_prompt=json.dumps(payload, sort_keys=True, separators=(",", ":")),
    )
    audit = PublicKnowledgeLeakageAuditor.audit(
        tampered,
        forbidden_exact_values=["type_ii_candidate"],
    )
    assert audit.status is PublicKnowledgeLeakageAuditStatus.LEAK_DETECTED
    assert audit.detected_forbidden_field_names == ["evaluation_scope"]
    assert audit.detected_forbidden_value_sha256s == [
        hashlib.sha256(b"type_ii_candidate").hexdigest()
    ]


def test_readiness_artifact_is_deterministic_ready_and_frozen_bound(
    corpus,
    frozen_cohort,
    readiness,
) -> None:
    second = materialize_public_knowledge_readiness(
        frozen_cohort=frozen_cohort,
        corpus=corpus,
    )
    committed = load_public_knowledge_readiness(READINESS_PATH)
    frozen_by_cve = {
        item.cve_id: item for item in frozen_cohort.case_materializations
    }

    assert readiness == second == committed
    assert readiness.contract == PHASE10D_PUBLIC_KNOWLEDGE_READINESS_CONTRACT
    assert readiness.readiness_result is (
        PublicPromptReadinessResult.READY_FOR_PUBLIC_PROVIDER
    )
    assert readiness.selected_cve_ids == SELECTED_CVES
    assert serialize_public_knowledge_readiness(readiness) == (
        READINESS_PATH.read_text(encoding="utf-8")
    )
    for record in readiness.case_readiness:
        frozen = frozen_by_cve[record.cve_id]
        assert record.benchmark_case_id == frozen.benchmark_case_id
        assert record.documented_interaction_id == (
            frozen.documented_interaction.id
        )
        assert record.reasoning_context_id == frozen.reasoning_context.id
        assert record.knowledge_entry_id == frozen.knowledge_entry_id


def test_readiness_builder_check_and_no_raw_prompt_storage() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "scripts/build_public_knowledge_readiness.py",
            "--check",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    raw = READINESS_PATH.read_text(encoding="utf-8")

    assert result.returncode == 0
    assert result.stdout == ""
    assert result.stderr == ""
    assert '"system_prompt"' not in raw
    assert '"user_prompt"' not in raw
    assert '"provider_response"' not in raw
    assert '"model_output"' not in raw


def test_frozen_inputs_are_byte_exact() -> None:
    for relative_path, expected in FROZEN_FILE_SHA256.items():
        actual = hashlib.sha256((ROOT / relative_path).read_bytes()).hexdigest()
        assert actual == expected


def test_new_projection_path_has_no_provider_network_or_qemu_dependency() -> None:
    paths = [
        ROOT / "src/chipchain/reasoning/knowledge_projection.py",
        ROOT / "src/chipchain/evaluation/public_knowledge_readiness.py",
        ROOT / "src/chipchain/evaluation/public_knowledge_readiness_models.py",
        ROOT / "scripts/build_public_knowledge_readiness.py",
    ]
    forbidden_imports = (
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
            for fragment in forbidden_imports
        )
