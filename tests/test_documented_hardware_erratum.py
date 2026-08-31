"""Phase 10D Step 8B-2B0 documented-erratum contract tests."""

from __future__ import annotations

import ast
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest
from pydantic import ValidationError

from chipchain.hardware_trigger import (
    PHASE10D_DOCUMENTED_ERRATUM_SOURCE_CONTRACT,
    PHASE10D_DOCUMENTED_HARDWARE_ERRATUM_CONTRACT,
    AdditionalTimingConditionPrecision,
    CpuRevisionDisposition,
    DocumentedEffectModality,
    DocumentedErratumObjectiveUse,
    DocumentedErratumSourceDocument,
    DocumentedHardwareEffectKind,
    DocumentedHardwareErratumContract,
    DocumentedMemoryType,
    DocumentedMitigationKind,
    DocumentedMitigationSemantics,
    DocumentedOperationApplicability,
    DocumentedProgramRelation,
    DocumentedRelationPrecision,
    DocumentedSemanticEventKind,
    HardwareTriggerSignature,
    build_documented_hardware_erratum,
    load_documented_erratum_source,
    serialize_documented_hardware_erratum,
)


ROOT = Path(__file__).resolve().parents[1]
CURATION_PATH = (
    ROOT
    / "data/public_cve/objective/"
    "cve_2023_34320_erratum_1508412.source.json"
)
PUBLIC_SOURCE_PATH = (
    ROOT / "data/public_cve/source/arm_cross_layer_seed_v1.source.json"
)
GENERATED_PATH = (
    ROOT
    / "data/evaluation/"
    "cve_2023_34320_documented_erratum_1508412_v1.json"
)
EXPECTED_PUBLIC_SOURCE_FILE_SHA256 = (
    "32a1f9782a2c966123f7f7bc141adb2d82a7ee8452705e06b1d4835e00f0e848"
)
EXPECTED_PUBLIC_SOURCE_RECORD_SHA256 = (
    "980a723600d6288617bf924fcc9e6a95e89079c498d8890286c6bb01e43c5a42"
)
EXPECTED_CORPUS_ID = (
    "public-cve-corpus:"
    "778765c51a0d9b939eb37b390367a3d0"
    "cd02720942c8746c19eb0a1c38930e49"
)
EXPECTED_ID = (
    "documented-hardware-erratum:"
    "8ad52bee747242179997fd58989c92f419ff051f618682e07e158d00a787096c"
)
EXPECTED_ARTIFACT_SHA256 = (
    "bd50b8b50313041c3d5245cccaf51a0d4d479914033ad233d79a740180b0c5a1"
)
FROZEN_FILE_HASHES = {
    "data/public_cve/source/arm_cross_layer_seed_v1.source.json": (
        EXPECTED_PUBLIC_SOURCE_FILE_SHA256
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
    "data/evaluation/runs/phase10d_step8b1d_public_deepseek_20260831_one_shot.json": (
        "5bf1f1268b90a8a7eaf17bb52846ae64f2edc752ec904b3db3125fc0efafdedd"
    ),
    "data/evaluation/runs/phase10d_step8b1d_public_deepseek_20260831_offline_summary.json": (
        "d022b22be95269a601c5a263e7e4cd5844f93b53fec93055c3aac089a053df99"
    ),
    "data/evaluation/public_documented_arm_secondary_masked_semantic_recovery_v1.json": (
        "425cb9c29a2ce21114938e63d917e815f3aeef917395199d1e914ca6d86bc9e5"
    ),
}


@pytest.fixture(scope="module")
def source() -> DocumentedErratumSourceDocument:
    return load_documented_erratum_source(CURATION_PATH)


@pytest.fixture(scope="module")
def contract(
    source: DocumentedErratumSourceDocument,
) -> DocumentedHardwareErratumContract:
    return build_documented_hardware_erratum(
        source,
        public_source_bytes=PUBLIC_SOURCE_PATH.read_bytes(),
    )


def _source_payload() -> dict[str, object]:
    return json.loads(CURATION_PATH.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_exact_contract_and_authoritative_source_identity(
    source: DocumentedErratumSourceDocument,
    contract: DocumentedHardwareErratumContract,
) -> None:
    authoritative = contract.authoritative_source

    assert source.contract == PHASE10D_DOCUMENTED_ERRATUM_SOURCE_CONTRACT
    assert contract.contract == PHASE10D_DOCUMENTED_HARDWARE_ERRATUM_CONTRACT
    assert contract.id == EXPECTED_ID
    assert contract.cve_id == "CVE-2023-34320"
    assert authoritative.vendor == "Arm"
    assert authoritative.document_id == "SDEN-1152370"
    assert authoritative.document_version == "11.0"
    assert authoritative.issue_date.isoformat() == "2020-09-01"
    assert authoritative.erratum_id == "1508412"
    assert authoritative.section_title == (
        "NC/Device Load and Store Exclusive or PAR-Read collision can cause deadlock"
    )
    assert authoritative.source_kind.value == "vendor_errata_notice"
    assert authoritative.source_access_status.value == (
        "publicly_accessible_at_curation"
    )
    assert authoritative.source_locator == (
        "arm-document:SDEN-1152370:11.0:erratum-1508412"
    )
    assert "?" not in authoritative.source_locator
    assert "token" not in authoritative.source_locator.lower()


def test_exact_cpu_revision_semantics(
    contract: DocumentedHardwareErratumContract,
) -> None:
    dispositions = {
        item.revision: item.disposition for item in contract.revision_records
    }

    assert dispositions == {
        "r0p0": CpuRevisionDisposition.AFFECTED,
        "r1p0": CpuRevisionDisposition.AFFECTED,
        "r1p1": CpuRevisionDisposition.FIXED,
    }
    assert contract.configurations == "all_configurations"


def test_case_a_exact_program_order_and_alternatives(
    contract: DocumentedHardwareErratumContract,
) -> None:
    case = contract.program_order_cases[0]

    assert case.case_id == "case_a"
    assert {item.kind for item in case.event_1.alternatives} == {
        DocumentedSemanticEventKind.STORE_EXCLUSIVE,
        DocumentedSemanticEventKind.SYSTEM_REGISTER_READ,
    }
    load = case.event_2.alternatives[0]
    assert load.kind is DocumentedSemanticEventKind.MEMORY_LOAD
    assert set(load.memory_types) == {
        DocumentedMemoryType.DEVICE,
        DocumentedMemoryType.NORMAL_NON_CACHEABLE,
    }


def test_case_b_exact_program_order_and_device_only_load(
    contract: DocumentedHardwareErratumContract,
) -> None:
    case = contract.program_order_cases[1]

    assert case.case_id == "case_b"
    load = case.event_1.alternatives[0]
    assert load.kind is DocumentedSemanticEventKind.MEMORY_LOAD
    assert load.memory_types == [DocumentedMemoryType.DEVICE]
    assert {item.kind for item in case.event_2.alternatives} == {
        DocumentedSemanticEventKind.STORE_EXCLUSIVE,
        DocumentedSemanticEventKind.SYSTEM_REGISTER_READ,
    }
    par_read = next(
        item
        for item in case.event_2.alternatives
        if item.kind is DocumentedSemanticEventKind.SYSTEM_REGISTER_READ
    )
    assert par_read.system_register == "PAR_EL1"
    assert par_read.applicability is (
        DocumentedOperationApplicability.PRIVILEGED_AARCH64
    )
    store_exclusive = next(
        item
        for item in case.event_2.alternatives
        if item.kind is DocumentedSemanticEventKind.STORE_EXCLUSIVE
    )
    assert store_exclusive.applicability is (
        DocumentedOperationApplicability.ARM_A_PROFILE
    )


def test_precision_effect_mitigation_and_objective_boundaries(
    contract: DocumentedHardwareErratumContract,
) -> None:
    for case in contract.program_order_cases:
        assert case.relation is DocumentedProgramRelation.CLOSE_PROXIMITY
        assert case.relation_precision is (
            DocumentedRelationPrecision.QUALITATIVE_ONLY
        )
        assert case.quantitative_bound is None
    assert contract.additional_timing_condition_precision is (
        AdditionalTimingConditionPrecision.UNSPECIFIED_BY_PUBLIC_SOURCE
    )
    assert contract.documented_effect.kind is (
        DocumentedHardwareEffectKind.CORE_DEADLOCK
    )
    assert contract.documented_effect.modality is DocumentedEffectModality.POSSIBLE
    assert all(
        item.semantics is DocumentedMitigationSemantics.DOCUMENTED_MITIGATION
        for item in contract.documented_mitigations
    )
    assert {item.kind for item in contract.documented_mitigations} == set(
        DocumentedMitigationKind
    )
    assert contract.objective_use is (
        DocumentedErratumObjectiveUse.SEMANTIC_PATTERN_REFERENCE_ONLY
    )

    payload = contract.model_dump(mode="json")
    serialized = json.dumps(payload, sort_keys=True).lower()
    assert "system_deadlock" not in serialized
    assert "instruction_sequence" not in serialized
    assert "executable_workaround" not in serialized
    assert "triggerable" not in serialized
    assert "confirmed_feasible" not in serialized
    assert "primary_ready" not in serialized
    assert "verified" not in serialized


def test_source_precision_declarations_are_exact(
    contract: DocumentedHardwareErratumContract,
) -> None:
    assert contract.source_precision.model_dump(mode="json") == {
        "program_order_defined": True,
        "quantitative_proximity_bound_defined": False,
        "additional_timing_conditions_fully_defined": False,
        "unique_machine_code_sequence_defined": False,
        "effective_memory_type_resolution_defined": False,
        "runtime_environment_defined": False,
        "hardware_failure_observation_present": False,
    }


def test_frozen_public_cve_binding_is_exact(
    contract: DocumentedHardwareErratumContract,
) -> None:
    assert contract.public_source_file_sha256 == (
        EXPECTED_PUBLIC_SOURCE_FILE_SHA256
    )
    assert contract.public_source_record_sha256 == (
        EXPECTED_PUBLIC_SOURCE_RECORD_SHA256
    )
    assert contract.public_corpus_id == EXPECTED_CORPUS_ID


def test_deterministic_identity_and_artifact_bytes(
    source: DocumentedErratumSourceDocument,
    contract: DocumentedHardwareErratumContract,
) -> None:
    second = build_documented_hardware_erratum(
        source,
        public_source_bytes=PUBLIC_SOURCE_PATH.read_bytes(),
    )

    assert second == contract
    assert second.id == contract.id == EXPECTED_ID
    assert serialize_documented_hardware_erratum(second) == (
        serialize_documented_hardware_erratum(contract)
    )
    assert serialize_documented_hardware_erratum(contract) == (
        GENERATED_PATH.read_text(encoding="utf-8")
    )
    assert _sha256(GENERATED_PATH) == EXPECTED_ARTIFACT_SHA256


@pytest.mark.parametrize(
    "mutation",
    [
        "wrong_cve",
        "wrong_erratum",
        "duplicate_revision",
        "r1p1_affected",
        "missing_affected_revision",
        "case_a_reversed",
        "case_a_missing_normal_nc",
        "case_b_reversed",
        "case_b_broadened",
        "unordered_case",
        "invented_quantitative_bound",
        "missing_relation",
        "guaranteed_effect",
        "system_deadlock_effect",
        "exact_machine_code_claim",
        "experimental_proof",
        "transient_source_query",
        "frozen_file_hash_mismatch",
        "frozen_record_hash_mismatch",
        "frozen_corpus_id_mismatch",
        "verdict_metadata",
        "metric_metadata",
    ],
)
def test_source_contract_fails_closed_on_semantic_broadening(
    mutation: str,
) -> None:
    payload = copy.deepcopy(_source_payload())
    cases = payload["program_order_cases"]
    revisions = payload["revision_records"]
    if mutation == "wrong_cve":
        payload["cve_id"] = "CVE-2023-34321"
    elif mutation == "wrong_erratum":
        payload["authoritative_source"]["erratum_id"] = "1508413"
    elif mutation == "duplicate_revision":
        revisions[1] = copy.deepcopy(revisions[0])
    elif mutation == "r1p1_affected":
        revisions[2]["disposition"] = "affected"
    elif mutation == "missing_affected_revision":
        revisions.pop(0)
    elif mutation == "case_a_reversed":
        cases[0]["event_1"], cases[0]["event_2"] = (
            cases[0]["event_2"],
            cases[0]["event_1"],
        )
    elif mutation == "case_a_missing_normal_nc":
        cases[0]["event_2"]["alternatives"][0]["memory_types"] = ["device"]
    elif mutation == "case_b_reversed":
        cases[1]["event_1"], cases[1]["event_2"] = (
            cases[1]["event_2"],
            cases[1]["event_1"],
        )
    elif mutation == "case_b_broadened":
        cases[1]["event_1"]["alternatives"][0]["memory_types"].append(
            "normal_non_cacheable"
        )
    elif mutation == "unordered_case":
        cases[0]["events"] = [cases[0].pop("event_1"), cases[0].pop("event_2")]
    elif mutation == "invented_quantitative_bound":
        cases[0]["quantitative_bound"] = 4
    elif mutation == "missing_relation":
        cases[0].pop("relation")
    elif mutation == "guaranteed_effect":
        payload["documented_effect"]["modality"] = "guaranteed"
    elif mutation == "system_deadlock_effect":
        payload["documented_effect"]["kind"] = "system_deadlock"
    elif mutation == "exact_machine_code_claim":
        payload["source_precision"]["unique_machine_code_sequence_defined"] = True
    elif mutation == "experimental_proof":
        payload["hardware_trigger_proof"] = {"kind": "assertion_violation"}
    elif mutation == "transient_source_query":
        payload["authoritative_source"]["source_locator"] += "?token=secret"
    elif mutation == "frozen_file_hash_mismatch":
        payload["public_source_file_sha256"] = "0" * 64
    elif mutation == "frozen_record_hash_mismatch":
        payload["public_source_record_sha256"] = "0" * 64
    elif mutation == "frozen_corpus_id_mismatch":
        payload["public_corpus_id"] = "public-cve-corpus:" + "0" * 64
    elif mutation == "verdict_metadata":
        payload["metadata"] = {"verification_status": "verified"}
    elif mutation == "metric_metadata":
        payload["metadata"] = {"hit_rate": 1.0}

    with pytest.raises(ValidationError):
        DocumentedErratumSourceDocument.model_validate(payload)


def test_public_source_mismatch_fails_closed(
    source: DocumentedErratumSourceDocument,
) -> None:
    changed = PUBLIC_SOURCE_PATH.read_bytes().replace(
        b"Cortex-A77 erratum 1508412 software-triggered deadlock",
        b"Cortex-A77 erratum 1508412 changed title",
        1,
    )

    with pytest.raises(ValueError, match="source file SHA-256 mismatch"):
        build_documented_hardware_erratum(source, public_source_bytes=changed)


def test_generated_contract_rejects_semantic_id_tampering(
    contract: DocumentedHardwareErratumContract,
) -> None:
    payload = contract.model_dump(mode="json")
    payload["id"] = "documented-hardware-erratum:" + "0" * 64

    with pytest.raises(ValidationError, match="ID does not match"):
        DocumentedHardwareErratumContract.model_validate(payload)


def test_builder_has_ground_truth_provider_qemu_network_import_firewall() -> None:
    paths = [
        ROOT
        / "src/chipchain/hardware_trigger/documented_erratum_models.py",
        ROOT / "src/chipchain/hardware_trigger/documented_erratum.py",
        ROOT / "scripts/build_cve_2023_34320_documented_erratum.py",
    ]
    forbidden_import_roots = {
        "httpx",
        "requests",
        "socket",
        "urllib",
    }
    forbidden_fragments = (
        "GroundTruth",
        "ReasoningProvider",
        "Qemu",
        "qemu",
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
        assert all(fragment not in text for fragment in forbidden_fragments)


def test_builder_check_accepts_committed_artifact() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "scripts/build_cve_2023_34320_documented_erratum.py",
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


def test_frozen_public_and_step8b1_artifacts_are_byte_exact() -> None:
    for relative_path, expected_sha256 in FROZEN_FILE_HASHES.items():
        assert _sha256(ROOT / relative_path) == expected_sha256


def test_existing_a32_trigger_contract_identity_is_unchanged() -> None:
    path = (
        ROOT
        / "tests/fixtures/phase9c/arm_a32_trigger_runtime/"
        "hardware_trigger_signature.json"
    )
    signature = HardwareTriggerSignature.model_validate_json(path.read_bytes())

    assert signature.id == (
        "hardware-trigger-signature:"
        "6c40f20a04baf56570c4f2994f1859e4b4012371300c78b43143829d16bd26ba"
    )
