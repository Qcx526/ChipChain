"""Offline Phase 10D Step 6 objective-input materialization tests."""

from __future__ import annotations

import ast
import hashlib
import json
import shutil
from pathlib import Path

import pytest
from pydantic import ValidationError

from chipchain.analysis import ProgramArtifact
from chipchain.evaluation import (
    ExperimentExecutionMode,
    ObjectiveExperimentCaseSource,
    ObjectiveExperimentInputSourceSet,
    ObjectiveInputMaterializationError,
    ObjectiveTriggerabilityMaterializationRecord,
    ObjectiveTriggerabilitySource,
    Phase10DObjectiveInputMaterializer,
    RealExperimentCaseInput,
    RealExperimentExecutionError,
    RealExperimentInputSet,
    RealModelExecutionArchive,
    RealModelExperimentExecutor,
    real_experiment_case_input_id,
)
from chipchain.hardware_trigger import (
    AngrFirmwareTriggerMatcher,
    ArmExecutionMode,
    FirmwareTriggerMatcher,
    HardwareTriggerSignature,
    StaticFirmwareTriggerMatch,
    StaticFirmwareTriggerMatchResult,
    TriggerabilityStatus,
)
from chipchain.models import Architecture
from chipchain.runtime.qemu import (
    QemuTriggerRawTraceParser,
    QemuTriggerRunnerError,
    normalize_qemu_trigger_trace,
)
from tests.test_phase10d_real_execution import (
    _CountingProvider,
    _offline_real_provider,
    _plan_and_inputs,
)


ROOT = Path(__file__).resolve().parents[1]
SOURCE_FIXTURE = (
    ROOT / "tests/fixtures/evaluation/phase10d_owned_objective_inputs.json"
)
ARTIFACT_REFERENCE = Path(
    "tests/fixtures/phase9c/arm_a32_trigger_runtime/"
    "arm_a32_trigger_runtime.elf"
)
SIGNATURE_REFERENCE = Path(
    "tests/fixtures/phase9c/arm_a32_trigger_runtime/"
    "hardware_trigger_signature.json"
)
RAW_REFERENCE = Path(
    "tests/fixtures/qemu_trigger_raw/valid_arm_a32_trigger_trace.jsonl"
)
EXPECTED_STATIC_IDS = [
    "static-firmware-trigger-match:"
    "069987f861581eb35ec38f90c8c3fc27bd3091d2cf1d7fbdd96ab6aee3cf543f",
    "static-firmware-trigger-match:"
    "e05ba197df4ea563afe35e185d88b9ecda4483fda30b7b5b1d5b53094d14182c",
]
EXPECTED_RUNTIME_TRACE_ID = (
    "runtime-trigger-execution-trace:"
    "1225c5404ef186469fcdf3f531f5c592a37c4e9e5a444dbb5c3011106e3623d5"
)
EXPECTED_RUNTIME_OCCURRENCE_ID = (
    "runtime-firmware-trigger-occurrence:"
    "2831dd7e559620e401ac72bc0001b3a0786644a2daee7da0f753b8a9d7ec2a78"
)
EXPECTED_STATIC_SHA256 = (
    "351bd7dc83a194ab38b4b9ac06454834ee9afb417d2076c294ec5f027a9e7b32"
)
EXPECTED_RUNTIME_SHA256 = (
    "b86ddea32c67ecd389ccb1d422596e0bb5e0c78bfffda32b7375526e94d416aa"
)
EXPECTED_AGGREGATION_ID = (
    "triggerability-aggregation:"
    "8e4643645b8333faff524da54676f0aa7e5a403ea430674ec1d730d41b74495a"
)


def _source_set() -> ObjectiveExperimentInputSourceSet:
    return ObjectiveExperimentInputSourceSet.model_validate_json(
        SOURCE_FIXTURE.read_text(encoding="utf-8")
    )


def _objective_case() -> ObjectiveExperimentCaseSource:
    return next(
        item for item in _source_set().case_sources
        if item.triggerability_source is not None
    )


def _control_case() -> ObjectiveExperimentCaseSource:
    return next(
        item for item in _source_set().case_sources
        if item.triggerability_source is None
    )


def _source_copy(**changes: object) -> ObjectiveTriggerabilitySource:
    source = _objective_case().triggerability_source
    assert source is not None
    values = source.model_dump(mode="python", exclude={"id"})
    values.update(changes)
    return ObjectiveTriggerabilitySource.create(**values)


def _case_with_source(
    source: ObjectiveTriggerabilitySource,
    *,
    context=None,
) -> ObjectiveExperimentCaseSource:
    base = _objective_case()
    return ObjectiveExperimentCaseSource.create(
        benchmark_case_id=base.benchmark_case_id,
        reasoning_context=context or base.reasoning_context,
        triggerability_source=source,
    )


class _FixtureStaticMatcher(FirmwareTriggerMatcher):
    """Ground-Truth-free deterministic test seam for ordinary unit tests."""

    def _match_detached(
        self,
        artifact: ProgramArtifact,
        signature: HardwareTriggerSignature,
    ) -> StaticFirmwareTriggerMatchResult:
        assert artifact.path is not None
        artifact_sha256 = hashlib.sha256(Path(artifact.path).read_bytes()).hexdigest()
        matches = []
        for function_name, function_address in (
            ("executed_trigger", "0x40200018"),
            ("not_called_trigger", "0x40200028"),
        ):
            start = int(function_address, 16)
            matches.append(
                StaticFirmwareTriggerMatch.create(
                    artifact_id=artifact.id,
                    artifact_sha256=artifact_sha256,
                    signature_id=signature.id,
                    hardware_vulnerability_id=(
                        signature.hardware_vulnerability_id
                    ),
                    architecture=signature.architecture,
                    execution_mode=signature.execution_mode,
                    function_address=function_address,
                    function_name=function_name,
                    instruction_locations=[
                        {
                            "instruction_address": f"0x{start + index * 4:08x}",
                            "instruction_word": word,
                            "basic_block_address": function_address,
                        }
                        for index, word in enumerate(
                            signature.instruction_sequence
                        )
                    ],
                    basic_block_path=[function_address],
                )
            )
        return StaticFirmwareTriggerMatchResult(
            artifact_id=artifact.id,
            artifact_sha256=artifact_sha256,
            signature_id=signature.id,
            hardware_vulnerability_id=signature.hardware_vulnerability_id,
            architecture=signature.architecture,
            execution_mode=signature.execution_mode,
            matches=matches,
            diagnostics=["owned_synthetic_test_seam"],
        )


def _materializer() -> Phase10DObjectiveInputMaterializer:
    return Phase10DObjectiveInputMaterializer(
        static_matcher=_FixtureStaticMatcher()
    )


def _offline_materialized_input_set():
    manifest, plan, _ = _plan_and_inputs()
    inputs = _materializer().materialize_input_set(
        plan, _source_set(), fixture_root=ROOT
    )
    return manifest, plan, inputs


def _objective_input(inputs: RealExperimentInputSet) -> RealExperimentCaseInput:
    return next(item for item in inputs.case_inputs if item.triggerability is not None)


def _copy_source_files(tmp_path: Path) -> Path:
    for reference in (ARTIFACT_REFERENCE, SIGNATURE_REFERENCE, RAW_REFERENCE):
        target = tmp_path / reference
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / reference, target)
    return tmp_path


def test_source_identity_and_case_cohort_are_deterministic_and_order_neutral() -> None:
    source_set = _source_set()
    rebuilt = ObjectiveExperimentInputSourceSet.create(
        case_sources=list(reversed(source_set.case_sources))
    )
    source = _objective_case().triggerability_source
    assert source is not None
    reordered = dict(reversed(list(source.model_dump(exclude={"id"}).items())))
    rebuilt_source = ObjectiveTriggerabilitySource.create(**reordered)

    assert rebuilt == source_set
    assert rebuilt.model_dump_json() == source_set.model_dump_json()
    assert rebuilt_source == source


@pytest.mark.parametrize(
    "reference",
    [
        "/home/example/firmware.elf",
        "C:/fixture/firmware.elf",
        "../firmware.elf",
        "tests/fixtures/../firmware.elf",
    ],
)
def test_source_rejects_absolute_and_traversal_paths(reference: str) -> None:
    with pytest.raises(ValueError, match="path-neutral"):
        _source_copy(artifact_reference=reference)


def test_materializer_rejects_symlink_escape_from_fixture_root(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside.elf"
    outside.write_bytes((ROOT / ARTIFACT_REFERENCE).read_bytes())
    (root / "escape.elf").symlink_to(outside)
    source = _source_copy(artifact_reference="escape.elf")

    with pytest.raises(ObjectiveInputMaterializationError, match="escapes"):
        _materializer().materialize_case_input(
            _plan_and_inputs()[1], _case_with_source(source), fixture_root=root
        )


@pytest.mark.parametrize(
    ("reference", "message"),
    [
        (ARTIFACT_REFERENCE, "artifact SHA-256"),
        (SIGNATURE_REFERENCE, "signature file SHA-256"),
        (RAW_REFERENCE, "raw trace SHA-256"),
    ],
)
def test_materializer_rejects_tampered_source_bytes(
    tmp_path: Path, reference: Path, message: str
) -> None:
    root = _copy_source_files(tmp_path)
    path = root / reference
    path.write_bytes(path.read_bytes() + b"\n")

    with pytest.raises(ObjectiveInputMaterializationError, match=message):
        _materializer().materialize_case_input(
            _plan_and_inputs()[1], _objective_case(), fixture_root=root
        )


def test_signature_semantic_id_mismatch_fails_closed() -> None:
    source = _source_copy(
        expected_signature_id="hardware-trigger-signature:different"
    )

    with pytest.raises(ObjectiveInputMaterializationError, match="semantic ID"):
        _materializer().materialize_case_input(
            _plan_and_inputs()[1], _case_with_source(source), fixture_root=ROOT
        )


def test_raw_trace_run_id_mismatch_fails_closed(tmp_path: Path) -> None:
    root = _copy_source_files(tmp_path)
    raw_path = root / RAW_REFERENCE
    records = [
        json.loads(line) for line in raw_path.read_text("utf-8").splitlines()
    ]
    records[0]["run_id"] = "different-owned-run"
    raw_path.write_text(
        "\n".join(json.dumps(item, separators=(",", ":")) for item in records)
        + "\n",
        encoding="utf-8",
    )
    source = _source_copy(
        expected_raw_trace_sha256=hashlib.sha256(raw_path.read_bytes()).hexdigest()
    )

    with pytest.raises(ObjectiveInputMaterializationError, match="run ID"):
        _materializer().materialize_case_input(
            _plan_and_inputs()[1], _case_with_source(source), fixture_root=root
        )


def test_context_interaction_and_hardware_target_mismatch_fail_closed() -> None:
    with pytest.raises(ValueError, match="interaction mismatch"):
        _case_with_source(
            _source_copy(candidate_interaction_id="cross-layer-interaction:other")
        )
    with pytest.raises(ValueError, match="hardware target mismatch"):
        _case_with_source(
            _source_copy(hardware_vulnerability_id="different-hardware-target")
        )


def test_architecture_and_execution_mode_mismatch_fail_closed() -> None:
    with pytest.raises(ValueError, match="ARM only"):
        _source_copy(architecture=Architecture.RISC_V)
    with pytest.raises(ValueError):
        _source_copy(execution_mode="thumb_t32")


def test_source_cannot_declare_status_or_derived_output() -> None:
    payload = _objective_case().triggerability_source.model_dump(mode="json")
    payload["status"] = "triggerable"
    with pytest.raises(ValidationError, match="Extra inputs"):
        ObjectiveTriggerabilitySource.model_validate(payload)
    assert {
        "expected_aggregation_id",
        "expected_static_match_ids",
        "expected_runtime_occurrence_ids",
        "expected_triggerability_status",
    }.isdisjoint(ObjectiveTriggerabilitySource.model_fields)


def test_public_normalizer_is_pure_exact_and_run_bound() -> None:
    source = _objective_case().triggerability_source
    assert source is not None
    parsed = QemuTriggerRawTraceParser().parse(ROOT / RAW_REFERENCE)
    trace = normalize_qemu_trigger_trace(
        parsed,
        run_id=source.expected_run_id,
        scenario_id=source.scenario_id,
        artifact_id=source.artifact_id,
        artifact_sha256=source.expected_artifact_sha256,
    )

    assert trace.id == EXPECTED_RUNTIME_TRACE_ID
    assert trace.metadata == {
        "execution_scope": "declared_arm_a32",
        "observation_scope": "runtime_trigger_sequence_t_only",
    }
    with pytest.raises(QemuTriggerRunnerError, match="run ID"):
        normalize_qemu_trigger_trace(
            parsed,
            run_id="different-run",
            scenario_id=source.scenario_id,
            artifact_id=source.artifact_id,
            artifact_sha256=source.expected_artifact_sha256,
        )


def test_owned_positive_uses_full_pipeline_and_derives_exact_output() -> None:
    pytest.importorskip("angr")
    _, plan, _ = _plan_and_inputs()
    item = Phase10DObjectiveInputMaterializer(
        static_matcher=AngrFirmwareTriggerMatcher()
    ).materialize_case_input(plan, _objective_case(), fixture_root=ROOT)
    trigger = item.triggerability
    record = item.objective_materialization

    assert trigger is not None and record is not None
    assert trigger.status is TriggerabilityStatus.TRIGGERABLE
    assert trigger.id == EXPECTED_AGGREGATION_ID
    assert trigger.static_match_ids == EXPECTED_STATIC_IDS
    assert trigger.trace_id == EXPECTED_RUNTIME_TRACE_ID
    assert trigger.runtime_occurrence_ids == [EXPECTED_RUNTIME_OCCURRENCE_ID]
    assert trigger.static_result_sha256 == EXPECTED_STATIC_SHA256
    assert trigger.runtime_result_sha256 == EXPECTED_RUNTIME_SHA256
    assert record.triggerability_aggregation_id == trigger.id


def test_control_case_remains_without_objective_result() -> None:
    _, plan, _ = _plan_and_inputs()
    item = _materializer().materialize_case_input(
        plan, _control_case(), fixture_root=ROOT
    )

    assert item.reasoning_context.cross_layer_interaction is None
    assert item.reasoning_context.attack_pattern_reference is None
    assert item.reasoning_context.dynamic_trigger_fact_reference is None
    assert item.triggerability is None
    assert item.objective_materialization is None


def test_source_fixture_contains_no_truth_label_or_outcome_keys() -> None:
    payload = json.loads(SOURCE_FIXTURE.read_text(encoding="utf-8"))
    forbidden_fragments = {
        "ground_truth",
        "label",
        "evaluation_scope",
        "expected_hit",
        "expected_feasibility",
        "expected_triggerability",
    }

    def visit(value: object) -> None:
        if isinstance(value, dict):
            for key, nested in value.items():
                normalized = str(key).lower()
                assert all(item not in normalized for item in forbidden_fragments)
                visit(nested)
        elif isinstance(value, list):
            for nested in value:
                visit(nested)

    visit(payload)


def test_production_objective_modules_have_import_and_path_firewall() -> None:
    modules = [
        ROOT / "src/chipchain/evaluation/objective_input_models.py",
        ROOT / "src/chipchain/evaluation/objective_input_materialization.py",
    ]
    forbidden_imports = {
        "BenchmarkManifest",
        "EvaluationBenchmarkCase",
        "GroundTruthChain",
        "BenchmarkEvaluationRunner",
        "ContextObjectiveUpperBoundEvaluator",
    }
    forbidden_paths = {
        "phase10a_owned_arm.json",
        "ground_truth.json",
    }
    for module in modules:
        source = module.read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        assert forbidden_imports.isdisjoint(imported)
        assert all(item not in source for item in forbidden_paths)
    materializer_source = modules[1].read_text(encoding="utf-8")
    assert "QemuTriggerSequenceRunner" not in materializer_source
    assert "subprocess" not in materializer_source
    assert "Provider" not in materializer_source


def test_materializer_does_not_read_truth_or_manifest_files(monkeypatch) -> None:
    _, plan, _ = _plan_and_inputs()
    opened: list[str] = []
    original_open = Path.open
    original_read_bytes = Path.read_bytes

    def tracked_open(path, *args, **kwargs):
        opened.append(path.as_posix())
        return original_open(path, *args, **kwargs)

    def tracked_read_bytes(path):
        opened.append(path.as_posix())
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "open", tracked_open)
    monkeypatch.setattr(Path, "read_bytes", tracked_read_bytes)
    _materializer().materialize_case_input(
        plan, _objective_case(), fixture_root=ROOT
    )

    assert all("phase10a_owned_arm.json" not in item for item in opened)
    assert all(
        not item.endswith("arm_a32_trigger_runtime/ground_truth.json")
        for item in opened
    )


def test_legacy_case_input_without_materialization_preserves_exact_id() -> None:
    _, plan, inputs = _offline_materialized_input_set()
    objective = _objective_input(inputs)
    legacy = RealExperimentCaseInput.create(
        plan,
        benchmark_case_id=objective.benchmark_case_id,
        reasoning_context=objective.reasoning_context,
        triggerability=objective.triggerability,
    )
    payload = legacy.model_dump(
        mode="json", exclude={"objective_materialization"}
    )
    restored = RealExperimentCaseInput.model_validate(payload)

    assert restored.id == legacy.id
    assert restored.objective_materialization is None
    assert objective.id != legacy.id
    assert objective.id == RealExperimentCaseInput.model_validate(
        objective.model_dump(mode="json")
    ).id


def test_materialization_triggerability_cross_wire_is_rejected() -> None:
    _, plan, inputs = _offline_materialized_input_set()
    objective = _objective_input(inputs)
    record = objective.objective_materialization
    assert record is not None and objective.triggerability is not None
    values = record.model_dump(mode="python", exclude={"id"})
    values["triggerability_aggregation_id"] = (
        "triggerability-aggregation:different"
    )
    cross_wired = ObjectiveTriggerabilityMaterializationRecord.create(**values)
    input_id = real_experiment_case_input_id(
        experiment_plan_id=plan.id,
        benchmark_case_id=objective.benchmark_case_id,
        reasoning_context_id=objective.reasoning_context.id,
        triggerability_aggregation_id=objective.triggerability.id,
        objective_materialization_id=cross_wired.id,
    )

    with pytest.raises(ValidationError, match="triggerability mismatch"):
        RealExperimentCaseInput.model_validate(
            {
                **objective.model_dump(mode="json"),
                "id": input_id,
                "objective_materialization": cross_wired.model_dump(mode="json"),
            }
        )


def test_real_provider_create_requires_materialization_but_offline_allows_legacy(
) -> None:
    _, _, offline_inputs = _offline_materialized_input_set()
    objective = _objective_input(offline_inputs)
    _, real_plan, _ = _plan_and_inputs(
        execution_mode=ExperimentExecutionMode.REAL_PROVIDER
    )

    with pytest.raises(ValueError, match="requires objective materialization"):
        RealExperimentCaseInput.create(
            real_plan,
            benchmark_case_id=objective.benchmark_case_id,
            reasoning_context=objective.reasoning_context,
            triggerability=objective.triggerability,
        )
    assert objective.triggerability is not None


def test_complete_real_provider_inputs_materialize_without_provider_call() -> None:
    _, real_plan, _ = _plan_and_inputs(
        execution_mode=ExperimentExecutionMode.REAL_PROVIDER
    )

    inputs = _materializer().materialize_input_set(
        real_plan, _source_set(), fixture_root=ROOT
    )

    objective = _objective_input(inputs)
    assert objective.objective_materialization is not None
    assert objective.triggerability is not None
    assert objective.triggerability.status is TriggerabilityStatus.TRIGGERABLE


def test_executor_rejects_legacy_real_bypass_before_provider_calls() -> None:
    _, _, offline_inputs = _offline_materialized_input_set()
    objective = _objective_input(offline_inputs)
    manifest, real_plan, source_inputs = _plan_and_inputs(
        execution_mode=ExperimentExecutionMode.REAL_PROVIDER
    )
    legacy_payload = {
        "id": real_experiment_case_input_id(
            experiment_plan_id=real_plan.id,
            benchmark_case_id=objective.benchmark_case_id,
            reasoning_context_id=objective.reasoning_context.id,
            triggerability_aggregation_id=objective.triggerability.id,
        ),
        "experiment_plan_id": real_plan.id,
        "benchmark_case_id": objective.benchmark_case_id,
        "reasoning_context": objective.reasoning_context.model_dump(mode="json"),
        "triggerability": objective.triggerability.model_dump(mode="json"),
        "metadata": {},
    }
    legacy_objective = RealExperimentCaseInput.model_validate(legacy_payload)
    remaining = [
        item for item in source_inputs.case_inputs
        if item.benchmark_case_id != legacy_objective.benchmark_case_id
    ]
    real_inputs = RealExperimentInputSet.create(
        real_plan, case_inputs=[legacy_objective, *remaining]
    )
    provider, client = _offline_real_provider()

    with pytest.raises(
        RealExperimentExecutionError,
        match="requires objective materialization",
    ):
        RealModelExperimentExecutor(provider=provider).execute(
            real_plan, manifest, real_inputs
        )
    assert client.completions.calls == []
    assert client.responses.calls == []


def test_archive_roundtrip_persists_provenance_without_host_paths() -> None:
    manifest, plan, inputs = _offline_materialized_input_set()
    archive = RealModelExperimentExecutor(
        provider=_CountingProvider()
    ).execute(plan, manifest, inputs)
    restored = RealModelExecutionArchive.model_validate_json(
        archive.model_dump_json()
    )
    objective = _objective_input(restored.input_set)
    serialized = restored.model_dump_json()

    assert restored == archive
    assert objective.objective_materialization is not None
    assert (
        objective.objective_materialization.source.id
        == _objective_case().triggerability_source.id
    )
    assert str(ROOT) not in serialized
    assert "raw_trace_bytes" not in serialized
    assert "elf_bytes" not in serialized
