"""B2-A source-only identity, vocabulary, and detached provenance regressions."""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import runpy

import pytest
from pydantic import ValidationError

from chipchain.verification.candidate_state_observation_models import (
    CandidateEffectiveMemoryTypeObservation as Memory,
    CandidateExecutionContextObservation as Context,
    CandidateStateObservationMaterialization as Materialization,
    CandidateStateObservationSourceManifest as Manifest,
    CandidateStateOwnedFixtureProvenance,
    candidate_state_observation_id,
)


ROOT = Path(__file__).resolve().parents[1]
RUNNER = runpy.run_path(str(ROOT / "scripts/export_candidate_state_observations.py"))


@pytest.fixture
def source():
    return RUNNER["build_owned_candidate_state_observations"]()


def _values(value):
    return value.model_dump(mode="json", exclude={"id", "contract"})


def _rehash(payload):
    # Prefix is preserved; the complete normalized payload, not a stale hash,
    # is presented to the authoritative validator in every adversarial test.
    payload["id"] = candidate_state_observation_id(
        payload["id"].split(":", 1)[0], {k: v for k, v in payload.items() if k != "id"}
    )
    return payload


def _rehash_bundle(payload):
    for field in ("effective_memory_type_observations", "execution_context_observations"):
        payload[field].sort(key=lambda record: record["id"])
    return _rehash(payload)


def test_roundtrip_and_independent_empty_source(source):
    for obj in [source, source.source_manifest_snapshot, *source.effective_memory_type_observations, *source.execution_context_observations]:
        assert type(obj).model_validate_json(obj.model_dump_json()) == obj
    empty = Materialization.create(source_manifest_snapshot=source.source_manifest_snapshot)
    assert empty.effective_memory_type_observations == empty.execution_context_observations == []


@pytest.mark.parametrize("model, field, expected", [
    (Manifest, "source_kind", ["owned_fixture", "external_typed_observation"]),
    (Manifest, "source_semantics", ["objective_typed_source_only"]),
    (Memory, "observation_semantics", ["objective_source_observation_only"]),
    (Context, "observation_semantics", ["objective_source_observation_only"]),
    (Memory, "access_address_kind", ["virtual_address", "physical_address"]),
    (Memory, "resolution_basis", ["direct_typed_source", "audited_translation_resolution"]),
])
def test_exact_v1_json_schema(model, field, expected):
    schema = model.model_json_schema()["properties"][field]
    assert schema.get("enum", [schema.get("const")]) == expected
    assert "$ref" not in schema


def test_stable_identifier_and_locator_json_schema_patterns_are_exact():
    manifest = Manifest.model_json_schema()["properties"]
    stable_pattern = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$"
    for field in (
        "source_artifact_id",
        "producer_profile_id",
        "producer_profile_version",
        "normalization_profile_id",
    ):
        assert manifest[field]["pattern"] == stable_pattern
    locator = Memory.model_json_schema()["properties"]["source_record_locator"]
    assert locator["pattern"] == r"^record:[a-z0-9][a-z0-9._-]{0,127}$"


@pytest.mark.parametrize("field, bad", [
    ("source_kind", "trusted_source"), ("source_semantics", "verified"),
    ("source_artifact_sha256", "A" * 64), ("source_artifact_sha256", "a" * 63),
    ("source_artifact_sha256", "a" * 64 + "\n"), ("artifact_sha256", "A" * 64),
    ("producer_profile_id", " "), ("producer_profile_version", ""),
    ("normalization_profile_id", ""), ("source_artifact_id", ""),
])
def test_manifest_invalid_fields(source, field, bad):
    with pytest.raises(ValidationError):
        Manifest.create(**{**_values(source.source_manifest_snapshot), field: bad})


@pytest.mark.parametrize(("field", "bad"), [
    ("source_artifact_id", "/tmp/source.json"),
    ("source_artifact_id", "~/source"),
    ("source_artifact_id", "file:///tmp/source"),
    ("source_artifact_id", "file:relative-source"),
    ("producer_profile_id", r"C:\machine\profile"),
    ("producer_profile_id", "C:/machine/profile"),
    ("producer_profile_id", "C:machine-profile"),
    ("normalization_profile_id", "../profile"),
    ("normalization_profile_id", "./profile"),
    ("producer_profile_version", "versions/v1"),
    ("producer_profile_version", " v1"),
    ("producer_profile_version", "v1 "),
    ("producer_profile_id", "producer\nprofile"),
    ("normalization_profile_id", "normalization\tprofile"),
])
def test_stable_source_identifiers_reject_host_local_values(
    source, field, bad
):
    with pytest.raises(ValidationError, match="stable and path/whitespace free"):
        Manifest.create(
            **{**_values(source.source_manifest_snapshot), field: bad}
        )


def test_fixed_uuid_and_date_shaped_semantic_identifiers_are_accepted(source):
    values = _values(source.source_manifest_snapshot)
    fixed_uuid = "550e8400-e29b-41d4-a716-446655440000"
    changed = Manifest.create(
        **{
            **values,
            "source_artifact_id": fixed_uuid,
            "producer_profile_version": "2026-09-07T01:02:03Z",
        }
    )
    assert changed.source_artifact_id == fixed_uuid
    assert changed.producer_profile_version == "2026-09-07T01:02:03Z"
    assert changed.id != source.source_manifest_snapshot.id


def test_owned_flags_and_external_source_kind(source):
    values = _values(source.source_manifest_snapshot)
    with pytest.raises(ValidationError):
        Manifest.create(**{**values, "owned_fixture_provenance": None})
    with pytest.raises(ValidationError):
        Manifest.create(**{**values, "source_kind": "external_typed_observation"})
    external = Manifest.create(**{**values, "source_kind": "external_typed_observation", "owned_fixture_provenance": None})
    assert external.source_kind == "external_typed_observation"
    flags = values["owned_fixture_provenance"]
    for key in flags:
        for invalid in (False, 1, "true", None):
            with pytest.raises(ValidationError):
                CandidateStateOwnedFixtureProvenance.model_validate({**flags, key: invalid})
        with pytest.raises(ValidationError):
            CandidateStateOwnedFixtureProvenance.model_validate({k: v for k, v in flags.items() if k != key})


@pytest.mark.parametrize("field, value", [
    ("access_address", "0x80000000"), ("access_address", {"value": "80000000"}),
    ("access_address", None), ("access_address_kind", "unknown"),
    ("observed_effective_memory_type_id", ""), ("resolution_basis", "static_guess"),
    ("observation_semantics", "runtime_verified"), ("instruction_address", "not-hex"),
    ("source_record_locator", ""),
])
def test_memory_requires_explicit_typed_values(source, field, value):
    with pytest.raises(ValidationError):
        Memory.create(**{**_values(source.effective_memory_type_observations[0]), field: value})


@pytest.mark.parametrize(
    ("family", "field", "bad"),
    [
        ("effective_memory_type_observations", "observed_effective_memory_type_id", "/tmp/memory-type"),
        ("effective_memory_type_observations", "observed_effective_memory_type_id", "file:memory-type"),
        ("execution_context_observations", "observed_execution_context_ids", [r"C:\context"]),
        ("execution_context_observations", "observed_execution_context_ids", ["context\tlocal"]),
    ],
)
def test_normalized_value_identifiers_share_source_hygiene(
    source, family, field, bad
):
    observation = getattr(source, family)[0]
    with pytest.raises(ValidationError, match="stable and path/whitespace free"):
        type(observation).create(**{**_values(observation), field: bad})


def test_addresses_context_set_and_neutral_namespaces(source):
    memory = source.effective_memory_type_observations[0]
    normalized = Memory.create(**{**_values(memory), "instruction_address": "0x00400008", "access_address": {"value": "0x000080000000"}})
    assert normalized == memory
    context = source.execution_context_observations[0]
    assert Context.create(**{**_values(context), "observed_execution_context_ids": list(reversed(context.observed_execution_context_ids))}) == context
    for values in ([], ["same", "same"], ["same", " same "], [""]):
        with pytest.raises(ValidationError):
            Context.create(**{**_values(context), "observed_execution_context_ids": values})
    # The generic vocabulary does not prescribe architectural privilege labels.
    arbitrary = Context.create(**{**_values(context), "observed_execution_context_ids": ["owned-synthetic-context-A"]})
    assert arbitrary.id != context.id


@pytest.mark.parametrize("value", ["0x00001000", "0X00001000"])
def test_access_address_canonical_hex_alignment(value):
    from chipchain.verification.candidate_state_observation_models import (
        CandidateStateAccessAddress,
    )

    assert CandidateStateAccessAddress.model_validate({"value": value}).value == "0x1000"


@pytest.mark.parametrize("value", [4096, -1, "-0x1", "", "1000", "not-an-address"])
def test_access_address_rejects_non_hex_address_values(value):
    from chipchain.verification.candidate_state_observation_models import (
        CandidateStateAccessAddress,
    )

    with pytest.raises(ValidationError):
        CandidateStateAccessAddress.model_validate({"value": value})


@pytest.mark.parametrize(
    "locator",
    ["record:000001", "record:event-42", "record:cpu0.step17"],
)
def test_source_record_locator_accepts_canonical_v1_tokens(source, locator):
    memory = Memory.create(
        **{
            **_values(source.effective_memory_type_observations[0]),
            "source_record_locator": locator,
        }
    )
    assert memory.source_record_locator == locator


@pytest.mark.parametrize(
    "locator",
    [
        "/tmp/source.json",
        "~/source",
        "C:/source",
        r"C:\source",
        "line:42",
        "record:",
        "record:UPPER",
        "record:contains space",
        "record:a/b",
        r"record:a\b",
        "record:.leading-dot",
        "record:trailing-newline\n",
    ],
)
def test_source_record_locator_rejects_noncanonical_values(source, locator):
    with pytest.raises(ValidationError, match="canonical record"):
        Memory.create(
            **{
                **_values(source.effective_memory_type_observations[0]),
                "source_record_locator": locator,
            }
        )


@pytest.mark.parametrize("family, value_field, replacement", [
    ("effective_memory_type_observations", "observed_effective_memory_type_id", "owned-synthetic-other-memory"),
    ("execution_context_observations", "observed_execution_context_ids", ["owned-synthetic-other-context"]),
])
def test_duplicate_and_contradictory_logical_records(source, family, value_field, replacement):
    values = _values(source)
    original = getattr(source, family)[0]
    for extra in (original, type(original).create(**{**_values(original), value_field: replacement})):
        with pytest.raises(ValidationError, match="duplicate"):
            Materialization.create(**{**values, family: [*getattr(source, family), extra]})


def test_locator_namespace_is_family_scoped(source):
    locator = "record:shared-event"
    memory = Memory.create(
        **{
            **_values(source.effective_memory_type_observations[0]),
            "source_record_locator": locator,
        }
    )
    context = Context.create(
        **{
            **_values(source.execution_context_observations[0]),
            "source_record_locator": locator,
        }
    )
    result = Materialization.create(
        source_manifest_snapshot=source.source_manifest_snapshot,
        effective_memory_type_observations=[memory],
        execution_context_observations=[context],
    )
    reversed_result = Materialization.create(
        source_manifest_snapshot=source.source_manifest_snapshot,
        effective_memory_type_observations=list(
            reversed(result.effective_memory_type_observations)
        ),
        execution_context_observations=list(
            reversed(result.execution_context_observations)
        ),
    )
    assert memory.id != context.id
    assert len(result.effective_memory_type_observations) == 1
    assert len(result.execution_context_observations) == 1
    assert reversed_result == result


@pytest.mark.parametrize("family, model", [("effective_memory_type_observations", Memory), ("execution_context_observations", Context)])
@pytest.mark.parametrize("field, replacement", [
    ("source_manifest_id", "candidate-state-source-manifest:" + "e" * 64),
    ("architecture", "risc_v"), ("artifact_id", "owned-synthetic-foreign"),
    ("artifact_sha256", "f" * 64), ("instruction_set", "owned-other-instruction-set"),
])
def test_fully_rehashed_foreign_provenance_rejected(source, family, model, field, replacement):
    payload = source.model_dump(mode="json")
    record = payload[family][0]
    record[field] = replacement
    _rehash(record)
    assert model.model_validate(record).id == record["id"]
    with pytest.raises(ValidationError, match="manifest mismatch|artifact provenance mismatch"):
        Materialization.model_validate(_rehash_bundle(payload))


def test_rehashed_memory_value_is_valid_different_authoritative_source(source):
    payload = source.model_dump(mode="json")
    record = payload["effective_memory_type_observations"][0]
    record["observed_effective_memory_type_id"] = "owned-synthetic-different-memory"
    _rehash(record)
    changed = Materialization.model_validate(_rehash_bundle(payload))
    assert changed.id != source.id
    assert changed.source_manifest_snapshot == source.source_manifest_snapshot
    # The core has not independently authenticated correspondence to raw bytes.


def test_rehashed_context_value_is_valid_different_authoritative_source(source):
    payload = source.model_dump(mode="json")
    record = payload["execution_context_observations"][0]
    record["observed_execution_context_ids"] = [
        "owned-synthetic-different-context"
    ]
    _rehash(record)
    changed = Materialization.model_validate(_rehash_bundle(payload))
    assert changed.id != source.id
    assert changed.source_manifest_snapshot == source.source_manifest_snapshot
    assert changed.execution_context_observations[0].observed_execution_context_ids == [
        "owned-synthetic-different-context"
    ]


def test_stale_ids_and_mutated_nested_instances_fail_closed(source):
    for obj in [source, source.source_manifest_snapshot, *source.effective_memory_type_observations, *source.execution_context_observations]:
        payload = obj.model_dump(mode="json")
        payload["id"] = "foreign-id"
        with pytest.raises(ValidationError, match="not deterministic"):
            type(obj).model_validate(payload)
    source.execution_context_observations[0].observed_execution_context_ids.append("owned-inplace-mutation")
    with pytest.raises(ValidationError, match="not deterministic"):
        Materialization.create(**_values(source))


def test_detached_full_dump_after_caller_mutations(source):
    memories = list(source.effective_memory_type_observations)
    contexts = list(source.execution_context_observations)
    manifest = source.source_manifest_snapshot
    retained = Materialization.create(source_manifest_snapshot=manifest, effective_memory_type_observations=memories, execution_context_observations=contexts)
    before = retained.model_dump(mode="json")
    memories[0].access_address.value = "0x1234"
    memories[0].instruction_address.value = "0x1238"
    contexts[0].observed_execution_context_ids.append("owned-mutated")
    object.__setattr__(manifest, "producer_profile_version", "mutated")
    object.__setattr__(manifest.owned_fixture_provenance, "owned", False)
    memories.clear()
    contexts.clear()
    assert retained.model_dump(mode="json") == before
    assert Materialization.model_validate(before) == retained


def test_core_firewall_and_no_verdict_fields(source):
    tree = ast.parse((ROOT / "src/chipchain/verification/candidate_state_observation_models.py").read_text())
    allowed = {"__future__", "hashlib", "json", "re", "typing", "pydantic", "chipchain.models.common", "chipchain.models.enums", "chipchain.verification.models"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert all(name.name in allowed for name in node.names)
        if isinstance(node, ast.ImportFrom):
            assert node.module in allowed
            if node.module == "chipchain.verification.models":
                assert [name.name for name in node.names] == ["ProgramAddress"]
    forbidden = ["requirement_id", "candidate_id", "status", "verified", "satisfied", "confidence", "metadata", "host_timestamp", "wall_clock_time", "cycle_count"]
    for obj in [source, source.source_manifest_snapshot, *source.effective_memory_type_observations, *source.execution_context_observations]:
        assert not set(forbidden) & set(type(obj).model_fields)
        for key in forbidden:
            with pytest.raises(ValidationError):
                type(obj).model_validate({**obj.model_dump(mode="json"), key: "forbidden"})
    production = (
        ROOT
        / "src/chipchain/verification/candidate_state_observation_models.py"
    ).read_text(encoding="utf-8")
    for generated_identity_source in (
        "uuid4(",
        "datetime.now(",
        "time.time(",
        "utc_now(",
    ):
        assert generated_identity_source not in production


def test_owned_fixture_hash_and_exact_frozen_addresses(source):
    snapshot = RUNNER["FIXTURE"].read_bytes()
    assert source.source_manifest_snapshot.source_artifact_sha256 == hashlib.sha256(snapshot).hexdigest()
    frozen = json.loads((ROOT / "tests/fixtures/phase10d/aarch64_static_fused_behavior_v1/expected_fixture_design.json").read_bytes())
    assert source.source_manifest_snapshot.artifact_sha256 == frozen["artifact_sha256"]
    addresses = {record["address"] for record in frozen["instructions"]}
    for record in [*source.effective_memory_type_observations, *source.execution_context_observations]:
        assert record.instruction_address.value in addresses


def test_export_package_names_are_available():
    from chipchain.verification import CandidateStateObservationMaterialization, export_candidate_state_observations
    assert CandidateStateObservationMaterialization is Materialization
    assert callable(export_candidate_state_observations)
