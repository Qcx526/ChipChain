"""Phase 10D Step 8B-0 single-source corpus build tests."""

from __future__ import annotations

import ast
import json
from pathlib import Path
import subprocess
import sys

import pytest
from pydantic import ValidationError

from chipchain.corpus import (
    PUBLIC_CVE_SOURCE_CONTRACT,
    PublicCveSourceDocument,
    PublicCveSourceRecord,
    build_public_cve_corpus,
    load_public_cve_corpus,
    load_public_cve_source,
    serialize_public_cve_corpus,
    write_public_cve_corpus,
)


ROOT = Path(__file__).resolve().parents[1]
SOURCE_PATH = (
    ROOT / "data/public_cve/source/arm_cross_layer_seed_v1.source.json"
)
GENERATED_PATH = ROOT / "data/public_cve/arm_cross_layer_seed_v1.json"
EXPECTED_CORPUS_ID = (
    "public-cve-corpus:"
    "778765c51a0d9b939eb37b390367a3d0"
    "cd02720942c8746c19eb0a1c38930e49"
)


@pytest.fixture(scope="module")
def source() -> PublicCveSourceDocument:
    return load_public_cve_source(SOURCE_PATH)


def _source_record_payload(
    source: PublicCveSourceDocument,
    index: int = 0,
) -> dict[str, object]:
    return source.records[index].model_dump(mode="json")


def test_authoritative_source_has_seven_records_and_no_generated_ids(
    source: PublicCveSourceDocument,
) -> None:
    payload = json.loads(SOURCE_PATH.read_text(encoding="utf-8"))
    forbidden_keys = {"id", "knowledge_entries", "knowledge_entry_id"}

    def keys(value: object) -> set[str]:
        if isinstance(value, dict):
            return set(value).union(*(keys(item) for item in value.values()))
        if isinstance(value, list):
            return set().union(*(keys(item) for item in value))
        return set()

    raw = SOURCE_PATH.read_text(encoding="utf-8")
    assert source.contract == PUBLIC_CVE_SOURCE_CONTRACT
    assert source.corpus_name == "arm_cross_layer_seed_v1"
    assert len(source.records) == 7
    assert [item.cve_id for item in source.records] == sorted(
        item.cve_id for item in source.records
    )
    assert set(payload) == {"contract", "corpus_name", "records"}
    assert forbidden_keys.isdisjoint(keys(payload))
    assert "public-cve-research-sample:" not in raw
    assert "vulnerability-knowledge-entry:" not in raw
    assert "public-cve-corpus:" not in raw


def test_source_build_is_exactly_the_frozen_step8a_corpus(
    source: PublicCveSourceDocument,
) -> None:
    built = build_public_cve_corpus(source)
    frozen = load_public_cve_corpus(GENERATED_PATH)

    assert built == frozen
    assert built.id == EXPECTED_CORPUS_ID
    assert [item.id for item in built.knowledge_entries] == [
        item.id for item in frozen.knowledge_entries
    ]
    assert [item.id for item in built.records] == [
        item.id for item in frozen.records
    ]
    assert built.metadata == frozen.metadata


def test_generated_serialization_is_deterministic_and_byte_exact(
    source: PublicCveSourceDocument,
    tmp_path: Path,
) -> None:
    corpus = build_public_cve_corpus(source)
    first = serialize_public_cve_corpus(corpus)
    second = serialize_public_cve_corpus(build_public_cve_corpus(source))
    output = tmp_path / "generated.json"
    write_public_cve_corpus(corpus, output)

    assert first == second
    assert first.endswith("\n")
    assert first == GENERATED_PATH.read_text(encoding="utf-8")
    assert output.read_bytes() == GENERATED_PATH.read_bytes()


def test_maintenance_script_check_accepts_committed_snapshot() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "scripts/build_public_cve_corpus.py",
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


def test_one_source_record_derives_one_entry_sample_and_stable_ids(
    source: PublicCveSourceDocument,
) -> None:
    payload = _source_record_payload(source)
    payload.update(
        {
            "cve_id": "CVE-2099-9999",
            "title": "Synthetic test-only corpus builder record",
            "underlying_issue_key": "synthetic-test-only-builder-record",
            "related_cve_ids": [],
            "source_references": [
                "https://example.invalid/CVE-2099-9999"
            ],
        }
    )
    extra = PublicCveSourceRecord.model_validate(payload)
    expanded_source = PublicCveSourceDocument(
        corpus_name=source.corpus_name,
        records=[*source.records, extra],
    )

    first = build_public_cve_corpus(expanded_source)
    second = build_public_cve_corpus(expanded_source)
    entry = next(
        item
        for item in first.knowledge_entries
        if item.external_id == "CVE-2099-9999"
    )
    sample = next(
        item for item in first.records if item.cve_id == "CVE-2099-9999"
    )

    assert len(first.knowledge_entries) == len(source.records) + 1
    assert len(first.records) == len(source.records) + 1
    assert entry.id.startswith("vulnerability-knowledge-entry:")
    assert sample.id.startswith("public-cve-research-sample:")
    assert sample.knowledge_entry_id == entry.id
    assert first.id != EXPECTED_CORPUS_ID
    assert first == second
    assert first.id == second.id


def test_source_fact_mutation_propagates_without_duplicate_maintenance(
    source: PublicCveSourceDocument,
) -> None:
    source_payload = source.model_dump(mode="json")
    changed_title = "Curator-updated test-only title"
    source_payload["records"][0]["title"] = changed_title
    mutated_source = PublicCveSourceDocument.model_validate(source_payload)
    original = build_public_cve_corpus(source)
    mutated = build_public_cve_corpus(mutated_source)
    cve_id = mutated_source.records[0].cve_id
    original_entry = next(
        item for item in original.knowledge_entries if item.external_id == cve_id
    )
    mutated_entry = next(
        item for item in mutated.knowledge_entries if item.external_id == cve_id
    )
    original_sample = next(
        item for item in original.records if item.cve_id == cve_id
    )
    mutated_sample = next(item for item in mutated.records if item.cve_id == cve_id)

    assert mutated_source.records[0].title == changed_title
    assert mutated_entry.title == changed_title
    assert mutated_sample.title == changed_title
    assert mutated_entry.id != original_entry.id
    assert mutated_sample.knowledge_entry_id == mutated_entry.id
    assert mutated_sample.id != original_sample.id
    assert mutated.id != original.id


def test_source_order_cannot_change_generated_output(
    source: PublicCveSourceDocument,
) -> None:
    payload = source.model_dump(mode="json")
    payload["records"] = list(reversed(payload["records"]))
    reversed_source = PublicCveSourceDocument.model_validate(payload)
    normal = build_public_cve_corpus(source)
    reversed_output = build_public_cve_corpus(reversed_source)

    assert reversed_source == source
    assert reversed_output == normal
    assert [item.id for item in reversed_output.records] == [
        item.id for item in normal.records
    ]
    assert [item.id for item in reversed_output.knowledge_entries] == [
        item.id for item in normal.knowledge_entries
    ]
    assert serialize_public_cve_corpus(reversed_output) == (
        serialize_public_cve_corpus(normal)
    )


def test_duplicate_source_cve_fails_closed(
    source: PublicCveSourceDocument,
) -> None:
    payload = source.model_dump(mode="json")
    payload["records"].append(payload["records"][0])

    with pytest.raises(ValidationError, match="unique CVE IDs"):
        PublicCveSourceDocument.model_validate(payload)


@pytest.mark.parametrize(
    ("field_name", "unsafe_value"),
    [
        ("title", "/tmp/file"),
        ("summary", "~/file"),
        ("trigger_summary", r"C:\Users\name\file"),
        ("source_references", r"\\server\share"),
        ("precondition_summary", "file:///tmp/file"),
        ("hardware_effect_summary", "<html>raw advisory</html>"),
        ("title", "owned_synthetic marker"),
    ],
)
def test_source_reuses_fail_closed_corpus_text_safety(
    source: PublicCveSourceDocument,
    field_name: str,
    unsafe_value: str,
) -> None:
    payload = _source_record_payload(source)
    replacement: object = unsafe_value
    if field_name in {"affected_components", "source_references"}:
        replacement = [unsafe_value]
    payload[field_name] = replacement

    with pytest.raises(ValidationError, match="forbidden|host path"):
        PublicCveSourceRecord.model_validate(payload)


@pytest.mark.parametrize("key", ["exploit_payload", "poc"])
def test_source_rejects_prohibited_metadata_fields(
    source: PublicCveSourceDocument,
    key: str,
) -> None:
    payload = _source_record_payload(source)
    payload["metadata"] = {key: "test-only prohibited material"}

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        PublicCveSourceRecord.model_validate(payload)


@pytest.mark.parametrize(
    "reference",
    [
        "https://nvd.nist.gov/vuln/detail/CVE-2023-34320",
        "https://xenbits.xenproject.org/xsa/advisory-436.html",
    ],
)
def test_source_allows_public_https_references(
    source: PublicCveSourceDocument,
    reference: str,
) -> None:
    payload = _source_record_payload(source)
    payload["source_references"] = [reference]

    record = PublicCveSourceRecord.model_validate(payload)
    assert record.source_references == [reference]


def test_source_contract_rejects_generated_fields(
    source: PublicCveSourceDocument,
) -> None:
    payload = source.model_dump(mode="json")
    payload["id"] = "public-cve-source:forbidden"
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        PublicCveSourceDocument.model_validate(payload)

    record_payload = _source_record_payload(source)
    record_payload["knowledge_entry_id"] = "forbidden-derived-id"
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        PublicCveSourceRecord.model_validate(record_payload)


def test_source_builder_imports_no_execution_or_verification_layers() -> None:
    imported_modules: set[str] = set()
    for relative_path in (
        "src/chipchain/corpus/source_models.py",
        "src/chipchain/corpus/builder.py",
        "src/chipchain/corpus/loader.py",
        "scripts/build_public_cve_corpus.py",
    ):
        tree = ast.parse((ROOT / relative_path).read_text(encoding="utf-8"))
        imported_modules.update(
            node.module or ""
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
        )

    forbidden_prefixes = (
        "chipchain.evaluation",
        "chipchain.hardware_trigger",
        "chipchain.reasoning",
        "chipchain.runtime",
        "chipchain.verification",
    )
    assert all(
        not module.startswith(forbidden_prefixes)
        for module in imported_modules
    )
