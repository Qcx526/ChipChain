"""Contracts for source-backed static hardware references."""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path

from pydantic import ValidationError
import pytest

from chipchain.analysis import (
    StaticDocumentedErratumHardwareReference,
    StaticHardwareReferenceCatalog,
    StaticHardwareReferenceKind,
    StaticHardwareReferenceSemantics,
    StaticOwnedSyntheticHardwareReference,
    static_documented_erratum_hardware_reference_id,
    static_hardware_reference_catalog_id,
)
from chipchain.hardware_trigger.documented_erratum_models import (
    DocumentedHardwareErratumContract,
    documented_hardware_erratum_id,
)
from chipchain.models import Architecture


ROOT = Path(__file__).resolve().parents[1]
ERRATUM = (
    ROOT / "data/evaluation/"
    "cve_2023_34320_documented_erratum_1508412_v1.json"
)


@pytest.fixture(scope="module")
def erratum() -> DocumentedHardwareErratumContract:
    return DocumentedHardwareErratumContract.model_validate_json(
        ERRATUM.read_bytes()
    )


def _owned(
    reference_id: str = "owned-synthetic-hardware-condition-v1",
    architecture: Architecture = Architecture.ARM,
) -> StaticOwnedSyntheticHardwareReference:
    return StaticOwnedSyntheticHardwareReference.create(
        reference_id=reference_id,
        architecture=architecture,
        title=f"{reference_id} reference",
        source_reference_ids=["owned-synthetic-reference-design-v1"],
    )


def _documented(
    erratum: DocumentedHardwareErratumContract,
) -> StaticDocumentedErratumHardwareReference:
    return StaticDocumentedErratumHardwareReference.create(
        reference_id=erratum.id,
        architecture=Architecture.ARM,
        source_documented_erratum_snapshot=erratum,
    )


def test_reference_vocabularies_and_schema_are_closed() -> None:
    assert list(StaticHardwareReferenceKind) == [
        StaticHardwareReferenceKind.OWNED_SYNTHETIC_CONDITION,
        StaticHardwareReferenceKind.DOCUMENTED_HARDWARE_ERRATUM,
    ]
    assert list(StaticHardwareReferenceSemantics) == [
        StaticHardwareReferenceSemantics.REFERENCE_ONLY,
        StaticHardwareReferenceSemantics.SOURCE_DOCUMENTED_REFERENCE_ONLY,
    ]
    owned_schema = StaticOwnedSyntheticHardwareReference.model_json_schema()
    assert owned_schema["properties"]["reference_kind"]["const"] == (
        "owned_synthetic_condition"
    )
    assert owned_schema["properties"]["reference_semantics"]["const"] == (
        "reference_only"
    )


def test_owned_reference_is_explicitly_synthetic_benign_and_has_no_cve() -> None:
    reference = _owned()
    assert reference.owned is True
    assert reference.synthetic is True
    assert reference.benign is True
    fields = type(reference).model_fields
    assert "cve_id" not in fields
    assert "erratum_id" not in fields
    assert "affected_revision" not in fields
    assert "hardware_failure_verdict" not in fields


def test_documented_reference_uses_exact_erratum_object_id(erratum) -> None:
    reference = _documented(erratum)
    assert reference.reference_id == erratum.id
    assert reference.source_documented_erratum_snapshot == erratum
    assert reference.cve_id == "CVE-2023-34320"
    assert reference.erratum_id == "1508412"
    assert reference.processor == "Cortex-A77"

    payload = reference.model_dump(mode="json")
    payload["reference_id"] = "CVE-2023-34320"
    with pytest.raises(ValidationError, match="must equal erratum object ID"):
        StaticDocumentedErratumHardwareReference.model_validate(payload)


def test_documented_reference_snapshot_tamper_fails(erratum) -> None:
    payload = _documented(erratum).model_dump(mode="json")
    payload["source_documented_erratum_snapshot"]["id"] = (
        "documented-hardware-erratum:bad"
    )
    with pytest.raises(ValidationError, match="documented erratum ID"):
        StaticDocumentedErratumHardwareReference.model_validate(payload)


def test_rehashed_outer_reference_cannot_hide_tampered_documented_erratum_snapshot(
    erratum,
) -> None:
    reference = _documented(erratum)
    reference_payload = reference.model_dump(mode="json")
    inner_payload = reference_payload["source_documented_erratum_snapshot"]
    inner_payload["cve_id"] = "CVE-2099-0000"
    inner_payload["id"] = documented_hardware_erratum_id(
        {key: value for key, value in inner_payload.items() if key != "id"}
    )

    with pytest.raises(ValidationError, match="CVE-2023-34320"):
        DocumentedHardwareErratumContract.model_validate(inner_payload)

    reference_payload["reference_id"] = inner_payload["id"]
    reference_payload["id"] = static_documented_erratum_hardware_reference_id(
        {
            key: value
            for key, value in reference_payload.items()
            if key != "id"
        }
    )
    with pytest.raises(ValidationError, match="CVE-2023-34320"):
        StaticDocumentedErratumHardwareReference.model_validate(
            reference_payload
        )

    catalog_payload = StaticHardwareReferenceCatalog.create(
        references=[reference]
    ).model_dump(mode="json")
    catalog_payload["references"] = [reference_payload]
    catalog_payload["id"] = static_hardware_reference_catalog_id(
        {key: value for key, value in catalog_payload.items() if key != "id"}
    )
    with pytest.raises(ValidationError, match="CVE-2023-34320"):
        StaticHardwareReferenceCatalog.model_validate(catalog_payload)


def test_owned_reference_detaches_source_reference_list() -> None:
    source_reference_ids = ["owned-synthetic-reference-design-v1"]
    reference = StaticOwnedSyntheticHardwareReference.create(
        reference_id="owned-synthetic-caller-list-isolation-v1",
        architecture=Architecture.ARM,
        title="owned synthetic caller list isolation",
        source_reference_ids=source_reference_ids,
    )
    before = reference.model_dump_json()

    source_reference_ids.append("caller-added-source")
    source_reference_ids.clear()

    assert reference.source_reference_ids == [
        "owned-synthetic-reference-design-v1"
    ]
    assert reference.model_dump_json() == before


def test_documented_reference_detaches_erratum_snapshot(erratum) -> None:
    caller_erratum = DocumentedHardwareErratumContract.model_validate(
        erratum.model_dump(mode="json")
    )
    reference = _documented(caller_erratum)
    before = reference.model_dump_json()

    caller_erratum.revision_records.clear()
    caller_erratum.program_order_cases.clear()

    assert len(reference.source_documented_erratum_snapshot.revision_records) == 3
    assert len(reference.source_documented_erratum_snapshot.program_order_cases) == 2
    assert reference.model_dump_json() == before


def test_hardware_reference_catalog_detaches_reference_inputs() -> None:
    references = [
        _owned("owned-synthetic-catalog-input-a"),
        _owned("owned-synthetic-catalog-input-b"),
    ]
    catalog = StaticHardwareReferenceCatalog.create(references=references)
    before = catalog.model_dump_json()
    before_id = catalog.id

    references.reverse()
    references.clear()

    assert len(catalog.references) == 2
    assert catalog.id == before_id
    assert catalog.model_dump_json() == before


def test_empty_and_mixed_architecture_catalog_are_valid(erratum) -> None:
    assert StaticHardwareReferenceCatalog.create(references=[]).references == []
    catalog = StaticHardwareReferenceCatalog.create(
        references=[
            _owned(architecture=Architecture.RISC_V),
            _documented(erratum),
        ]
    )
    assert {item.architecture for item in catalog.references} == {
        Architecture.ARM,
        Architecture.RISC_V,
    }


def test_catalog_order_and_source_reference_order_are_deterministic(erratum) -> None:
    first_owned = _owned("owned-synthetic-a")
    second_owned = StaticOwnedSyntheticHardwareReference.create(
        reference_id="owned-synthetic-b",
        architecture=Architecture.ARM,
        title="owned synthetic b",
        source_reference_ids=["source-z", "source-a"],
    )
    documented = _documented(erratum)
    catalogs = [
        StaticHardwareReferenceCatalog.create(references=references)
        for references in (
            [first_owned, second_owned, documented],
            [documented, second_owned, first_owned],
        )
    ]
    permuted_second = StaticOwnedSyntheticHardwareReference.create(
        reference_id="owned-synthetic-b",
        architecture=Architecture.ARM,
        title="owned synthetic b",
        source_reference_ids=["source-a", "source-z"],
    )
    catalogs.append(
        StaticHardwareReferenceCatalog.create(
            references=[documented, first_owned, permuted_second]
        )
    )
    assert len({catalog.id for catalog in catalogs}) == 1
    assert len(
        {
            hashlib.sha256(
                json.dumps(
                    catalog.model_dump(mode="json"),
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            ).hexdigest()
            for catalog in catalogs
        }
    ) == 1


def test_duplicate_reference_and_record_are_rejected() -> None:
    reference = _owned()
    with pytest.raises(ValidationError, match="reference IDs must be unique"):
        StaticHardwareReferenceCatalog.create(
            references=[reference, reference]
        )


def test_duplicate_record_id_payload_fails_at_child_identity_boundary() -> None:
    catalog_payload = StaticHardwareReferenceCatalog.create(
        references=[
            _owned("owned-synthetic-record-id-a"),
            _owned("owned-synthetic-record-id-b"),
        ]
    ).model_dump(mode="json")
    assert (
        catalog_payload["references"][0]["reference_id"]
        != catalog_payload["references"][1]["reference_id"]
    )
    catalog_payload["references"][1]["id"] = catalog_payload["references"][
        0
    ]["id"]

    with pytest.raises(
        ValidationError,
        match="owned synthetic hardware reference ID mismatch",
    ):
        StaticHardwareReferenceCatalog.model_validate(catalog_payload)


@pytest.mark.parametrize("value", ["/tmp/reference", "C:\\reference", "file:data"])
def test_owned_reference_text_is_path_neutral(value: str) -> None:
    with pytest.raises(ValidationError, match="path-neutral"):
        StaticOwnedSyntheticHardwareReference.create(
            reference_id=value,
            architecture=Architecture.ARM,
            title="owned reference",
            source_reference_ids=["owned-source"],
        )


def test_reference_models_have_no_outcome_fields() -> None:
    forbidden = {
        "affected",
        "triggered",
        "verified",
        "vulnerable",
        "confidence",
        "score",
        "attack_chain",
    }
    for model in (
        StaticOwnedSyntheticHardwareReference,
        StaticDocumentedErratumHardwareReference,
        StaticHardwareReferenceCatalog,
    ):
        assert forbidden.isdisjoint(model.model_fields)


def test_reference_core_dependency_firewall() -> None:
    path = ROOT / "src/chipchain/analysis/static_hardware_reference_models.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    modules = {
        node.module or ""
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    }
    forbidden = (
        "angr",
        "capstone",
        "aarch64_static_semantic_decoder",
        "structure_extractor",
        "runtime",
        "reasoning",
        "provider",
        "knowledge",
    )
    assert not any(any(term in module for term in forbidden) for module in modules)
