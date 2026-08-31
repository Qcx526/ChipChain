"""Deterministic offline materialization of documented erratum semantics."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from chipchain.corpus import (
    BenchmarkAdmissionStatus,
    PublicCveSourceDocument,
    PublicCveSourceRecord,
    build_public_cve_corpus,
)
from chipchain.hardware_trigger.documented_erratum_models import (
    DocumentedErratumSourceDocument,
    DocumentedHardwareErratumContract,
)


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _source_record_sha256(record: PublicCveSourceRecord) -> str:
    snapshot = PublicCveSourceRecord.model_validate(
        record.model_dump(mode="json")
    )
    return hashlib.sha256(
        _canonical_json_bytes(snapshot.model_dump(mode="json"))
    ).hexdigest()


def load_documented_erratum_source(
    path: str | Path,
) -> DocumentedErratumSourceDocument:
    """Load and validate one human-reviewed curation source."""

    return DocumentedErratumSourceDocument.model_validate_json(
        Path(path).read_bytes()
    )


def build_documented_hardware_erratum(
    source: DocumentedErratumSourceDocument,
    *,
    public_source_bytes: bytes,
) -> DocumentedHardwareErratumContract:
    """Build one contract from detached curation and frozen public bytes."""

    curation = DocumentedErratumSourceDocument.model_validate(
        source.model_dump(mode="json")
    )
    public_source_file_sha256 = hashlib.sha256(public_source_bytes).hexdigest()
    if public_source_file_sha256 != curation.public_source_file_sha256:
        raise ValueError("frozen public-CVE source file SHA-256 mismatch")

    public_source = PublicCveSourceDocument.model_validate_json(public_source_bytes)
    matching_records = [
        record for record in public_source.records if record.cve_id == curation.cve_id
    ]
    if len(matching_records) != 1:
        raise ValueError("frozen public source must contain exactly one bound CVE")
    record = matching_records[0]
    record_sha256 = _source_record_sha256(record)
    if record_sha256 != curation.public_source_record_sha256:
        raise ValueError("frozen public-CVE source record SHA-256 mismatch")
    if record.admission_status is not BenchmarkAdmissionStatus.NEXT_OBJECTIVE_CANDIDATE:
        raise ValueError("frozen public-CVE admission status changed")

    corpus = build_public_cve_corpus(public_source)
    if corpus.id != curation.public_corpus_id:
        raise ValueError("frozen public-CVE corpus identity mismatch")

    values = curation.model_dump(mode="json", exclude={"contract"})
    return DocumentedHardwareErratumContract.create(**values)


def serialize_documented_hardware_erratum(
    contract: DocumentedHardwareErratumContract,
) -> str:
    """Return stable generated JSON with one trailing newline."""

    snapshot = DocumentedHardwareErratumContract.model_validate(
        contract.model_dump(mode="json")
    )
    return snapshot.model_dump_json(indent=2, ensure_ascii=False) + "\n"


def write_documented_hardware_erratum(
    contract: DocumentedHardwareErratumContract,
    path: str | Path,
) -> None:
    """Write one deterministic contract without network or runtime access."""

    Path(path).write_text(
        serialize_documented_hardware_erratum(contract),
        encoding="utf-8",
    )
