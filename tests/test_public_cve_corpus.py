"""Phase 10D Step 8A public-CVE corpus intake tests."""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from chipchain.corpus import (
    ArmArchitectureProfile,
    BenchmarkAdmissionBlocker,
    BenchmarkAdmissionStatus,
    CrossLayerResearchClassification,
    PublicCveCorpus,
    PublicCveResearchSample,
    load_public_cve_corpus,
    summarize_public_cve_samples,
)
from chipchain.knowledge import (
    DeterministicKnowledgeRetriever,
    InMemoryKnowledgeEntryRepository,
    KnowledgeEntryKind,
    KnowledgeRetrievalQuery,
)
from chipchain.models import Architecture


ROOT = Path(__file__).resolve().parents[1]
CORPUS_PATH = ROOT / "data/public_cve/arm_cross_layer_seed_v1.json"
EXPECTED_CVE_IDS = {
    "CVE-2022-23960",
    "CVE-2023-34320",
    "CVE-2023-34321",
    "CVE-2023-52481",
    "CVE-2024-26670",
    "CVE-2024-7883",
    "CVE-2025-10263",
}


@pytest.fixture(scope="module")
def corpus() -> PublicCveCorpus:
    return load_public_cve_corpus(CORPUS_PATH)


def _by_cve(corpus: PublicCveCorpus) -> dict[str, PublicCveResearchSample]:
    return {item.cve_id: item for item in corpus.records}


def _recreate(
    sample: PublicCveResearchSample,
    **changes: object,
) -> PublicCveResearchSample:
    values: dict[str, object] = {
        "cve_id": sample.cve_id,
        "architecture": sample.architecture,
        "architecture_profile": sample.architecture_profile,
        "title": sample.title,
        "summary": sample.summary,
        "affected_components": list(reversed(sample.affected_components)),
        "cross_layer_classification": sample.cross_layer_classification,
        "underlying_issue_key": sample.underlying_issue_key,
        "related_cve_ids": list(reversed(sample.related_cve_ids)),
        "trigger_summary": sample.trigger_summary,
        "precondition_summary": sample.precondition_summary,
        "hardware_effect_summary": sample.hardware_effect_summary,
        "source_references": list(reversed(sample.source_references)),
        "admission_status": sample.admission_status,
        "admission_blockers": list(reversed(sample.admission_blockers)),
        "knowledge_entry_id": sample.knowledge_entry_id,
        "metadata": {"curator_note": "identity-excluded"},
    }
    values.update(changes)
    return PublicCveResearchSample.create(**values)  # type: ignore[arg-type]


def test_seed_contains_exactly_seven_unique_public_cves(
    corpus: PublicCveCorpus,
) -> None:
    cve_ids = [item.cve_id for item in corpus.records]

    assert len(corpus.records) == 7
    assert len(cve_ids) == len(set(cve_ids))
    assert set(cve_ids) == EXPECTED_CVE_IDS
    assert cve_ids == sorted(cve_ids)

    with pytest.raises(ValueError, match="unique CVE IDs"):
        PublicCveCorpus.create(
            records=[corpus.records[0], corpus.records[0]],
            knowledge_entries=[
                corpus.knowledge_entries[0],
                corpus.knowledge_entries[1],
            ],
        )


def test_sample_and_corpus_ids_are_deterministic(
    corpus: PublicCveCorpus,
) -> None:
    for sample in corpus.records:
        assert _recreate(sample).id == sample.id

    reordered = PublicCveCorpus.create(
        records=list(reversed(corpus.records)),
        knowledge_entries=list(reversed(corpus.knowledge_entries)),
        metadata={"curator_note": "identity-excluded"},
    )
    assert reordered.id == corpus.id
    assert PublicCveCorpus.model_validate_json(corpus.model_dump_json()) == corpus


def test_references_relations_and_blockers_are_unique_sorted(
    corpus: PublicCveCorpus,
) -> None:
    for sample in corpus.records:
        assert sample.source_references == sorted(sample.source_references)
        assert sample.related_cve_ids == sorted(sample.related_cve_ids)
        assert len(sample.related_cve_ids) == len(set(sample.related_cve_ids))
        assert sample.cve_id not in sample.related_cve_ids
        assert sample.admission_blockers == sorted(
            sample.admission_blockers, key=lambda item: item.value
        )

    sample = corpus.records[0]
    payload = sample.model_dump(mode="json")
    payload["related_cve_ids"] = [sample.cve_id]
    with pytest.raises(ValidationError, match="cannot relate to itself"):
        PublicCveResearchSample.model_validate(payload)


def test_each_sample_exactly_binds_one_cve_knowledge_entry(
    corpus: PublicCveCorpus,
) -> None:
    entries = {item.id: item for item in corpus.knowledge_entries}

    assert len(entries) == len(corpus.records)
    for sample in corpus.records:
        entry = entries[sample.knowledge_entry_id]
        assert entry.entry_kind is KnowledgeEntryKind.CVE
        assert entry.external_id == sample.cve_id
        assert entry.architecture is sample.architecture is Architecture.ARM
        assert entry.affected_components == sample.affected_components
        assert entry.references == sample.source_references

    mismatched = _recreate(
        corpus.records[0],
        knowledge_entry_id=corpus.knowledge_entries[1].id,
    )
    with pytest.raises(ValueError, match="knowledge entry binding mismatch"):
        PublicCveCorpus.create(
            records=[mismatched, *corpus.records[1:]],
            knowledge_entries=corpus.knowledge_entries,
        )


def test_architecture_profile_and_admission_rules_fail_closed(
    corpus: PublicCveCorpus,
) -> None:
    records = _by_cve(corpus)
    m_profile = records["CVE-2024-7883"]
    assert m_profile.architecture is Architecture.ARM
    assert m_profile.architecture_profile is ArmArchitectureProfile.M_PROFILE
    assert m_profile.cross_layer_classification is (
        CrossLayerResearchClassification.OUT_OF_CURRENT_ARCH_SCOPE
    )
    assert m_profile.admission_status is (
        BenchmarkAdmissionStatus.OUT_OF_CURRENT_ARCH_SCOPE
    )
    assert m_profile.admission_blockers == [
        BenchmarkAdmissionBlocker.M_PROFILE_OUT_OF_CURRENT_SCOPE
    ]

    with pytest.raises(
        ValidationError, match="cannot enter current objective admission"
    ):
        _recreate(
            m_profile,
            admission_status=BenchmarkAdmissionStatus.NEXT_OBJECTIVE_CANDIDATE,
        )

    related = records["CVE-2023-34321"]
    assert related.cross_layer_classification is (
        CrossLayerResearchClassification.CROSS_LAYER_RELATED
    )
    assert related.cross_layer_classification is not (
        CrossLayerResearchClassification.TYPE_I_CANDIDATE
    )
    assert related.admission_status is BenchmarkAdmissionStatus.SECONDARY_ONLY
    with pytest.raises(
        ValidationError, match="cannot become an objective candidate"
    ):
        _recreate(
            related,
            admission_status=BenchmarkAdmissionStatus.NEXT_OBJECTIVE_CANDIDATE,
        )
    with pytest.raises(ValidationError, match="cannot receive a strict type"):
        _recreate(
            related,
            cross_layer_classification=(
                CrossLayerResearchClassification.TYPE_I_CANDIDATE
            ),
        )


def test_underlying_issue_reporting_is_independent_of_cve_count(
    corpus: PublicCveCorpus,
) -> None:
    summary = corpus.summary
    assert summary.total_cve_records == 7
    assert summary.unique_underlying_issues == len(
        {item.underlying_issue_key for item in corpus.records}
    )

    first = corpus.records[0]
    related_record = _recreate(
        first,
        cve_id="CVE-2099-9999",
        related_cve_ids=[first.cve_id],
    )
    shared_issue_summary = summarize_public_cve_samples(
        [first, related_record]
    )
    assert shared_issue_summary.total_cve_records == 2
    assert shared_issue_summary.unique_underlying_issues == 1


def test_seed_relations_preserve_software_mitigation_distinctions(
    corpus: PublicCveCorpus,
) -> None:
    records = _by_cve(corpus)
    assert records["CVE-2023-52481"].related_cve_ids == ["CVE-2024-26670"]
    assert records["CVE-2024-26670"].related_cve_ids == ["CVE-2023-52481"]
    assert records["CVE-2025-10263"].related_cve_ids == ["CVE-2026-53354"]
    assert "CVE-2026-53354" not in records
    assert len(corpus.records) == 7


def test_summary_has_closed_classification_and_admission_counts(
    corpus: PublicCveCorpus,
) -> None:
    assert corpus.summary.model_dump(mode="json") == {
        "total_cve_records": 7,
        "unique_underlying_issues": 7,
        "classification_counts": {
            "type_i_candidate": 1,
            "type_ii_candidate": 4,
            "type_iii_candidate": 0,
            "cross_layer_related": 1,
            "out_of_current_arch_scope": 1,
        },
        "admission_counts": {
            "next_objective_candidate": 1,
            "secondary_only": 1,
            "blocked_current_verifier": 4,
            "out_of_current_arch_scope": 1,
        },
    }


def test_corpus_contains_no_host_raw_html_or_payload_material(
    corpus: PublicCveCorpus,
) -> None:
    raw = CORPUS_PATH.read_text(encoding="utf-8")
    lowered = raw.lower()
    forbidden_fragments = (
        "<!doctype",
        "<html",
        "file://",
        "/home/",
        "/users/",
        "owned_synthetic",
        '"exploit_code"',
        '"poc"',
        '"payload"',
        '"raw_html"',
    )
    assert all(fragment not in lowered for fragment in forbidden_fragments)
    assert all(
        not value
        for item in corpus.records
        for key, value in item.metadata.items()
        if key in {"owned", "synthetic", "not_real_vulnerability"}
    )

    payload = corpus.records[0].model_dump(mode="json")
    payload["metadata"] = {"raw_html": "<html>not allowed</html>"}
    with pytest.raises(ValidationError, match="forbidden execution state"):
        PublicCveResearchSample.model_validate(payload)


@pytest.mark.parametrize(
    ("field_name", "path_value"),
    [
        ("title", "/tmp/chipchain/file.json"),
        ("summary", "/var/lib/file"),
        ("affected_components", "/opt/example"),
        ("trigger_summary", "~/secret"),
        ("precondition_summary", r"C:\Users\name\file"),
        ("hardware_effect_summary", "C:/Users/name/file"),
        ("source_references", r"\server\share\file"),
        ("source_references", r"\\server\share\file"),
        ("metadata", r"\local-root"),
        ("source_references", "file:/tmp/file"),
        ("metadata", "file:///tmp/file"),
        ("metadata", "FiLe:/tmp/mixed-case"),
    ],
)
def test_local_host_paths_fail_closed_in_all_corpus_text_surfaces(
    corpus: PublicCveCorpus,
    field_name: str,
    path_value: str,
) -> None:
    replacement: object = path_value
    if field_name in {"affected_components", "source_references"}:
        replacement = [path_value]
    elif field_name == "metadata":
        replacement = {"curator_note": path_value}

    with pytest.raises(ValidationError, match="contains a host path"):
        _recreate(corpus.records[0], **{field_name: replacement})


@pytest.mark.parametrize(
    "reference",
    [
        "https://nvd.nist.gov/vuln/detail/CVE-2023-34320",
        "https://xenbits.xenproject.org/xsa/advisory-436.html",
        "Arm Spectre-BHB security publication",
        "Normal prose about CVE-2023-34320 on Arm.",
    ],
)
def test_public_urls_and_named_publications_are_not_host_paths(
    corpus: PublicCveCorpus,
    reference: str,
) -> None:
    sample = _recreate(corpus.records[0], source_references=[reference])

    assert sample.source_references == [reference]


def test_corpus_does_not_contaminate_owned_evaluation_fixtures() -> None:
    for relative_path in (
        "tests/fixtures/evaluation/phase10a_owned_arm.json",
        "tests/fixtures/evaluation/phase10d_owned_objective_inputs.json",
    ):
        fixture_text = (ROOT / relative_path).read_text(encoding="utf-8")
        assert EXPECTED_CVE_IDS.isdisjoint(
            cve_id
            for cve_id in EXPECTED_CVE_IDS
            if cve_id in fixture_text
        )


def test_existing_knowledge_retrieval_remains_local_and_reference_only(
    corpus: PublicCveCorpus,
) -> None:
    repository = InMemoryKnowledgeEntryRepository(corpus.knowledge_entries)
    query = KnowledgeRetrievalQuery.create(
        architecture=Architecture.ARM,
        text="Cortex A77 deadlock",
        entry_kinds=[KnowledgeEntryKind.CVE],
    )
    first = DeterministicKnowledgeRetriever(repository).retrieve(query)
    second = DeterministicKnowledgeRetriever(repository).retrieve(query)

    assert first == second
    assert first.knowledge_entry_ids
    assert all(type(item) is str for item in first.knowledge_entry_ids)
    assert first.metadata["retrieval_mode"] == "deterministic_local_lexical"

    imported_modules: set[str] = set()
    for relative_path in (
        "src/chipchain/corpus/models.py",
        "src/chipchain/corpus/loader.py",
    ):
        tree = ast.parse((ROOT / relative_path).read_text(encoding="utf-8"))
        imported_modules.update(
            node.module or ""
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
        )
    assert all(
        not module.startswith(
            (
                "chipchain.evaluation",
                "chipchain.hardware_trigger",
                "chipchain.runtime",
                "chipchain.verification",
            )
        )
        for module in imported_modules
    )


def test_committed_json_is_structured_and_paraphrased() -> None:
    payload = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
    assert payload["contract"] == "chipchain_public_cve_corpus_v1"
    assert payload["metadata"]["curation_scope"] == (
        "public_source_paraphrases"
    )
    assert set(payload) == {
        "contract",
        "id",
        "knowledge_entries",
        "metadata",
        "records",
    }
