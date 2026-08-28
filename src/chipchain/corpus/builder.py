"""Deterministic offline build pipeline for public-CVE corpus snapshots."""

from __future__ import annotations

from pathlib import Path

from chipchain.corpus.models import PublicCveCorpus, PublicCveResearchSample
from chipchain.corpus.source_models import PublicCveSourceDocument
from chipchain.knowledge import KnowledgeEntryKind, VulnerabilityKnowledgeEntry


def build_public_cve_corpus(
    source: PublicCveSourceDocument,
) -> PublicCveCorpus:
    """Derive knowledge entries, sample IDs, and corpus ID from one source."""

    snapshot = PublicCveSourceDocument.model_validate(
        source.model_dump(mode="json")
    )
    knowledge_entries: list[VulnerabilityKnowledgeEntry] = []
    samples: list[PublicCveResearchSample] = []
    for record in snapshot.records:
        entry = VulnerabilityKnowledgeEntry.create(
            entry_kind=KnowledgeEntryKind.CVE,
            external_id=record.cve_id,
            architecture=record.architecture,
            title=record.title,
            summary=record.summary,
            affected_components=record.affected_components,
            references=record.source_references,
            metadata={"corpus_role": "retrieval_only"},
        )
        knowledge_entries.append(entry)
        samples.append(
            PublicCveResearchSample.create(
                cve_id=record.cve_id,
                architecture=record.architecture,
                architecture_profile=record.architecture_profile,
                title=record.title,
                summary=record.summary,
                affected_components=record.affected_components,
                cross_layer_classification=(
                    record.cross_layer_classification
                ),
                underlying_issue_key=record.underlying_issue_key,
                related_cve_ids=record.related_cve_ids,
                trigger_summary=record.trigger_summary,
                precondition_summary=record.precondition_summary,
                hardware_effect_summary=record.hardware_effect_summary,
                source_references=record.source_references,
                admission_status=record.admission_status,
                admission_blockers=record.admission_blockers,
                knowledge_entry_id=entry.id,
                metadata={
                    "admission_scope": "staging_only",
                    "source_type": "public_advisory",
                },
            )
        )
    return PublicCveCorpus.create(
        records=samples,
        knowledge_entries=knowledge_entries,
        metadata={
            "benchmark_admission": "staging_only",
            "corpus_name": snapshot.corpus_name,
            "curation_scope": "public_source_paraphrases",
        },
    )


def serialize_public_cve_corpus(corpus: PublicCveCorpus) -> str:
    """Return stable UTF-8-ready JSON text with one final newline."""

    snapshot = PublicCveCorpus.model_validate(corpus.model_dump(mode="json"))
    return snapshot.model_dump_json(indent=2, ensure_ascii=False) + "\n"


def write_public_cve_corpus(
    corpus: PublicCveCorpus,
    path: str | Path,
) -> None:
    """Write one deterministic generated snapshot without external state."""

    Path(path).write_text(
        serialize_public_cve_corpus(corpus),
        encoding="utf-8",
    )
