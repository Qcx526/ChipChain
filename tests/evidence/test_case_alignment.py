"""Synthetic non-causal comparison scope tests; no real finding values."""

import pytest
from pydantic import ValidationError

from chipchain.core import Architecture
from chipchain.behavior.processor import ExactScalar
from chipchain.adapters.hardware_case import parse_isa_csv, parse_rtl_log
from chipchain.evidence import (
    AlignedPair, AlignmentResult, AlignmentScope, ComparableField, ComparisonOutcome,
    DivergenceObservation, EvidenceLevel, FieldComparison, align_common_program,
    divergence_context, first_observed_divergence_in_scope,
)


def test_contiguous_alignment_preserves_unpaired_occurrences_and_cov_independence(synthetic_case):
    result = synthetic_case.alignment(
        rows=[synthetic_case.csv_row(), synthetic_case.csv_row(pc=0x204, mode=""), synthetic_case.csv_row(pc=0x204)],
        rtl_rows=[synthetic_case.rtl_row(pc=0x100), synthetic_case.rtl_row(cov=80),
                  "DELAYED r1=0000000000000001", synthetic_case.rtl_row(pc=0x204, cov=5, exception=True),
                  synthetic_case.rtl_row(pc=0x204, cov=80), synthetic_case.rtl_row(pc=0x300)],
    )
    assert len(result.aligned_pairs) == 3
    assert [item.rtl_observation.record_ordinal for item in result.aligned_pairs] == [1, 3, 4]
    assert result.aligned_pairs[1].rtl_observation_id != result.aligned_pairs[2].rtl_observation_id
    assert result.unaligned_isa_observation_ids == ()
    assert result.unaligned_rtl_observation_ids == tuple(result.rtl_artifact.observations[i].id for i in (0, 2, 5))
    assert result.status == "RELIABLE_KEYS_PARTIAL_SEMANTICS"
    assert first_observed_divergence_in_scope(result) is None
    assert result.scope.isa_source.artifact_sha256 == result.isa_artifact.source.artifact_sha256


@pytest.mark.parametrize("mutation", ["pc", "encoding", "insertion", "deletion", "ambiguous", "start"])
def test_alignment_fails_closed_without_guessing(synthetic_case, mutation):
    rows = [synthetic_case.csv_row(), synthetic_case.csv_row(pc=0x204)]
    right = [synthetic_case.rtl_row(), synthetic_case.rtl_row(pc=0x204)]
    if mutation == "pc":
        right[1] = synthetic_case.rtl_row(pc=0x208)
    elif mutation == "encoding":
        right[1] = synthetic_case.rtl_row(pc=0x204, encoding="00000033")
    elif mutation == "insertion":
        right.insert(1, synthetic_case.rtl_row(pc=0x300))
    elif mutation == "deletion":
        right.pop()
    elif mutation == "ambiguous":
        right.append(synthetic_case.rtl_row())
    else:
        rows[0] = synthetic_case.csv_row(pc=0x100)
    with pytest.raises(ValueError):
        synthetic_case.alignment(rows=rows, rtl_rows=right)


def test_difference_and_context_remain_scoped(synthetic_case):
    rows = [synthetic_case.csv_row(pc=0x200 + i * 4) for i in range(4)]
    right = [synthetic_case.rtl_row(pc=0x200 + i * 4, mstatus=3 if i == 2 else 1) for i in range(4)]
    result = synthetic_case.alignment(rows=rows, rtl_rows=right)
    difference = first_observed_divergence_in_scope(result)
    assert difference.aligned_pair.alignment_ordinal == 2
    assert difference.field == ComparableField.MSTATUS
    assert difference.comparison.isa_value.value == "0x1"
    assert difference.comparison.rtl_value.value == "0x3"
    assert difference.comparison.xor.value == "0x2"
    assert difference.evidence_level == EvidenceLevel.CROSS_ARTIFACT_CORRELATED
    assert difference.scope == result.scope
    assert divergence_context(result, difference, before=1, after=1) == result.aligned_pairs[1:4]
    assert divergence_context(result, difference, before=10, after=10) == result.aligned_pairs
    restricted = synthetic_case.alignment(rows=rows, rtl_rows=right, fields=(ComparableField.FRM,))
    assert first_observed_divergence_in_scope(restricted) is None
    for before, after in ((-1, 0), (True, 0), (0, 1.5)):
        with pytest.raises(ValueError):
            divergence_context(result, difference, before=before, after=after)
    with pytest.raises(ValueError):
        divergence_context(restricted, difference)


@pytest.mark.parametrize("left,right,outcome,xor", [
    (None, None, "NOT_COMPARABLE", None),
    (None, (8, "0x1"), "MISSING_LEFT", None),
    ((8, "0x1"), None, "MISSING_RIGHT", None),
    ((8, "0x1"), (16, "0x1"), "NOT_COMPARABLE", None),
    ((8, "0x1"), (8, "0x1"), "EQUAL", None),
    ((8, "0x1"), (8, "0x3"), "DIFFERENT", "0x2"),
])
def test_comparison_outcomes_exact_missing_and_width(left, right, outcome, xor):
    value = lambda pair: None if pair is None else ExactScalar(width_bits=pair[0], value=pair[1])
    comparison = FieldComparison.create(ComparableField.MSTATUS, value(left), value(right))
    assert comparison.outcome.value == outcome
    assert (comparison.xor.value if comparison.xor is not None else None) == xor
    assert FieldComparison.model_validate_json(comparison.model_dump_json()).id == comparison.id
    invalid = comparison.model_dump(mode="json")
    invalid["outcome"] = "DIFFERENT" if outcome != "DIFFERENT" else "EQUAL"
    with pytest.raises(ValidationError):
        FieldComparison.model_validate(invalid)


def test_missing_state_stays_missing_not_difference(synthetic_case):
    row = synthetic_case.csv_row(mstatus="")
    result = synthetic_case.alignment(rows=[row])
    comparison = result.aligned_pairs[0].comparisons[0]
    assert comparison.outcome == ComparisonOutcome.MISSING_LEFT
    assert comparison.isa_value is None and comparison.xor is None
    assert first_observed_divergence_in_scope(result) is None


@pytest.mark.parametrize("fields", [(), (ComparableField.MSTATUS,) * 2, (ComparableField.FRM, ComparableField.MSTATUS), ("WDATA",), ("COV",)])
def test_comparison_scope_is_explicit_closed_and_canonical(synthetic_case, fields):
    with pytest.raises(ValidationError):
        synthetic_case.alignment(fields=fields)


def test_wrong_source_and_unchecked_nested_objects_rejected(synthetic_case):
    result = synthetic_case.alignment()
    other = parse_isa_csv(synthetic_case.csv([synthetic_case.csv_row(mstatus="2")]), architecture=Architecture.RISC_V)
    with pytest.raises(ValueError):
        align_common_program(result.scope, other, result.rtl_artifact)
    forged = result.isa_artifact.model_copy(update={"observations": (result.isa_artifact.observations[0].model_copy(update={"record_ordinal": 10}),)})
    with pytest.raises(ValidationError):
        align_common_program(result.scope, forged, result.rtl_artifact)
    source = result.scope.rtl_source.model_copy(update={"architecture": Architecture.ARM})
    scope = result.scope.model_copy(update={"rtl_source": source})
    with pytest.raises(ValidationError):
        align_common_program(scope, result.isa_artifact, result.rtl_artifact)


@pytest.mark.parametrize("mutation", ["pair_ordinal", "pair_pc", "pair_state", "pair_scope", "comparison", "pair_missing", "unpaired", "pair_duplicate"])
def test_detached_result_referential_integrity(synthetic_case, mutation):
    result = synthetic_case.alignment(rows=[synthetic_case.csv_row(), synthetic_case.csv_row(pc=0x204)],
                                      rtl_rows=[synthetic_case.rtl_row(), synthetic_case.rtl_row(pc=0x204)])
    data = result.model_dump(mode="json")
    pair = data["aligned_pairs"][0]
    if mutation == "pair_ordinal":
        pair["alignment_ordinal"] = 2
    elif mutation in ("pair_pc", "pair_state"):
        tokens = pair["rtl_observation"]["raw_line"].split()
        tokens[2 if mutation == "pair_pc" else 5] = "0x0000000208" if mutation == "pair_pc" else "0000000000000002"
        pair["rtl_observation"]["raw_line"] = " ".join(tokens)
    elif mutation == "pair_scope":
        pair["scope"]["comparable_fields"] = ["frm"]
        pair["comparisons"] = [pair["comparisons"][1]]
    elif mutation == "comparison":
        pair["comparisons"][0]["isa_value"]["value"] = "0x2"
    elif mutation == "pair_missing":
        data["aligned_pairs"].pop()
    elif mutation == "pair_duplicate":
        data["aligned_pairs"][1] = pair
    else:
        data["unaligned_rtl_observation_ids"] = ["invented"]
    with pytest.raises(ValidationError):
        AlignmentResult.model_validate(data)


def test_source_payload_cannot_be_forged_via_internally_consistent_pair(synthetic_case):
    result = synthetic_case.alignment()
    pair = result.aligned_pairs[0]
    raw = pair.isa_observation.raw_line.replace("f0:", "f1:")
    replacement = type(pair.isa_observation).model_validate(pair.isa_observation.model_copy(update={"raw_line": raw}))
    internally_consistent = AlignedPair.model_validate(pair.model_copy(update={"isa_observation": replacement}))
    with pytest.raises(ValidationError):
        AlignmentResult.model_validate(result.model_copy(update={"aligned_pairs": (internally_consistent,)}))


def test_all_results_roundtrip_and_detached_lists(synthetic_case):
    result = synthetic_case.alignment(rtl_rows=[synthetic_case.rtl_row(mstatus=3)])
    difference = first_observed_divergence_in_scope(result)
    for value in (result, result.scope, result.aligned_pairs[0], difference):
        restored = type(value).model_validate_json(value.model_dump_json())
        assert restored == value and restored.id == value.id
    pairs = list(result.aligned_pairs)
    comparisons = list(pairs[0].comparisons)
    pair = AlignedPair.model_validate({**pairs[0].model_dump(), "comparisons": comparisons})
    retained = AlignmentResult.model_validate({**result.model_dump(), "aligned_pairs": [pair]})
    stable_id = retained.id
    pairs.clear()
    comparisons.clear()
    object.__setattr__(pair.comparisons[0].isa_value, "value", "0xff")
    assert retained.id == stable_id
    with pytest.raises(ValidationError):
        retained.aligned_pairs[0].comparisons = ()


@pytest.mark.parametrize("forbidden", ["root_cause", "causal", "trigger", "necessary", "sufficient", "vulnerability", "verified", "run_id", "campaign_id", "timestamp"])
def test_no_verdict_or_invented_provenance_fields(synthetic_case, forbidden):
    result = synthetic_case.alignment(rtl_rows=[synthetic_case.rtl_row(mstatus=3)])
    difference = first_observed_divergence_in_scope(result)
    for value in (result, result.scope, result.aligned_pairs[0], difference, result.isa_artifact, result.isa_artifact.source):
        assert forbidden not in type(value).model_fields
        with pytest.raises(ValidationError):
            type(value).model_validate({**value.model_dump(mode="json"), forbidden: True})
    assert {level.value for level in EvidenceLevel} == {
        "BYTE_VERIFIED", "FORMAT_OBSERVED", "PRODUCER_DECLARED", "CROSS_ARTIFACT_CORRELATED", "INFERRED", "UNKNOWN",
    }


def test_no_level_upgrade_or_false_divergence(synthetic_case):
    result = synthetic_case.alignment()
    with pytest.raises(ValidationError):
        DivergenceObservation(aligned_pair=result.aligned_pairs[0], field=ComparableField.MSTATUS)
    data = result.isa_artifact.model_dump(mode="json")
    data["observations"][0]["evidence_level"] = "INFERRED"
    with pytest.raises(ValidationError):
        type(result.isa_artifact).model_validate(data)
