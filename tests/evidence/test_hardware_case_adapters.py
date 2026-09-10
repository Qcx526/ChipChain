"""Benign format-only adapter regressions, never a real divergence fixture."""

from hashlib import sha256

import pytest
from pydantic import ValidationError

from chipchain.core import Architecture
from chipchain.adapters.hardware_case import (
    HardwareCaseFormatError, parse_isa_csv, parse_isa_log, parse_rtl_log, parse_signature,
)
from chipchain.evidence import (
    ComparableField, EvidenceArtifactSource, ParsedCaseArtifact,
    RtlDelayedObservation, TraceSourceSide,
)


def test_csv_lossless_typed_and_missing_mode(synthetic_case):
    row = synthetic_case.csv_row(mode="")
    row[7] = 'opaque,"operand"'
    payload = synthetic_case.csv([row])
    result = parse_isa_csv(payload, architecture=Architecture.RISC_V)
    item = result.observations[0]
    assert result.exact_bytes() == payload
    restored = ParsedCaseArtifact.model_validate_json(result.model_dump_json())
    assert restored.id == result.id and restored.exact_bytes() == payload
    assert tuple(item.id for item in restored.observations) == tuple(item.id for item in result.observations)
    assert result.source.artifact_sha256 == sha256(payload).hexdigest()
    assert result.source.byte_length == len(payload)
    assert result.run_provenance == "CORRELATED_ARTIFACT_SET"
    assert item.pc.value == "0x200"
    assert item.instruction_encoding == "00000013"
    assert item.mnemonic == item.instruction_text == "nop"
    assert item.mode is None
    assert item.raw_update_text == row[2]  # mixed FPR/CSR lexical updates
    assert item.columns[7] == row[7]
    assert item.state_value(ComparableField.MSTATUS).value == "0x1"


@pytest.mark.parametrize("column,value", [
    (0, "200"), (0, "00000000000002gg"), (0, "0x00000000000200"),
    (4, "0000001"), (4, "000000zz"), (4, "000000AF"),
    (5, "unknown"), (5, "4"), (9, "10000000000000000"),
    (10, "8"), (11, "20"), (12, "100"), (15, "100000000"),
    (1, ""), (6, ""),
])
def test_csv_bad_typed_fields(synthetic_case, column, value):
    row = synthetic_case.csv_row()
    row[column] = value
    with pytest.raises(HardwareCaseFormatError):
        parse_isa_csv(synthetic_case.csv([row]), architecture=Architecture.RISC_V)


@pytest.mark.parametrize("mutation", ["header", "extra_column", "missing_column", "extra_header", "empty_row", "lf", "no_final", "quote", "nul"])
def test_csv_malformed_snapshot(synthetic_case, mutation):
    payload = synthetic_case.csv()
    row = synthetic_case.csv_row()
    if mutation == "header":
        payload = payload.replace(b"pc,instr,", b"address,instr,", 1)
    elif mutation == "extra_column":
        payload = synthetic_case.csv([row + ["extra"]])
    elif mutation == "missing_column":
        payload = synthetic_case.csv([row[:-1]])
    elif mutation == "extra_header":
        payload += synthetic_case.header.encode() + b"\r\n"
    elif mutation == "empty_row":
        payload += b"\r\n"
    elif mutation == "lf":
        payload = payload.replace(b"\r\n", b"\n")
    elif mutation == "no_final":
        payload = payload[:-2]
    elif mutation == "quote":
        payload = payload.replace(b",nop,", b',no"p,', 1)
    else:
        payload += b"\x00\r\n"
    with pytest.raises(HardwareCaseFormatError):
        parse_isa_csv(payload, architecture=Architecture.RISC_V)


def test_isa_log_preserves_distinct_kinds_and_lexical_fields(synthetic_case):
    payload = synthetic_case.isa_log()
    result = parse_isa_log(payload, architecture=Architecture.RISC_V)
    assert result.exact_bytes() == payload
    assert [item.kind for item in result.observations] == [
        "LABEL_OR_CONTEXT", "DESCRIPTION", "COMMIT", "COMMIT", "EXCEPTION", "OTHER_SUPPORTED",
    ]
    assert result.observations[0].pc is None
    assert result.observations[1].pc.value == "0x200"
    assert result.observations[1].instruction_encoding == "00000013"
    assert "mem " in dict(result.observations[3].lexical_fields)["updates"]
    assert "post_state" not in result.observations[3].model_dump()


@pytest.mark.parametrize("line", [
    "unknown record", "core   0: 3 0x200 (0x00000013)",
    "core   0: 3 0x0000000000000200 (0x00000013) invented_update",
    "core   0: 3 0x0000000000000200 (0x00000013) x32 0x0000000000000000",
    "core   0: 0x0000000000000200 (0x00000013) [0x1,0] nop",
    "core   0: exception nonsense", "core   0:           tval 0xgg",
    "core   0: >>>>  bad label", "core\t0: >>>>  label",
])
def test_isa_log_rejects_structural_corruption(line):
    with pytest.raises(HardwareCaseFormatError):
        parse_isa_log((line + "\n").encode(), architecture=Architecture.RISC_V)


def test_rtl_distinct_kinds_cov_and_sentinel(synthetic_case):
    rows = [synthetic_case.rtl_row(cov=999, sentinel=True),
            "DELAYED r5=0000000000000001", "DELAYED f0=0000000000000002 00",
            synthetic_case.rtl_row(pc=0x204, cov=1, exception=True)]
    payload = synthetic_case.rtl(rows)
    result = parse_rtl_log(payload, architecture=Architecture.RISC_V)
    assert result.exact_bytes() == payload
    assert [item.kind for item in result.observations] == ["RTL_NORMAL", "DELAYED", "DELAYED", "RTL_EXCEPTION"]
    first, *_, last = result.observations
    assert (first.record_ordinal, last.record_ordinal) == (0, 3)
    assert (first.cov, last.cov) == (999, 1)
    assert first.is_writeback_sentinel
    assert first.writeback_token == "0x00000000deadbeef"
    assert not hasattr(first, "architectural_value")
    assert not hasattr(first, "cycle")
    assert not hasattr(first, "timestamp")
    assert first.hart == 0 and first.mode == "3"
    assert isinstance(result.observations[1], RtlDelayedObservation)
    assert not hasattr(result.observations[1], "pc")
    assert dict(result.observations[2].lexical_fields)["value"] == "0000000000000002"
    assert not hasattr(result.observations[2], "ieee_value")


@pytest.mark.parametrize("exception", [False, True])
@pytest.mark.parametrize("index,value", [(0, "2"), (1, "4"), (2, "0x200"), (2, "0x00000002gg"),
    (3, "0x123"), (3, "0x000000gg"), (4, "0xdeadbeef"), (5, "1"),
    (12, "-1"), (12, "1073741824"), (26, "ff"), (27, "8"), (48, "80000000")])
def test_rtl_bad_tokens(synthetic_case, exception, index, value):
    tokens = synthetic_case.rtl_row(exception=exception).split()
    actual_index = index + (1 if exception and index >= 13 else 0)
    tokens[actual_index] = value
    with pytest.raises(HardwareCaseFormatError):
        parse_rtl_log(synthetic_case.rtl([" ".join(tokens)]), architecture=Architecture.RISC_V)


@pytest.mark.parametrize("line", ["DELAYED r32=0000000000000000", "DELAYED r1=1",
    "DELAYED r1=0000000000000000 00", "DELAYED f1=0000000000000000",
    "DELAYED f1=0000000000000000 ff", "DELAYED x1=0000000000000000",
    "DELAYED f1=000000000000000G 00", "DELAYED r1=0000000000000000 extra"])
def test_bad_delayed(synthetic_case, line):
    with pytest.raises(HardwareCaseFormatError):
        parse_rtl_log(synthetic_case.rtl([line]), architecture=Architecture.RISC_V)


@pytest.mark.parametrize("mutation", ["header", "short", "long", "exception_marker", "empty", "trailing"])
def test_rtl_malformed_shape(synthetic_case, mutation):
    row = synthetic_case.rtl_row(exception=mutation == "exception_marker")
    if mutation == "short":
        row = " ".join(row.split()[:-1])
    elif mutation == "long":
        row += " 00"
    elif mutation == "exception_marker":
        row = row.replace("EXCEPTION", "UNKNOWN")
    elif mutation == "empty":
        row = ""
    payload = synthetic_case.rtl([row])
    if mutation == "header":
        payload = payload.replace(b"COV", b"CYCLE", 1)
    elif mutation == "trailing":
        payload += b"garbage\n"
    with pytest.raises(HardwareCaseFormatError):
        parse_rtl_log(payload, architecture=Architecture.RISC_V)


def test_signature_sides_opaque_and_lossless(synthetic_case):
    payload = synthetic_case.signature()
    results = [parse_signature(payload, source_side=side, architecture=Architecture.RISC_V) for side in TraceSourceSide]
    for result in results:
        assert result.exact_bytes() == payload
        assert len(result.observations) == 254
        assert result.observations[1].raw_hex_record == f"{1:032x}"
        assert not hasattr(result.observations[1], "pc")
        assert not hasattr(result.observations[1], "csr")
    assert results[0].id != results[1].id
    assert results[0].observations[0].id != results[1].observations[0].id


@pytest.mark.parametrize("mutation", ["short", "long", "uppercase", "nonhex", "missing_row", "extra_row", "blank", "no_final"])
def test_signature_rejects_malformed_snapshot(synthetic_case, mutation):
    lines = synthetic_case.signature().decode().splitlines()
    if mutation == "short":
        lines[0] = "0" * 31
    elif mutation == "long":
        lines[0] = "0" * 33
    elif mutation == "uppercase":
        lines[0] = "A" * 32
    elif mutation == "nonhex":
        lines[0] = "g" * 32
    elif mutation == "missing_row":
        lines.pop()
    elif mutation == "extra_row":
        lines.append("0" * 32)
    elif mutation == "blank":
        lines[0] = ""
    payload = ("\n".join(lines) + ("" if mutation == "no_final" else "\n")).encode()
    with pytest.raises(HardwareCaseFormatError):
        parse_signature(payload, source_side=TraceSourceSide.ISA_SIDE, architecture=Architecture.RISC_V)


@pytest.mark.parametrize("name", ["csv", "isa_log", "rtl", "signature"])
def test_exact_sha_architecture_and_input_type_boundaries(synthetic_case, name):
    parser = {"csv": parse_isa_csv, "isa_log": parse_isa_log, "rtl": parse_rtl_log, "signature": parse_signature}[name]
    payload = getattr(synthetic_case, name)()
    kwargs = {"source_side": TraceSourceSide.ISA_SIDE} if name == "signature" else {}
    result = parser(payload, architecture=Architecture.RISC_V, expected_sha256=sha256(payload).hexdigest(), **kwargs)
    assert result.exact_bytes() == payload
    with pytest.raises(HardwareCaseFormatError):
        parser(payload, architecture=Architecture.RISC_V, expected_sha256="0" * 64, **kwargs)
    with pytest.raises(HardwareCaseFormatError):
        parser(payload, architecture=Architecture.ARM, **kwargs)
    with pytest.raises(HardwareCaseFormatError):
        parser(bytearray(payload), architecture=Architecture.RISC_V, **kwargs)
    with pytest.raises(HardwareCaseFormatError):
        parser(payload.decode(), architecture=Architecture.RISC_V, **kwargs)


def test_artifact_roundtrip_and_nested_source_binding(synthetic_case):
    artifact = parse_isa_csv(synthetic_case.csv(), architecture=Architecture.RISC_V)
    assert ParsedCaseArtifact.model_validate_json(artifact.model_dump_json()) == artifact
    assert ParsedCaseArtifact.model_validate_json(artifact.model_dump_json()).id == artifact.id
    for mutation in ("sha", "length", "source_id", "raw_line", "ordinal", "side", "profile", "arch"):
        data = artifact.model_dump(mode="json")
        if mutation == "sha":
            data["source"]["artifact_sha256"] = "0" * 64
        elif mutation == "length":
            data["source"]["byte_length"] += 1
        elif mutation in ("side", "profile", "arch"):
            key, value = {"side": ("source_side", "RTL_SIDE"), "profile": ("format_profile_id", "future_v2"), "arch": ("architecture", "arm")}[mutation]
            data["source"][key] = value
        elif mutation == "source_id":
            data["observations"][0]["source_id"] = "another-source"
        elif mutation == "ordinal":
            data["observations"][0]["record_ordinal"] = 1
        else:
            data["observations"][0]["raw_line"] = data["observations"][0]["raw_line"].replace("nop", "opaque")
        with pytest.raises(ValidationError):
            ParsedCaseArtifact.model_validate(data)
    forged = artifact.model_copy(update={"observations": (artifact.observations[0].model_copy(update={"raw_line": "broken"}),)})
    with pytest.raises(ValidationError):
        ParsedCaseArtifact.model_validate(forged)


def test_duplicate_and_repeated_pc_ordinals(synthetic_case):
    row = synthetic_case.csv_row()
    artifact = parse_isa_csv(synthetic_case.csv([row, row]), architecture=Architecture.RISC_V)
    first, second = artifact.observations
    assert first.pc == second.pc and first.raw_line == second.raw_line
    assert first.id != second.id
    data = artifact.model_dump(mode="json")
    data["observations"][1]["record_ordinal"] = 0
    with pytest.raises(ValidationError):
        ParsedCaseArtifact.model_validate(data)
    single = parse_isa_csv(synthetic_case.csv([row]), architecture=Architecture.RISC_V)
    assert single.observations[0].id != first.id  # exact source SHA participates


def test_retained_artifact_is_detached_and_immutable(synthetic_case):
    artifact = parse_isa_csv(synthetic_case.csv(), architecture=Architecture.RISC_V)
    source = artifact.source
    records = list(artifact.observations)
    retained = ParsedCaseArtifact(source=source, observations=records)
    original_id = retained.id
    records.clear()
    object.__setattr__(source, "artifact_sha256", "0" * 64)
    object.__setattr__(artifact.observations[0], "raw_line", "corrupt")
    assert len(retained.observations) == 1 and retained.id == original_id
    assert isinstance(retained.observations, tuple)
    with pytest.raises(ValidationError):
        retained.observations = ()
    with pytest.raises(ValidationError):
        retained.observations[0].record_ordinal = 2
    assert EvidenceArtifactSource.model_validate_json(retained.source.model_dump_json()).id == retained.source.id


@pytest.mark.parametrize("name", ["csv", "isa_log", "rtl", "signature"])
def test_full_byte_reconstruction_even_with_rebound_record_ids(synthetic_case, name):
    parser = {"csv": parse_isa_csv, "isa_log": parse_isa_log, "rtl": parse_rtl_log, "signature": parse_signature}[name]
    kwargs = {"source_side": TraceSourceSide.ISA_SIDE} if name == "signature" else {}
    artifact = parser(getattr(synthetic_case, name)(), architecture=Architecture.RISC_V, **kwargs)
    restored = ParsedCaseArtifact.model_validate_json(artifact.model_dump_json())
    assert restored.id == artifact.id and restored.exact_bytes() == artifact.exact_bytes()
    assert tuple(item.id for item in restored.observations) == tuple(item.id for item in artifact.observations)
    forged = artifact.model_dump(mode="json")
    forged["source"]["artifact_sha256"] = "0" * 64
    rebound_source = EvidenceArtifactSource.model_validate(forged["source"])
    for record in forged["observations"]:
        record["source_id"] = rebound_source.id
    # Source and every record reference now agree; exact reconstruction still rejects.
    with pytest.raises(ValidationError, match="reconstructed payload"):
        ParsedCaseArtifact.model_validate(forged)


@pytest.mark.parametrize("ordinal", [-1, True, "0", 1.0])
def test_ordinal_is_strict_not_coerced(synthetic_case, ordinal):
    artifact = parse_isa_csv(synthetic_case.csv(), architecture=Architecture.RISC_V)
    record = artifact.observations[0]
    with pytest.raises(ValidationError):
        type(record).model_validate({**record.model_dump(), "record_ordinal": ordinal})


def test_log_kind_and_profile_substitution_rejected(synthetic_case):
    artifact = parse_isa_log(synthetic_case.isa_log(), architecture=Architecture.RISC_V)
    description = artifact.observations[1]
    with pytest.raises(ValidationError):
        type(description).model_validate({**description.model_dump(), "kind": "COMMIT"})
    data = artifact.model_dump(mode="json")
    data["source"]["format_profile_id"] = "confirmed_signature_v1"
    replacement = EvidenceArtifactSource.model_validate(data["source"])
    for record in data["observations"]:
        record["source_id"] = replacement.id
    with pytest.raises(ValidationError):
        ParsedCaseArtifact.model_validate(data)
