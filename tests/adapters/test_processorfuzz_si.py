"""Permanent synthetic-only SI contracts; never read local hardware artifacts."""

from hashlib import sha256

import pytest
from pydantic import ValidationError

from chipchain.adapters.processorfuzz import (
    PARSER_PROFILE_ID, ProcessorFuzzSIIntegrityError, ProcessorFuzzSIParseError,
    RawProcessorFuzzSI, RawSIDataRecord, RawSIInstructionRecord, UnsupportedSIProfileError,
    map_processorfuzz_si, parse_processorfuzz_si,
)
from chipchain.behavior.processor import (
    BehaviorFactNature, BehaviorRelationKind, DeclaredOperand, InstructionBehavior,
    ProcessorBehaviorFragment, RegisterOperand,
)
from chipchain.core import ProcessorFuzzArtifact, deterministic_id


def replace_line(data, index, text):
    lines = data.decode("ascii").splitlines()
    lines[index] = text
    return ("\n".join(lines) + "\n").encode("ascii")


def test_exact_snapshot_structure_and_order(synthetic_si):
    raw = parse_processorfuzz_si(synthetic_si)
    assert raw.parser_profile_id == PARSER_PROFILE_ID
    assert raw.header == "p-m" and raw.byte_length == len(synthetic_si)
    assert raw.snapshot_sha256 == sha256(synthetic_si).hexdigest()
    assert raw.exact_bytes() == synthetic_si
    assert len(raw.instructions) == 7 and len(raw.data_records) == 2
    assert [r.instruction_ordinal for r in raw.instructions] == list(range(7))
    assert [r.source_line_number for r in raw.instructions] == list(range(3, 10))
    assert [r.label for r in raw.instructions] == ["_p0", "_l0", None, "_l1", None, None, "_s0"]
    assert raw.instructions[0].operand_tokens == ("x1", "zero", "0000")
    assert raw.instructions[0].trailing_token is None
    assert raw.instructions[1].trailing_token == "0000"
    assert raw.instructions[3].operand_tokens == ("x3", "-0(x1)")
    assert raw.instructions[4].operand_tokens[-1] == "_l999"
    assert raw.instructions[5].operand_tokens[-1] == "0xffe00"
    assert [r.data_ordinal for r in raw.data_records] == [0, 1]
    assert [r.source_line_number for r in raw.data_records] == [11, 12]
    for record in raw.instructions:
        assert record.raw_line_sha256 == sha256(record.raw_line.encode("ascii")).hexdigest()
    for record in raw.data_records:
        assert record.raw_line_sha256 == sha256(record.hex_token.encode("ascii")).hexdigest()


@pytest.mark.parametrize("line,operands,trailer", [
    ("_l0:    addi x1, x2, 0000", ("x1", "x2", "0000"), None),
    ("_l0:    addi x1, x2,   0000", ("x1", "x2", "0000"), None),
    ("_l0:    addi x1, x2,".ljust(50) + "0000", ("x1", "x2", "0000"), None),
    ("_l0:    addi x1, x2, 0000".ljust(50) + "0000", ("x1", "x2", "0000"), "0000"),
    ("_l0:    sret".ljust(50) + "0000", (), "0000"),
    ("_l0:    addi x1, x2, 0".ljust(50) + "0000   ", ("x1", "x2", "0"), "0000"),
])
def test_trailer_not_confused_with_operand(synthetic_si, line, operands, trailer):
    raw = parse_processorfuzz_si(replace_line(synthetic_si, 3, line))
    assert raw.instructions[1].operand_tokens == operands
    assert raw.instructions[1].trailing_token == trailer
    assert raw.instructions[1].raw_line == line


@pytest.mark.parametrize("line", [
    "_l0:    li".ljust(50) + "0000",  # Ambiguous numeric first operand, not silently stripped.
    "_l0:    addi x1, x2, 0  0000",  # Wrong trailer column.
    "_l0:    addi x1, x2, 0".ljust(50) + "0001",
])
def test_ambiguous_or_unknown_trailer_fails_closed(synthetic_si, line):
    with pytest.raises(ProcessorFuzzSIParseError):
        parse_processorfuzz_si(replace_line(synthetic_si, 3, line))


@pytest.mark.parametrize("index,line", [
    (0, "p-s"), (0, "v-u"), (0, "p-m "), (1, " "), (1, "# comment"),
    (2, "_p-1:   addi x1, zero, 0"), (2, "_p00:   addi x1, zero, 0"),
    (2, "_q0:    addi x1, zero, 0"), (2, "_p0 addi x1, zero, 0"),
    (2, "_p0:"), (2, "_p0:    .word 1234"), (2, "_p0:    ADDI x1, zero, 0"),
    (2, "_p0:    addi x1,,zero"), (2, "_p0:    addi x1, zero,"),
    (2, "_p0:    addi x32, zero, 0"), (2, "_p0:    addi x01, zero, 0"),
    (2, "_p0:    fadd.s f32, f1, f2"), (2, "_p0:    lw x1, 0(x32)"),
    (2, "_p0:    li x1, 0xGG"), (2, "_p0:    csrrw x1, unknown_csr, x2"),
    (2, "_p0:    la x1, symbol+4"), (2, "_p0:    li x1, 3 # comment"),
    (2, "# comment"), (2, "; comment"), (2, "// comment"), (2, ""),
    (2, "_p0:    unknown_directive"),
    (5, "_l0:    lw x3, 0(x1)"),  # Duplicate label.
    (8, "_p1:    fence"),  # Unsupported family order.
    (9, "data: "), (10, "000000000000000"), (10, "000000000000000G"),
    (10, "FFFFFFFFFFFFFFFF"), (10, "0000000000000000 "), (10, "data:"),
])
def test_malformed_or_unobserved_syntax_rejected(synthetic_si, index, line):
    with pytest.raises(ProcessorFuzzSIParseError) as error:
        parse_processorfuzz_si(replace_line(synthetic_si, index, line))
    assert synthetic_si.decode() not in str(error.value)
    if len(line) > 10:
        assert line not in str(error.value)


@pytest.mark.parametrize("mutation", ["crlf", "cr", "tab", "bom", "utf8", "bad_utf8", "nul", "del", "no_lf", "empty", "extra_blank"])
def test_strict_bytes_and_newlines(synthetic_si, mutation):
    cases = {
        "crlf": synthetic_si.replace(b"\n", b"\r\n"), "cr": synthetic_si + b"\r",
        "tab": synthetic_si.replace(b"        ", b"\t", 1), "bom": b"\xef\xbb\xbf" + synthetic_si,
        "utf8": synthetic_si + "中文".encode(), "bad_utf8": synthetic_si + b"\xff",
        "nul": synthetic_si + b"\x00", "del": synthetic_si + b"\x7f",
        "no_lf": synthetic_si[:-1], "empty": b"", "extra_blank": synthetic_si + b"\n",
    }
    with pytest.raises(ProcessorFuzzSIParseError):
        parse_processorfuzz_si(cases[mutation])


def test_no_implicit_profile_or_mutable_bytes(synthetic_si):
    with pytest.raises(UnsupportedSIProfileError):
        parse_processorfuzz_si(synthetic_si, parser_profile_id="universal")
    for data in (bytearray(synthetic_si), memoryview(synthetic_si), synthetic_si.decode()):
        with pytest.raises(ProcessorFuzzSIParseError):
            parse_processorfuzz_si(data)


def test_identity_roundtrip_exact_whitespace_and_filename_independence(synthetic_si, tmp_path):
    raw = parse_processorfuzz_si(synthetic_si)
    assert raw.id == deterministic_id("v2-processorfuzz-si-v1", raw.model_dump(mode="json"))
    assert RawProcessorFuzzSI.model_validate_json(raw.model_dump_json()).id == raw.id
    for record in (*raw.instructions, *raw.data_records):
        assert type(record).model_validate_json(record.model_dump_json()).id == record.id
    for name in ("synthetic-a.si", "synthetic-b.si"):
        path = tmp_path / name
        path.write_bytes(synthetic_si)  # Only synthetic data, never a local hardware artifact.
        assert parse_processorfuzz_si(path.read_bytes()).id == raw.id
    changed = synthetic_si.replace(b"_p0:    addi", b"_p0:     addi", 1)
    other = parse_processorfuzz_si(changed)
    assert other.instructions[0].operand_tokens == raw.instructions[0].operand_tokens
    assert other.id != raw.id and other.snapshot_sha256 != raw.snapshot_sha256
    assert other.exact_bytes() == changed


@pytest.mark.parametrize("field", ["snapshot_sha256", "byte_length", "mnemonic", "operand_tokens", "raw_line", "instruction_ordinal", "source_line_number", "data_ordinal", "data_token", "label", "trailing_token", "profile", "header", "ordering"])
def test_raw_snapshot_tampering_rejected(synthetic_si, field):
    payload = parse_processorfuzz_si(synthetic_si).model_dump(mode="json")
    if field == "snapshot_sha256": payload[field] = "a" * 64
    elif field == "byte_length": payload[field] += 1
    elif field == "data_ordinal": payload["data_records"][0][field] = 3
    elif field == "data_token": payload["data_records"][0]["hex_token"] = "1" * 16
    elif field == "profile": payload["parser_profile_id"] = "future_v2"
    elif field == "header": payload["header"] = "p-s"
    elif field == "ordering": payload["instructions"].reverse()
    else:
        payload["instructions"][0][field] = {
            "mnemonic": "sub", "operand_tokens": ["x2"], "raw_line": "_p0:    addi x1, zero, 1",
            "instruction_ordinal": 99, "source_line_number": 99, "label": "_p1", "trailing_token": "0000",
        }[field]
    with pytest.raises(ValidationError):
        RawProcessorFuzzSI.model_validate(payload)


def test_standalone_raw_record_integrity(synthetic_si):
    record = parse_processorfuzz_si(synthetic_si).instructions[0]
    with pytest.raises(ValidationError):
        RawSIInstructionRecord.model_validate({**record.model_dump(), "operand_tokens": ("x9",)})
    with pytest.raises(ValidationError):
        RawSIDataRecord(source_line_number=1, data_ordinal=0, hex_token="0" * 16 + "\n")


def test_mapper_binding_and_only_source_sequence(synthetic_si, synthetic_source):
    raw = parse_processorfuzz_si(synthetic_si)
    result = map_processorfuzz_si(raw, synthetic_source)
    assert result.source.artifact == synthetic_source.provenance
    assert result.source.processor_fuzz == synthetic_source
    assert result.source.hardware_target == synthetic_source.hardware_target
    assert result.source.producer_profile_id == synthetic_source.provenance.producer_profile_id
    assert len(result.elements) == len(raw.instructions)
    assert all(type(i) is InstructionBehavior for i in result.elements)
    assert {i.nature for i in (*result.elements, *result.relations)} == {BehaviorFactNature.SOURCE_DECLARED}
    assert {e.relation for e in result.relations} == {BehaviorRelationKind.SOURCE_SEQUENCE}
    ordered = sorted(result.elements, key=lambda i: i.source_ordinal)
    assert [(i.mnemonic, i.source_ordinal) for i in ordered] == [(i.mnemonic, i.instruction_ordinal) for i in raw.instructions]
    assert {(r.source_id, r.target_id) for r in result.relations} == {(a.id, b.id) for a,b in zip(ordered, ordered[1:])}
    assert all(i.program_address is None and i.encoding_hex is None and i.size_bytes is None for i in ordered)
    assert result.source.hardware_target.hardware_revision is None
    assert result.source.hardware_target.instruction_set_profile_id is None
    assert ProcessorBehaviorFragment.model_validate_json(result.model_dump_json()).id == result.id
    assert map_processorfuzz_si(raw, synthetic_source).id == result.id


def test_conservative_operand_classification(synthetic_si, synthetic_source):
    result = map_processorfuzz_si(parse_processorfuzz_si(synthetic_si), synthetic_source)
    ordered = sorted(result.elements, key=lambda i: i.source_ordinal)
    gpr = ordered[0].operands[1]
    assert isinstance(gpr, RegisterOperand) and gpr.register_ref.name == "zero"
    assert gpr.register_ref.register_class.value == "gpr"
    assert ordered[1].operands[0].register_ref.register_class.value == "floating_point"
    csr = ordered[2].operands[1].register_ref
    assert csr.namespace == "csr" and csr.name == "mstatus" and csr.register_class.value == "system"
    for op in (ordered[0].operands[2], ordered[1].operands[-1], ordered[3].operands[1], ordered[4].operands[1], ordered[5].operands[1]):
        assert isinstance(op, DeclaredOperand)
    assert ordered[0].operands[2].text == "0000"
    assert ordered[3].operands[1].text == "-0(x1)"


@pytest.mark.parametrize("instruction", [
    "lw x1, 0(x2)", "sw x1, 0(x2)", "amoadd.w x1, x2, (x3)",
    "csrrw x1, mstatus, x2", "jal x1, _l999", "jalr x1, 0(x2)",
    "bne x1, x2, _l999", "mret", "sret", "uret",
])
def test_effect_like_text_emits_only_instruction(synthetic_si, synthetic_source, instruction):
    data = replace_line(synthetic_si, 5, "_l1:    " + instruction)
    payload = synthetic_source.model_dump(mode="json")
    payload["provenance"]["artifact_sha256"] = sha256(data).hexdigest()
    source = ProcessorFuzzArtifact.model_validate(payload)
    result = map_processorfuzz_si(parse_processorfuzz_si(data), source)
    assert all(type(i) is InstructionBehavior for i in result.elements)
    assert all(r.relation == BehaviorRelationKind.SOURCE_SEQUENCE for r in result.relations)
    assert all(r.nature == BehaviorFactNature.SOURCE_DECLARED for r in (*result.elements, *result.relations))


@pytest.mark.parametrize("instruction", ["ecall", "ebreak"])
def test_unobserved_bare_forms_do_not_manufacture_events(synthetic_si, instruction):
    # Not observed in the current confirmed SI; this profile does not guess
    # additional bare forms from the discarded candidate collection.
    with pytest.raises(ProcessorFuzzSIParseError):
        parse_processorfuzz_si(replace_line(synthetic_si, 5, "_l1:    " + instruction))


def test_supported_csr_vocabulary_is_only_confirmed_case(synthetic_si, synthetic_source):
    names = {
        "fcsr", "mcause", "mepc", "mip", "mstatus", "mtval", "pmpaddr1", "pmpaddr2",
        "pmpaddr6", "pmpaddr7", "pmpcfg0", "scause", "sepc", "sip", "sstatus", "uepc",
    }
    for name in sorted(names):
        data = replace_line(synthetic_si, 4, f"        csrrw x2, {name}, x1")
        payload = synthetic_source.model_dump(mode="json")
        payload["provenance"]["artifact_sha256"] = sha256(data).hexdigest()
        result = map_processorfuzz_si(parse_processorfuzz_si(data), ProcessorFuzzArtifact.model_validate(payload))
        inst = next(i for i in result.elements if i.source_ordinal == 2)
        assert inst.operands[1].register_ref.name == name
        assert inst.operands[1].register_ref.namespace == "csr"
    with pytest.raises(ProcessorFuzzSIParseError):
        parse_processorfuzz_si(replace_line(synthetic_si, 4, "        csrrw x2, satp, x1"))


def test_lexical_parse_does_not_claim_isa_validity(synthetic_si):
    # A mnemonic with supported operand syntax is still an uninterpreted source
    # declaration, not a supported ISA operation or semantic decoder result.
    raw = parse_processorfuzz_si(replace_line(synthetic_si, 5, "_l1:    syntheticop x1, x2"))
    assert raw.instructions[3].mnemonic == "syntheticop"


@pytest.mark.parametrize("token", ["x0", "x31", "f0", "f31", "zero"])
def test_register_endpoints_keep_literal_spelling(synthetic_si, synthetic_source, token):
    data = replace_line(synthetic_si, 2, f"_p0:    addi {token}, zero, 1")
    source = ProcessorFuzzArtifact.model_validate({**synthetic_source.model_dump(), "provenance": {
        **synthetic_source.provenance.model_dump(), "artifact_sha256": sha256(data).hexdigest(),
    }})
    result = map_processorfuzz_si(parse_processorfuzz_si(data), source)
    first = min(result.elements, key=lambda i: i.source_ordinal)
    assert first.operands[0].register_ref.name == token  # Lexical classification, not ISA validity.


@pytest.mark.parametrize("mode", ["sha", "arm", "invalid_raw", "invalid_source"])
def test_mapper_fails_closed(synthetic_si, synthetic_source, mode):
    raw = parse_processorfuzz_si(synthetic_si)
    source = synthetic_source
    if mode == "sha":
        p = source.model_dump(mode="json"); p["provenance"]["artifact_sha256"] = "a" * 64
        source = ProcessorFuzzArtifact.model_validate(p)
    elif mode == "arm":
        p = source.model_dump(mode="json"); p["provenance"]["architecture"] = "arm"; p["hardware_target"]["architecture"] = "arm"
        source = ProcessorFuzzArtifact.model_validate(p)
    elif mode == "invalid_raw":
        object.__setattr__(raw.instructions[0], "mnemonic", "tampered")
    else:
        object.__setattr__(source.provenance, "producer_profile_id", None)
    with pytest.raises(ProcessorFuzzSIIntegrityError):
        map_processorfuzz_si(raw, source)


def test_detachment_and_identity_not_affected_by_caller_mutation(synthetic_si, synthetic_source):
    raw = parse_processorfuzz_si(synthetic_si)
    payload = raw.model_dump(mode="json")
    retained = RawProcessorFuzzSI.model_validate(payload)
    before, identity = retained.model_dump_json(), retained.id
    payload["instructions"][0]["operand_tokens"].clear()
    payload["data_records"].clear()
    assert retained.model_dump_json() == before and retained.id == identity
    reconstructed = RawProcessorFuzzSI.model_validate(raw)
    result = map_processorfuzz_si(raw, synthetic_source)
    result_before, result_id = result.model_dump_json(), result.id
    object.__setattr__(raw.instructions[0], "mnemonic", "bad")
    object.__setattr__(synthetic_source.hardware_target, "hardware_model", "changed")
    assert reconstructed.model_dump_json() == before
    assert result.model_dump_json() == result_before and result.id == result_id
    with pytest.raises(ValidationError):
        retained.instructions[0].label = "_p1"
    with pytest.raises(ValidationError):
        retained.data_records = ()


def test_no_forbidden_raw_fields(synthetic_si):
    raw = parse_processorfuzz_si(synthetic_si)
    for field in ("path", "filename", "confidence", "verified", "trigger", "program_address", "encoding_hex", "size_bytes", "privilege", "runtime", "verdict"):
        for model in (raw, raw.instructions[0], raw.data_records[0]):
            assert field not in type(model).model_fields
            with pytest.raises(ValidationError):
                type(model).model_validate({**model.model_dump(), field: "forbidden"})
