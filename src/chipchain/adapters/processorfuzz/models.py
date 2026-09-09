"""Immutable, byte-reconstructible raw SI contracts; no processor state claims."""

from hashlib import sha256
from typing import Annotated, ClassVar, Literal, Self

from pydantic import Field, model_validator

from chipchain.core import DomainModel, Identifier, deterministic_id
from chipchain.adapters.processorfuzz._syntax import instruction_fields


_Ordinal = Annotated[int, Field(strict=True, ge=0)]
_LineNumber = Annotated[int, Field(strict=True, ge=1)]
_Hash = Annotated[str, Field(strict=True, pattern=r"^[0-9a-f]{64}$")]
_Text = Annotated[str, Field(strict=True)]


class _RawIdentity(DomainModel):
    _namespace: ClassVar[str]

    @property
    def id(self) -> str:
        """Derive a path/time-independent, version-namespaced identity."""

        return deterministic_id(self._namespace, self.model_dump(mode="json"))


class RawSIInstructionRecord(_RawIdentity):
    """One source line, including exact spacing; never a decoded instruction."""

    _namespace = "v2-processorfuzz-si-instruction-v1"
    source_line_number: _LineNumber
    instruction_ordinal: _Ordinal
    label: _Text | None
    mnemonic: Identifier
    operand_tokens: tuple[_Text, ...]
    trailing_token: Literal["0000"] | None
    raw_line: _Text

    @property
    def raw_line_sha256(self) -> str:
        """Hash exact ASCII line bytes, excluding the LF delimiter."""

        return sha256(self.raw_line.encode("ascii")).hexdigest()

    @model_validator(mode="after")
    def validate_syntax(self) -> Self:
        """Prevent detached JSON from disagreeing with the retained source line."""

        if instruction_fields(self.raw_line) != (
            self.label, self.mnemonic, self.operand_tokens, self.trailing_token,
        ):
            raise ValueError("instruction fields disagree with exact raw line")
        return self


class RawSIDataRecord(_RawIdentity):
    """One unaddressed hex token; not a memory word, state or runtime value."""

    _namespace = "v2-processorfuzz-si-data-v1"
    source_line_number: _LineNumber
    data_ordinal: _Ordinal
    hex_token: Annotated[str, Field(strict=True, min_length=16, max_length=16, pattern=r"^[0-9a-f]{16}$")]

    @property
    def raw_line_sha256(self) -> str:
        """Hash exact data-line ASCII bytes, excluding LF."""

        return sha256(self.hex_token.encode("ascii")).hexdigest()


class RawProcessorFuzzSI(_RawIdentity):
    """Loss-preserving local syntax profile, not a universal ProcessorFuzz format.

    Retained raw lines and fixed delimiters reconstruct the exact input bytes.
    Revalidation binds syntax fields, physical positions, length and SHA together.
    """

    _namespace = "v2-processorfuzz-si-v1"
    parser_profile_id: Literal["processorfuzz_si_confirmed_v1"] = "processorfuzz_si_confirmed_v1"
    snapshot_sha256: _Hash
    byte_length: _Ordinal
    header: Literal["p-m"]
    instructions: tuple[RawSIInstructionRecord, ...] = Field(min_length=1)
    data_records: tuple[RawSIDataRecord, ...] = Field(min_length=1)

    def exact_bytes(self) -> bytes:
        """Reconstruct bytes; never normalize or read a filesystem path."""

        lines = [self.header, "", *(r.raw_line for r in self.instructions),
                 "data:", *(r.hex_token for r in self.data_records)]
        return ("\n".join(lines) + "\n").encode("ascii")

    @model_validator(mode="after")
    def validate_snapshot(self) -> Self:
        """Fail closed on duplicate labels, altered fields or snapshot mismatch."""

        labels: set[str] = set()
        families: list[str] = []
        for i, record in enumerate(self.instructions):
            if record.instruction_ordinal != i or record.source_line_number != i + 3:
                raise ValueError("instruction ordering/line position mismatch")
            if record.label is not None:
                if record.label in labels:
                    raise ValueError("duplicate label definition")
                labels.add(record.label)
                family = record.label[1]
                if not families or families[-1] != family:
                    families.append(family)
        if self.instructions[0].label is None or families != ["p", "l", "s"]:
            raise ValueError("unsupported label-family layout")
        for i, record in enumerate(self.data_records):
            if record.data_ordinal != i or record.source_line_number != len(self.instructions) + 4 + i:
                raise ValueError("data ordering/line position mismatch")
        snapshot = self.exact_bytes()
        if len(snapshot) != self.byte_length or sha256(snapshot).hexdigest() != self.snapshot_sha256:
            raise ValueError("exact byte snapshot length/SHA mismatch")
        return self
