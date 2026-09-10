"""Lossless observations with validated, read-only lexical/typed views.

Views deliberately are not separately serialized fields: hash binding and parsing
cannot disagree about which payload supplies a value. Ordinals are file order,
not retirement ordinals. Standalone records require a validated artifact bundle
before their source_id can be established as an exact byte binding.
"""

from typing import Annotated, Literal, Self, TypeAlias

from pydantic import Field, StringConstraints, model_validator

from chipchain.core import Identifier, ProgramAddress
from chipchain.behavior.processor import ExactScalar
from chipchain.evidence.base import EvidenceModel, Ordinal
from chipchain.evidence.enums import ComparableField, EvidenceLevel
from chipchain.evidence._profiles import (
    FIELD_NAMES, FIELD_WIDTHS, RTL_FIELD_INDICES, csv_columns,
    delayed_fields, hex_token, isa_log_fields, rtl_tokens,
)


class _Observation(EvidenceModel):
    source_id: Identifier
    record_ordinal: Ordinal
    raw_line: Annotated[str, StringConstraints(strict=True)]
    evidence_level: Literal[EvidenceLevel.FORMAT_OBSERVED] = EvidenceLevel.FORMAT_OBSERVED


class IsaCsvObservation(_Observation):
    """Confirmed CSV row; mixed update text does not assert GPR-only state."""

    _namespace = "v2-isa-csv-observation-v1"
    kind: Literal["ISA_CSV"] = "ISA_CSV"

    @model_validator(mode="after")
    def validate_payload(self) -> Self:
        csv_columns(self.raw_line)
        return self

    @property
    def columns(self) -> tuple[str, ...]:
        return csv_columns(self.raw_line)

    @property
    def pc(self) -> ProgramAddress:
        return ProgramAddress(value="0x" + self.columns[0])

    @property
    def instruction_encoding(self) -> str:
        return self.columns[4]

    @property
    def mode(self) -> str | None:
        return self.columns[5] or None

    @property
    def mnemonic(self) -> str:
        return self.columns[1]

    @property
    def instruction_text(self) -> str:
        return self.columns[6]

    @property
    def raw_update_text(self) -> str:
        return self.columns[2]

    def state_value(self, field: ComparableField) -> ExactScalar | None:
        """Read an approved printed state field, preserving empty tokens as None."""

        index = FIELD_NAMES.index(ComparableField(field).value)
        token = self.columns[9 + index]
        return ExactScalar(width_bits=FIELD_WIDTHS[index], value="0x" + token) if token else None


class IsaLogObservation(_Observation):
    """Description, commit, exception and context are distinct lexical kinds."""

    _namespace = "v2-isa-log-observation-v1"
    kind: Literal["DESCRIPTION", "COMMIT", "EXCEPTION", "LABEL_OR_CONTEXT", "OTHER_SUPPORTED"]

    @model_validator(mode="after")
    def validate_payload(self) -> Self:
        if isa_log_fields(self.raw_line)[0] != self.kind:
            raise ValueError("ISA log kind differs from payload")
        return self

    @property
    def lexical_fields(self) -> tuple[tuple[str, str], ...]:
        """Exact matched lexical fields; no inferred post-state or exception cause."""

        return tuple(isa_log_fields(self.raw_line)[1].items())

    @property
    def pc(self) -> ProgramAddress | None:
        token = dict(self.lexical_fields).get("pc")
        return ProgramAddress(value=token) if token is not None else None

    @property
    def instruction_encoding(self) -> str | None:
        token = dict(self.lexical_fields).get("bits")
        return token[2:] if token is not None else None


class RtlInstructionObservation(_Observation):
    """NORMAL/EXCEPTION printed records, not a physical-silicon truth assertion."""

    _namespace = "v2-rtl-instruction-observation-v1"
    kind: Literal["RTL_NORMAL", "RTL_EXCEPTION"]

    @model_validator(mode="after")
    def validate_payload(self) -> Self:
        rtl_tokens(self.raw_line, self.kind)
        return self

    @property
    def tokens(self) -> tuple[str, ...]:
        return rtl_tokens(self.raw_line, self.kind)

    @property
    def hart(self) -> int:
        return int(self.tokens[0])

    @property
    def mode(self) -> str:
        return self.tokens[1]

    @property
    def pc(self) -> ProgramAddress:
        return ProgramAddress(value=self.tokens[2])

    @property
    def instruction_encoding(self) -> str:
        return self.tokens[3][2:]

    @property
    def writeback_token(self) -> str:
        """Raw WDATA only; even a non-sentinel is not an architectural write fact."""

        return self.tokens[4]

    @property
    def is_writeback_sentinel(self) -> bool:
        return self.writeback_token == "0x00000000deadbeef"

    @property
    def cov(self) -> int:
        """Printed io_covSum, explicitly not cycle, time or retirement order."""

        return int(self.tokens[12])

    def state_value(self, field: ComparableField) -> ExactScalar:
        """Read only an audited field; internal FPR/WDATA are excluded."""

        index = FIELD_NAMES.index(ComparableField(field).value)
        return ExactScalar(width_bits=FIELD_WIDTHS[index], value="0x" + self.tokens[RTL_FIELD_INDICES[index]])


class RtlDelayedObservation(_Observation):
    """An independent delayed lexical record, with no fabricated PC association."""

    _namespace = "v2-rtl-delayed-observation-v1"
    kind: Literal["DELAYED"] = "DELAYED"

    @model_validator(mode="after")
    def validate_payload(self) -> Self:
        delayed_fields(self.raw_line)
        return self

    @property
    def lexical_fields(self) -> tuple[tuple[str, str], ...]:
        return tuple(delayed_fields(self.raw_line).items())


class SignatureObservation(_Observation):
    """An opaque 128-bit printed row, not an address or CSR layout claim."""

    _namespace = "v2-signature-observation-v1"
    kind: Literal["SIGNATURE"] = "SIGNATURE"

    @model_validator(mode="after")
    def validate_payload(self) -> Self:
        hex_token(self.raw_line, 128)
        return self

    @property
    def raw_hex_record(self) -> str:
        return self.raw_line


CaseObservation: TypeAlias = Annotated[
    IsaCsvObservation | IsaLogObservation | RtlInstructionObservation
    | RtlDelayedObservation | SignatureObservation,
    Field(discriminator="kind"),
]
