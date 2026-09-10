"""Exact artifact snapshots; content correlation is not authenticated run provenance."""

from hashlib import sha256
from typing import Annotated, Literal, Self, TypeAlias

from pydantic import Field, StringConstraints, model_validator

from chipchain.core import Architecture
from chipchain.evidence.base import EvidenceModel
from chipchain.evidence.enums import EvidenceLevel, TraceSourceSide
from chipchain.evidence.observations import CaseObservation
from chipchain.evidence._profiles import CSV_HEADER, RTL_HEADER


FormatProfile: TypeAlias = Literal[
    "confirmed_isa_csv_v1", "confirmed_isa_log_v1",
    "confirmed_rocket_rtl_log_v1", "confirmed_signature_v1",
]
Sha256 = Annotated[str, StringConstraints(strict=True, pattern=r"^[0-9a-f]{64}$")]


class EvidenceArtifactSource(EvidenceModel):
    """Declared side/profile and exact content identity; no local path or run ID."""

    _namespace = "v2-case-evidence-source-v1"
    artifact_sha256: Sha256
    byte_length: Annotated[int, Field(strict=True, gt=0)]
    architecture: Architecture
    source_side: TraceSourceSide
    format_profile_id: FormatProfile

    @model_validator(mode="after")
    def validate_profile(self) -> Self:
        if self.architecture != Architecture.RISC_V:
            raise ValueError("current local format profiles support RISC-V only")
        expected = {
            "confirmed_isa_csv_v1": TraceSourceSide.ISA_SIDE,
            "confirmed_isa_log_v1": TraceSourceSide.ISA_SIDE,
            "confirmed_rocket_rtl_log_v1": TraceSourceSide.RTL_SIDE,
        }.get(self.format_profile_id)
        if expected is not None and self.source_side != expected:
            raise ValueError("source side does not match local format profile")
        return self


class ParsedCaseArtifact(EvidenceModel):
    """Reconstruct exact bytes before establishing a record-to-source binding."""

    _namespace = "v2-parsed-case-artifact-v1"
    contract: Literal["v2_parsed_case_artifact_v1"] = "v2_parsed_case_artifact_v1"
    source: EvidenceArtifactSource
    observations: tuple[CaseObservation, ...]
    byte_binding_level: Literal[EvidenceLevel.BYTE_VERIFIED] = EvidenceLevel.BYTE_VERIFIED
    run_provenance: Literal["CORRELATED_ARTIFACT_SET"] = "CORRELATED_ARTIFACT_SET"

    def exact_bytes(self) -> bytes:
        """Reconstruct this closed profile including its header and line endings."""

        profile = self.source.format_profile_id
        header = {"confirmed_isa_csv_v1": CSV_HEADER, "confirmed_rocket_rtl_log_v1": RTL_HEADER}.get(profile)
        lines = ([header] if header is not None else []) + [item.raw_line for item in self.observations]
        ending = "\r\n" if profile == "confirmed_isa_csv_v1" else "\n"
        return (ending.join(lines) + ending).encode("ascii")

    @model_validator(mode="after")
    def validate_binding(self) -> Self:
        allowed = {
            "confirmed_isa_csv_v1": {"ISA_CSV"},
            "confirmed_isa_log_v1": {"DESCRIPTION", "COMMIT", "EXCEPTION", "LABEL_OR_CONTEXT", "OTHER_SUPPORTED"},
            "confirmed_rocket_rtl_log_v1": {"RTL_NORMAL", "RTL_EXCEPTION", "DELAYED"},
            "confirmed_signature_v1": {"SIGNATURE"},
        }[self.source.format_profile_id]
        if not self.observations:
            raise ValueError("empty artifacts are unsupported in this local profile")
        if self.source.format_profile_id == "confirmed_signature_v1" and len(self.observations) != 254:
            raise ValueError("confirmed signature profile requires exactly 254 records")
        source_id = self.source.id
        for ordinal, observation in enumerate(self.observations):
            if observation.source_id != source_id or observation.record_ordinal != ordinal:
                raise ValueError("observation source/ordinal binding mismatch")
            if observation.kind not in allowed:
                raise ValueError("observation kind incompatible with source profile")
        payload = self.exact_bytes()
        if len(payload) != self.source.byte_length or sha256(payload).hexdigest() != self.source.artifact_sha256:
            raise ValueError("reconstructed payload differs from exact source bytes")
        return self
