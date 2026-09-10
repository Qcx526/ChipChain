"""Single immutable byte input; no files, simulator invocations or run inference."""

from hashlib import sha256

from chipchain.core import Architecture
from chipchain.evidence import (
    EvidenceArtifactSource, FormatProfile, ParsedCaseArtifact, TraceSourceSide,
)
from chipchain.adapters.hardware_case.errors import HardwareCaseFormatError


def parse_snapshot(
    data: bytes, *, profile: FormatProfile, side: TraceSourceSide,
    architecture: Architecture, expected_sha256: str | None,
) -> ParsedCaseArtifact:
    if type(data) is not bytes:
        raise HardwareCaseFormatError("input must be an immutable bytes snapshot")
    digest = sha256(data).hexdigest()
    if expected_sha256 is not None and expected_sha256 != digest:
        raise HardwareCaseFormatError("input SHA differs from explicitly expected SHA")
    try:
        source = EvidenceArtifactSource(
            artifact_sha256=digest, byte_length=len(data), architecture=architecture,
            source_side=side, format_profile_id=profile,
        )
        text = data.decode("ascii")
        ending = "\r\n" if profile == "confirmed_isa_csv_v1" else "\n"
        if not text.endswith(ending):
            raise ValueError("final line terminator required")
        lines = text[:-len(ending)].split(ending)
        if profile == "confirmed_isa_csv_v1":
            # Exact header is checked through lossless artifact reconstruction.
            lines = lines[1:]
            kinds = ["ISA_CSV"] * len(lines)
        elif profile == "confirmed_rocket_rtl_log_v1":
            lines = lines[1:]
            kinds = ["DELAYED" if line.startswith("DELAYED ") else "RTL_EXCEPTION" if "EXCEPTION" in line.split() else "RTL_NORMAL" for line in lines]
        elif profile == "confirmed_signature_v1":
            kinds = ["SIGNATURE"] * len(lines)
        else:
            # Classification uses structural markers only; IR validates full grammar.
            kinds = [
                "DESCRIPTION" if " [" in line else "LABEL_OR_CONTEXT" if ">>>>" in line
                else "EXCEPTION" if ": exception " in line else "OTHER_SUPPORTED" if " tval " in line else "COMMIT"
                for line in lines
            ]
        return ParsedCaseArtifact.model_validate({
            "source": source,
            "observations": tuple({"kind": kind, "source_id": source.id, "record_ordinal": index, "raw_line": line} for index, (line, kind) in enumerate(zip(lines, kinds, strict=True))),
        })
    except ValueError:
        raise HardwareCaseFormatError("bytes rejected by confirmed local format/binding contract") from None
