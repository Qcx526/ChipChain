"""Benign synthetic format-only SI; no real ProcessorFuzz finding or vulnerability."""

from hashlib import sha256

import pytest

from chipchain.core import ArtifactProvenance, HardwareTargetIdentity, ProcessorFuzzArtifact


@pytest.fixture
def synthetic_si() -> bytes:
    """Hand-written lexical examples, not a copied real instruction sequence."""

    lines = [
        "p-m", "", "_p0:    addi x1, zero, 0000",
        "_l0:    fadd.s f1, f2, f3, rne".ljust(50) + "0000",
        "        csrrw x2, mstatus, x1",
        "_l1:    lw x3, -0(x1)",
        "        la x4, _l999",
        "        li x5, 0xffe00",
        "_s0:    fence",
        "data:", "0000000000000000", "0000000000000001",
    ]
    return ("\n".join(lines) + "\n").encode("ascii")


@pytest.fixture
def synthetic_source(synthetic_si) -> ProcessorFuzzArtifact:
    return ProcessorFuzzArtifact(
        hardware_target=HardwareTargetIdentity(
            target_id="synthetic-format-only-target", architecture="riscv", hardware_model="Synthetic",
        ),
        provenance=ArtifactProvenance(
            artifact_id="synthetic-format-only-si", artifact_sha256=sha256(synthetic_si).hexdigest(),
            architecture="riscv", source_kind="synthetic", producer_profile_id="synthetic-format-only-producer",
        ),
    )
