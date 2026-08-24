"""Opt-in real QEMU + angr acceptance for Phase 9C Step 3A."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

from chipchain.analysis import ProgramArtifact
from chipchain.hardware_trigger import (
    AngrFirmwareTriggerMatcher,
    HardwareTriggerSignature,
    RuntimeFirmwareTriggerMatcher,
)
from chipchain.models import Architecture
from chipchain.runtime.qemu import (
    QemuArmTriggerSequenceRunConfig,
    QemuTriggerSequenceRunner,
)


pytestmark = pytest.mark.qemu
ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "phase9c" / "arm_a32_trigger_runtime"


def _plugin_default() -> Path:
    suffix = ".dll" if os.name == "nt" else ".dylib" if sys.platform == "darwin" else ".so"
    return ROOT / "tools" / "qemu_plugins" / f"chipchain_trigger_sequence_observer{suffix}"


def test_real_owned_runtime_confirms_only_executed_static_match() -> None:
    if os.environ.get("CHIPCHAIN_RUN_QEMU_TESTS") != "1":
        pytest.skip("set CHIPCHAIN_RUN_QEMU_TESTS=1 for real QEMU validation")
    pytest.importorskip("angr")
    qemu_value = os.environ.get("CHIPCHAIN_QEMU_SYSTEM_ARM") or shutil.which(
        "qemu-system-arm"
    )
    plugin = Path(os.environ.get("CHIPCHAIN_QEMU_TRIGGER_PLUGIN", _plugin_default()))
    if not qemu_value:
        pytest.fail("QEMU opt-in requested but qemu-system-arm is unavailable")
    qemu = Path(qemu_value)
    if not qemu.is_file() or not plugin.is_file():
        pytest.fail("QEMU executable or trigger observer plugin is unavailable")
    firmware = FIXTURE / "arm_a32_trigger_runtime.elf"
    truth = json.loads((FIXTURE / "ground_truth.json").read_text("utf-8"))
    signature = HardwareTriggerSignature.model_validate_json(
        (FIXTURE / "hardware_trigger_signature.json").read_text("utf-8")
    )
    artifact = ProgramArtifact(
        id=truth["artifact_id"],
        architecture=Architecture.ARM,
        artifact_type="elf",
        path=str(firmware),
        fixture_identifier="owned-phase9c-step3a-runtime-elf",
        metadata={"fixture": True, "synthetic": True, "owned": True},
    )
    static = AngrFirmwareTriggerMatcher().match(artifact, signature)
    with tempfile.TemporaryDirectory(prefix="chipchain-phase9c-step3a-") as directory:
        run = QemuTriggerSequenceRunner().run(
            QemuArmTriggerSequenceRunConfig(
                qemu_executable=qemu,
                plugin_path=plugin,
                firmware_elf=firmware,
                raw_trace_path=Path(directory) / "trigger.jsonl",
                run_id="owned-phase9c-trigger-runtime-run",
                scenario_id="owned-phase9c-trigger-runtime-scenario",
                artifact_id=artifact.id,
                firmware_sha256=hashlib.sha256(firmware.read_bytes()).hexdigest(),
            )
        )
    dynamic = RuntimeFirmwareTriggerMatcher().match(static, run.runtime_trace)

    assert run.qemu_version == "11.0.3"
    assert run.firmware_sha256 == static.artifact_sha256 == truth["artifact_sha256"]
    assert run.parsed_trace.end.clean_shutdown is True
    assert len(static.matches) == 2
    assert len(dynamic.occurrences) == 1
    occurrence = dynamic.occurrences[0]
    assert occurrence.static_match_id == truth["static_occurrences"][0]["id"]
    assert occurrence.static_match_id != truth["static_occurrences"][1]["id"]
    assert [item.pc for item in occurrence.instructions] == truth[
        "static_occurrences"
    ][0]["instruction_addresses"]
    assert [item.instruction_word for item in occurrence.instructions] == truth[
        "static_occurrences"
    ][0]["instruction_words"]
