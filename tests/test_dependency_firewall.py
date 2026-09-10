"""Keep production and entry points independent of archived business packages."""

import ast
import re
from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
PRODUCTION = ROOT / "src/chipchain"
OLD_PACKAGES = (
    "agents", "analysis", "candidate", "corpus", "evaluation", "graph",
    "hardware_trigger", "knowledge", "models", "multi_agent", "reasoning",
    "runtime", "verification",
)


def test_production_imports_respect_core_behavior_adapter_trigger_direction() -> None:
    allowed = {
        "argparse", "collections.abc", "enum", "hashlib", "json", "math", "re", "typing",
        "pydantic", "chipchain", "chipchain.cli", "chipchain.core.address",
        "chipchain.core.architecture", "chipchain.core.identity", "chipchain.core.models",
        "chipchain.core.provenance",
        "chipchain.core.target", "chipchain.core.artifacts",
        "chipchain.core.input", "chipchain.core.debug",
    }
    behavior_allowed = {
        "chipchain.core", "chipchain.behavior.processor.base",
        "chipchain.behavior.processor.enums", "chipchain.behavior.processor.values",
        "chipchain.behavior.processor.instructions", "chipchain.behavior.processor.events",
        "chipchain.behavior.processor.state", "chipchain.behavior.processor.relations",
        "chipchain.behavior.processor.models",
    }
    adapter_allowed = {
        "chipchain.core", "chipchain.behavior.processor",
        "chipchain.adapters.processorfuzz._syntax", "chipchain.adapters.processorfuzz.errors",
        "chipchain.adapters.processorfuzz.models", "chipchain.adapters.processorfuzz.parser",
        "chipchain.adapters.processorfuzz.mapper",
    }
    trigger_allowed = {
        "chipchain.core", "chipchain.behavior.processor", "chipchain.trigger.base",
        "chipchain.trigger.enums", "chipchain.trigger.values", "chipchain.trigger.requirements",
        "chipchain.trigger.relations", "chipchain.trigger.models",
    }
    evidence_allowed = {
        "csv", "chipchain.core", "chipchain.behavior.processor",
        "chipchain.evidence.base", "chipchain.evidence.enums", "chipchain.evidence._profiles",
        "chipchain.evidence.observations", "chipchain.evidence.models", "chipchain.evidence.alignment",
    }
    case_adapter_allowed = {
        "chipchain.core", "chipchain.evidence",
        "chipchain.adapters.hardware_case._common", "chipchain.adapters.hardware_case.errors",
        "chipchain.adapters.hardware_case.isa_csv", "chipchain.adapters.hardware_case.isa_log",
        "chipchain.adapters.hardware_case.rtl_log", "chipchain.adapters.hardware_case.signature",
    }
    anchor_allowed = {
        "struct", "chipchain.core", "chipchain.behavior.processor", "chipchain.evidence",
        "chipchain.adapters.processorfuzz", "chipchain.anchors.base", "chipchain.anchors.elf",
        "chipchain.anchors.hardware_case",
    }
    candidate_allowed = {
        "chipchain.core", "chipchain.behavior.processor", "chipchain.evidence", "chipchain.anchors", "chipchain.trigger",
        "chipchain.candidates.base", "chipchain.candidates.enums", "chipchain.candidates.facts",
        "chipchain.candidates.models", "chipchain.candidates.context", "chipchain.candidates.validation",
    }
    for path in sorted(PRODUCTION.rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        file_allowed = (
            {name for name in allowed if not name.startswith("chipchain")} | behavior_allowed
            if "behavior" in path.relative_to(PRODUCTION).parts else allowed
        )
        if "adapters" in path.relative_to(PRODUCTION).parts:
            file_allowed = {name for name in allowed if not name.startswith("chipchain")} | adapter_allowed
            if "hardware_case" in path.relative_to(PRODUCTION).parts:
                file_allowed = {name for name in allowed if not name.startswith("chipchain")} | case_adapter_allowed
        elif not {"anchors", "candidates"}.intersection(path.relative_to(PRODUCTION).parts):
            assert "chipchain.adapters" not in source, path
        if "trigger" in path.relative_to(PRODUCTION).parts:
            file_allowed = {name for name in allowed if not name.startswith("chipchain")} | trigger_allowed
        elif "candidates" not in path.relative_to(PRODUCTION).parts:
            assert "chipchain.trigger" not in source, path
        if "evidence" in path.relative_to(PRODUCTION).parts:
            file_allowed = {name for name in allowed if not name.startswith("chipchain")} | evidence_allowed
        elif not {"hardware_case", "anchors", "candidates"}.intersection(path.relative_to(PRODUCTION).parts):
            assert "chipchain.evidence" not in source, path
        if "anchors" in path.relative_to(PRODUCTION).parts:
            file_allowed = {name for name in allowed if not name.startswith("chipchain")} | anchor_allowed
        elif "candidates" not in path.relative_to(PRODUCTION).parts:
            assert "chipchain.anchors" not in source, path
        if "candidates" in path.relative_to(PRODUCTION).parts:
            file_allowed = {name for name in allowed if not name.startswith("chipchain")} | candidate_allowed
            if path.name == "context.py":
                file_allowed |= {"chipchain.adapters.processorfuzz.models"}
            _check_candidate_adapter_imports(source, path.name)
        else:
            assert "chipchain.candidates" not in source, path
        for package in OLD_PACKAGES:
            assert re.search(r"\bchipchain\." + package + r"\b", source) is None, path
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Import):
                assert all(item.name in file_allowed for item in node.names), path
            elif isinstance(node, ast.ImportFrom):
                assert node.level == 0 and node.module in file_allowed, path
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    assert node.func.id not in {"__import__", "eval", "exec"}, path
                elif isinstance(node.func, ast.Attribute):
                    assert node.func.attr not in {"import_module", "exec_module"}, path
    for package in OLD_PACKAGES:
        assert not (PRODUCTION / package).exists()


@pytest.mark.parametrize("mode", ["root", "core", "behavior", "adapter", "trigger", "evidence", "case_adapter", "anchors", "candidates", "console", "module"])
def test_fresh_process_import_firewall(mode: str) -> None:
    # A fresh process avoids false assurance from previously imported backends.
    script = r'''
import importlib.abc
from pathlib import Path
import runpy
import sys

mode = sys.argv[1]
old = ("agents", "analysis", "candidate", "corpus", "evaluation", "graph",
       "hardware_trigger", "knowledge", "models", "multi_agent", "reasoning",
       "runtime", "verification")
if mode not in ("adapter", "case_adapter", "anchors", "candidates"):
    old += ("adapters",)
if mode not in ("evidence", "case_adapter", "anchors", "candidates"):
    old += ("evidence",)
if mode not in ("trigger", "candidates"):
    old += ("trigger",)
if mode not in ("anchors", "candidates"):
    old += ("anchors",)
if mode != "candidates":
    old += ("candidates",)
forbidden = tuple("chipchain." + item for item in old) + (
    "angr", "capstone", "networkx", "openai", "dotenv", "qemu", "provider",
    "jtag", "processorfuzz", "gdbfuzz", "requests", "httpx",
)
if mode == "case_adapter":
    forbidden += ("chipchain.adapters.processorfuzz",)
if mode in ("anchors", "candidates"):
    forbidden += ("chipchain.adapters.hardware_case",)
def forbidden_module(name):
    return any(name == prefix or name.startswith(prefix + ".") for prefix in forbidden)
class BlockBackends(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if forbidden_module(fullname):
            raise AssertionError("forbidden import: " + fullname)
sys.meta_path.insert(0, BlockBackends())
if mode == "root":
    import chipchain
    assert sorted(name for name in sys.modules if name.startswith("chipchain")) == ["chipchain"]
    assert "pydantic" not in sys.modules
    print(chipchain.__file__)
elif mode == "core":
    from chipchain.core import Architecture, ArtifactProvenance, DomainModel
    from chipchain.core import ProgramAddress, canonical_json_bytes, deterministic_id
    assert Architecture.RISC_V.value == "riscv"
    assert not any(name.startswith("chipchain.behavior") for name in sys.modules)
elif mode == "behavior":
    from chipchain.behavior.processor import ProcessorBehaviorFragment, InstructionBehavior
    assert ProcessorBehaviorFragment.model_fields["contract"].default == "v2_processor_behavior_fragment_v1"
elif mode == "adapter":
    from chipchain.adapters.processorfuzz import parse_processorfuzz_si, map_processorfuzz_si
    raw = parse_processorfuzz_si(b"p-m\n\n_p0:    addi x1, zero, 0\n_l0:    addi x2, x1, 1\n_s0:    fence\ndata:\n0000000000000000\n")
    assert len(raw.instructions) == 3
elif mode == "trigger":
    from chipchain.trigger import HardwareTriggerSpec, ExactScalarConstraint
    assert HardwareTriggerSpec.model_fields["contract"].default == "v2_hardware_trigger_spec_v1"
    constraint = ExactScalarConstraint(value={"width_bits": 8, "value": "0x1"})
    assert constraint.id.startswith("v2-trigger-exact-scalar-constraint-v1:")
elif mode == "evidence":
    from chipchain.evidence import FieldComparison, ComparableField, ComparisonOutcome
    comparison = FieldComparison.create(ComparableField.MSTATUS, None, None)
    assert comparison.outcome == ComparisonOutcome.NOT_COMPARABLE
elif mode == "case_adapter":
    from chipchain.adapters.hardware_case import parse_signature
    from chipchain.core import Architecture
    from chipchain.evidence import TraceSourceSide
    artifact = parse_signature((b"0" * 32 + b"\n") * 254,
        source_side=TraceSourceSide.ISA_SIDE, architecture=Architecture.RISC_V)
    assert len(artifact.observations) == 254
elif mode == "anchors":
    from chipchain.anchors import HardwareTestProgramELFSource
    source = HardwareTestProgramELFSource(artifact_sha256="0" * 64, byte_length=64)
    assert source.artifact_kind == "HARDWARE_TEST_PROGRAM_ELF"
elif mode == "candidates":
    from chipchain.candidates import HardwareTriggerCandidate, build_trigger_candidate_context
    assert HardwareTriggerCandidate.model_fields["status"].default == "HYPOTHESIS"
else:
    sys.argv = ["chipchain", "--help"]
    try:
        if mode == "console":
            runpy.run_path(str(Path(sys.executable).with_name("chipchain")), run_name="__main__")
        else:
            runpy.run_module("chipchain", run_name="__main__")
    except SystemExit as exc:
        assert exc.code == 0
    else:
        raise AssertionError("--help did not exit")
assert not [name for name in sys.modules if forbidden_module(name)]
'''
    subprocess.run([sys.executable, "-B", "-I", "-c", script, mode], check=True, capture_output=True, text=True)


def _check_candidate_adapter_imports(source: str, filename: str) -> None:
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            assert not any(n.name.startswith("chipchain.adapters") for n in node.names)
        if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("chipchain.adapters"):
            assert filename == "context.py"
            assert node.module == "chipchain.adapters.processorfuzz.models" and node.level == 0
            assert [(n.name, n.asname) for n in node.names] == [("RawProcessorFuzzSI", None)]


@pytest.mark.parametrize("source,filename", [
    ("from chipchain.adapters.processorfuzz import RawProcessorFuzzSI", "context.py"),
    ("from chipchain.adapters.processorfuzz.models import RawSIInstructionRecord", "context.py"),
    ("from chipchain.adapters.processorfuzz.models import RawProcessorFuzzSI", "models.py"),
    ("from chipchain.adapters.processorfuzz.models import *", "context.py"),
    ("from chipchain.adapters.processorfuzz.parser import parse_processorfuzz_si", "context.py"),
    ("from chipchain.adapters.processorfuzz.mapper import map_processorfuzz_si", "context.py"),
    ("from chipchain.adapters.hardware_case import parse_isa_csv", "context.py"),
    ("import chipchain.adapters.processorfuzz.models", "context.py"),
])
def test_candidate_raw_si_exception_rejects_broader_dependencies(source, filename):
    with pytest.raises(AssertionError):
        _check_candidate_adapter_imports(source, filename)
