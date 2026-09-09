"""Keep production and entry points independent of archived business packages."""

import ast
from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
PRODUCTION = ROOT / "src/chipchain"
OLD_PACKAGES = (
    "agents", "analysis", "candidate", "corpus", "evaluation", "graph",
    "hardware_trigger", "knowledge", "models", "multi_agent", "reasoning",
    "runtime", "verification", "trigger",
)


def test_production_imports_respect_core_behavior_adapter_direction() -> None:
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
    for path in sorted(PRODUCTION.rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        file_allowed = (
            {name for name in allowed if not name.startswith("chipchain")} | behavior_allowed
            if "behavior" in path.relative_to(PRODUCTION).parts else allowed
        )
        if "adapters" in path.relative_to(PRODUCTION).parts:
            file_allowed = {name for name in allowed if not name.startswith("chipchain")} | adapter_allowed
        else:
            assert "chipchain.adapters" not in source, path
        for package in OLD_PACKAGES:
            assert f"chipchain.{package}" not in source, path
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


@pytest.mark.parametrize("mode", ["root", "core", "behavior", "adapter", "console", "module"])
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
       "runtime", "verification", "trigger")
if mode != "adapter":
    old += ("adapters",)
forbidden = tuple("chipchain." + item for item in old) + (
    "angr", "capstone", "networkx", "openai", "dotenv", "qemu", "provider",
    "jtag", "processorfuzz", "gdbfuzz", "requests", "httpx",
)
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
