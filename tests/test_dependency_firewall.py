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
    "runtime", "verification",
)


def test_production_imports_and_references_are_core_only() -> None:
    allowed = {
        "argparse", "collections.abc", "enum", "hashlib", "json", "math", "re", "typing",
        "pydantic", "chipchain", "chipchain.cli", "chipchain.core.address",
        "chipchain.core.architecture", "chipchain.core.identity", "chipchain.core.models",
        "chipchain.core.provenance",
        "chipchain.core.target", "chipchain.core.artifacts",
        "chipchain.core.input", "chipchain.core.debug",
    }
    for path in sorted(PRODUCTION.rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        for package in OLD_PACKAGES:
            assert f"chipchain.{package}" not in source, path
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Import):
                assert all(item.name in allowed for item in node.names), path
            elif isinstance(node, ast.ImportFrom):
                assert node.level == 0 and node.module in allowed, path
    for package in OLD_PACKAGES:
        assert not (PRODUCTION / package).exists()


@pytest.mark.parametrize("mode", ["root", "core", "console", "module"])
def test_fresh_process_import_firewall(mode: str) -> None:
    # A fresh process avoids false assurance from previously imported backends.
    script = r'''
import importlib.abc
from pathlib import Path
import runpy
import sys

old = ("agents", "analysis", "candidate", "corpus", "evaluation", "graph",
       "hardware_trigger", "knowledge", "models", "multi_agent", "reasoning",
       "runtime", "verification")
forbidden = tuple("chipchain." + item for item in old) + (
    "angr", "capstone", "networkx", "openai", "dotenv", "qemu", "provider",
)
def forbidden_module(name):
    return any(name == prefix or name.startswith(prefix + ".") for prefix in forbidden)
class BlockBackends(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if forbidden_module(fullname):
            raise AssertionError("forbidden import: " + fullname)
sys.meta_path.insert(0, BlockBackends())
mode = sys.argv[1]
if mode == "root":
    import chipchain
    assert sorted(name for name in sys.modules if name.startswith("chipchain")) == ["chipchain"]
    assert "pydantic" not in sys.modules
    print(chipchain.__file__)
elif mode == "core":
    from chipchain.core import Architecture, ArtifactProvenance, DomainModel
    from chipchain.core import ProgramAddress, canonical_json_bytes, deterministic_id
    assert Architecture.RISC_V.value == "riscv"
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
    subprocess.run([sys.executable, "-I", "-c", script, mode], check=True, capture_output=True, text=True)
