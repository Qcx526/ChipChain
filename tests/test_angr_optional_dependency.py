"""Tests that angr remains an optional, lazily loaded backend."""

from __future__ import annotations

import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

import chipchain.analysis.angr_analyzer as angr_analyzer_module
from chipchain.analysis import AngrAnalyzer, ProgramAnalysisError, ProgramArtifact


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = (
    REPOSITORY_ROOT
    / "tests"
    / "fixtures"
    / "angr"
    / "arm_call_chain"
    / "arm_call_chain.elf"
)


def test_importing_public_analysis_api_does_not_import_angr() -> None:
    """Base users can import ChipChain without loading the native backend."""

    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; import chipchain.analysis; "
            "assert 'angr' not in sys.modules",
        ],
        cwd=REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr


def test_angr_is_declared_only_in_optional_dependency_group() -> None:
    """The normal and dev installs must not acquire angr implicitly."""

    configuration = tomllib.loads(
        (REPOSITORY_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    )
    project = configuration["project"]

    assert all(not item.startswith("angr") for item in project["dependencies"])
    assert all(
        not item.startswith("angr")
        for item in project["optional-dependencies"]["dev"]
    )
    assert project["optional-dependencies"]["angr"] == ["angr==9.3.2"]


def test_missing_optional_backend_uses_stable_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A missing optional import explains how to enable the backend."""

    real_import = angr_analyzer_module.importlib.import_module

    def fail_angr_import(name: str):
        if name == "angr":
            raise ImportError("synthetic missing optional dependency")
        return real_import(name)

    monkeypatch.setattr(
        angr_analyzer_module.importlib,
        "import_module",
        fail_angr_import,
    )
    artifact = ProgramArtifact(
        id="synthetic-arm-call-chain",
        architecture="arm",
        artifact_type="elf",
        path=str(FIXTURE_PATH),
        metadata={"fixture": True, "synthetic": True},
    )

    with pytest.raises(ProgramAnalysisError, match="'angr' extra"):
        AngrAnalyzer().analyze(artifact)
