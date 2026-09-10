"""Installed console and module entry points expose only the R0 shell."""

from pathlib import Path
import subprocess
import sys

import pytest


@pytest.mark.parametrize("entry", ["console", "module"])
def test_cli_help(entry: str) -> None:
    command = (
        [str(Path(sys.executable).with_name("chipchain"))]
        if entry == "console" else [sys.executable, "-m", "chipchain"]
    )
    result = subprocess.run(command + ["--help"], capture_output=True, text=True, check=True)
    normalized_stdout = " ".join(result.stdout.split())
    assert "ChipChain V2" in normalized_stdout
    assert "RISC-V-first" in normalized_stdout
    assert "not implemented" in normalized_stdout
    assert "positional arguments:" not in normalized_stdout
    assert result.stderr == ""


@pytest.mark.parametrize("command", ["experiment", "si", "trigger", "firmware"])
def test_unimplemented_commands_rejected(command: str) -> None:
    result = subprocess.run(
        [sys.executable, "-m", "chipchain", command], capture_output=True, text=True,
    )
    assert result.returncode == 2
    assert "unrecognized arguments" in result.stderr
