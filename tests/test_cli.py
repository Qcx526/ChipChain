"""Tests for the initial command-line interface."""

from __future__ import annotations

import pytest

from chipchain import __version__
from chipchain.cli import main


def test_help_displays_project_name(capsys: pytest.CaptureFixture[str]) -> None:
    """The help flag should exit successfully and identify the CLI."""

    with pytest.raises(SystemExit) as exc_info:
        main(["--help"])

    assert exc_info.value.code == 0
    output = capsys.readouterr().out
    assert "usage: chipchain" in output
    normalized_output = " ".join(output.split())
    assert "cross-layer chip vulnerability chains" in normalized_output


def test_version_displays_package_version(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The version flag should report the package version."""

    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])

    assert exc_info.value.code == 0
    assert capsys.readouterr().out.strip() == f"chipchain {__version__}"


def test_no_arguments_is_a_successful_no_op() -> None:
    """Phase 0 accepts no command and exits successfully."""

    assert main([]) == 0
