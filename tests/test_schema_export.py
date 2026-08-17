"""Tests for the lightweight JSON Schema export command."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def test_schema_export_script_writes_core_schemas(tmp_path: Path) -> None:
    """The documented script should emit both core model schemas."""

    result = subprocess.run(
        [
            sys.executable,
            "scripts/export_schema.py",
            "--output",
            str(tmp_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    vulnerability_schema = json.loads(
        (tmp_path / "vulnerability_sample.schema.json").read_text(encoding="utf-8")
    )
    chain_schema = json.loads(
        (tmp_path / "attack_chain.schema.json").read_text(encoding="utf-8")
    )
    assert vulnerability_schema["title"] == "VulnerabilitySample"
    assert chain_schema["title"] == "AttackChain"
