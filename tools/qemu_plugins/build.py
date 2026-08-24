"""Build an observer with an explicitly installed QEMU plugin SDK."""

from __future__ import annotations

import argparse
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path


def _compiler() -> str:
    explicit = os.environ.get("CHIPCHAIN_QEMU_PLUGIN_CC") or os.environ.get("CC")
    if explicit:
        return explicit
    for name in ("gcc", "clang", "cc"):
        found = shutil.which(name)
        if found:
            return found
    raise RuntimeError(
        "no supported GCC/Clang compiler found; set CHIPCHAIN_QEMU_PLUGIN_CC explicitly"
    )


def _glib_flags() -> list[str]:
    pkg_config = shutil.which("pkg-config")
    if not pkg_config:
        raise RuntimeError("pkg-config is required to locate GLib")
    completed = subprocess.run(
        [pkg_config, "--cflags", "--libs", "glib-2.0"],
        check=True,
        capture_output=True,
        text=True,
        shell=False,
    )
    return shlex.split(completed.stdout, posix=os.name != "nt")


def build(
    output: Path,
    include_dir: Path | None,
    *,
    source_name: str = "chipchain_runtime_observer.c",
) -> None:
    """Compile one explicitly selected checked-in observer source."""

    source = Path(__file__).with_name(source_name)
    command = [_compiler(), "-O2", "-Wall", "-Wextra", "-Werror"]
    if os.name != "nt":
        command.append("-fPIC")
    command.extend(["-shared", str(source), "-o", str(output)])
    if include_dir is not None:
        command.extend(["-I", str(include_dir)])
    command.extend(_glib_flags())
    output.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(command, check=True, shell=False)


def main() -> int:
    suffix = ".dll" if os.name == "nt" else ".dylib" if sys.platform == "darwin" else ".so"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
    )
    parser.add_argument(
        "--observer",
        choices=("runtime", "trigger-sequence"),
        default="runtime",
        help="observer contract to build (default preserves Phase 9B1)",
    )
    parser.add_argument(
        "--include-dir",
        type=Path,
        default=(Path(value) if (value := os.environ.get("QEMU_PLUGIN_INCLUDE")) else None),
        help="directory containing qemu-plugin.h (or set QEMU_PLUGIN_INCLUDE)",
    )
    args = parser.parse_args()
    try:
        source_name = {
            "runtime": "chipchain_runtime_observer.c",
            "trigger-sequence": "chipchain_trigger_sequence_observer.c",
        }[args.observer]
        output = args.output or Path(__file__).with_name(
            {
                "runtime": f"chipchain_runtime_observer{suffix}",
                "trigger-sequence": f"chipchain_trigger_sequence_observer{suffix}",
            }[args.observer]
        )
        build(output.resolve(), args.include_dir, source_name=source_name)
    except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"plugin build blocked: {exc}", file=sys.stderr)
        return 2
    print(output.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
