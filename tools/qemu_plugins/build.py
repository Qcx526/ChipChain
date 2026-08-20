"""Build the Phase 9B1 observer with an explicitly installed QEMU SDK."""

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


def build(output: Path, include_dir: Path | None) -> None:
    source = Path(__file__).with_name("chipchain_runtime_observer.c")
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
        default=Path(__file__).with_name(f"chipchain_runtime_observer{suffix}"),
    )
    parser.add_argument(
        "--include-dir",
        type=Path,
        default=(Path(value) if (value := os.environ.get("QEMU_PLUGIN_INCLUDE")) else None),
        help="directory containing qemu-plugin.h (or set QEMU_PLUGIN_INCLUDE)",
    )
    args = parser.parse_args()
    try:
        build(args.output.resolve(), args.include_dir)
    except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"plugin build blocked: {exc}", file=sys.stderr)
        return 2
    print(args.output.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
