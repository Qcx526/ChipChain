# Phase 9B1 passive QEMU observer

`chipchain_runtime_observer.c` is a deliberately dumb TCG plugin. It emits only
instruction execution and memory accesses that QEMU itself classifies as IO.
Physical addresses and access sizes come directly from the plugin API. The
plugin does not inspect values or registers and does not mutate the guest.

The reference target is QEMU 11.0.3 (plugin API v6) `qemu-system-arm`, machine
`virt`, CPU `cortex-a15`, TCG, and one vCPU. QEMU's plugin API is versioned, so
build the plugin against the headers belonging to the exact QEMU runtime under
test. Other API revisions require explicit source/build/runtime validation.

```powershell
$env:QEMU_PLUGIN_INCLUDE = 'C:\path\to\qemu\include\qemu'
$env:CHIPCHAIN_QEMU_PLUGIN_CC = 'C:\path\to\gcc.exe'
.\.venv\Scripts\python.exe tools\qemu_plugins\build.py
```

The builder uses an argv list with `shell=False`. It does not download a
compiler, QEMU, headers, or GLib. The resulting shared library is a local build
artifact and must not be committed.

Plugin options are `out=<raw-jsonl>` and `run_id=<safe-id>`. The Python runner
is the supported way to invoke it. A trace without the final clean `end` record
is incomplete and cannot become Dynamic Evidence.
