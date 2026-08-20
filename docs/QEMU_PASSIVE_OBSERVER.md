# ARM QEMU Passive Runtime Observer

## Scope and status

Phase 9B1 R2 supports ARM32 system emulation on `virt`, `cortex-a15`, TCG, and
one vCPU. QEMU 11.0.3 with plugin API 6 is the reproducible reference; runtime
version and plugin API are always probed rather than inferred from a filename.

The R2 implementation, fixtures, and offline tests are complete. The current
development host cannot rerun the real gate because it lacks the matching QEMU
binary, headers, build environment, and compiled plugin. Supplied reference
evidence established the R2 root cause, but it is not reported as a new local
`REAL_QEMU_STATUS = PASS`.

The checked-in topology text is an owned/sanitized/reconstructed contract
fixture based on the QEMU 11.0.3 FlatView printer and validated reference
topology facts. It is not a retained real `info mtree -f` capture. The complete
real output remains pending Ubuntu same-process QMP acceptance; only an artifact
actually generated there may later be recorded as a real sanitized capture.

## Observation and classification boundary

The key R2 rule is:

```text
Plugin Physical Observation != Plugin IO Classification Truth

Physical Access + Captured QEMU Machine Topology
  = Topology-Grounded MMIO Observation
```

The C plugin emits instruction execution plus every memory read/write for which
`qemu_plugin_get_hwaddr()` returns a handle. It obtains read/write, physical
address, and width from QEMU APIs. `plugin_is_io` and `plugin_device_name` are
retained only as non-authoritative diagnostics; `plugin_is_io=false` never
causes the raw event to be dropped. The plugin reads no register or memory
value and never mutates PC, registers, memory, interrupts, DMA, or faults.

For the validated QEMU 11.0.3 ARM `virt` fixture, the target store retained
physical address `0x09000000` but the plugin reported `is_io=false` and device
`RAM`. The same process's resolved FlatView mapped `0x09000000–0x09000fff` to
the `pl011` I/O leaf, and the independent `pl011_write` device trace confirmed
dispatch. This is a version-pinned observation, not a claim about all QEMU
versions.

## Raw JSONL v2

`chipchain_qemu_raw_trace` version 2 is backend-local and untrusted:

1. A unique header records plugin identity/build API, target, runtime API
   min/current, system mode, vCPU facts, and run ID.
2. Contiguous events are `instruction_exec`, `memory_read`, or `memory_write`.
   Memory events require PC, virtual/physical address, and byte width; optional
   plugin IO/device fields are diagnostic only.
3. A unique clean end record binds event count and last sequence.

Version 1 was a pre-stable Phase 9B1 development schema and is intentionally
not accepted after the semantic change. The parser rejects malformed JSON,
unknown fields/events, missing physical addresses, sequence gaps, incompatible
plugin facts, and missing/unclean end records. Exact raw bytes retain their own
SHA-256.

## Same-process topology capture

The runner starts the owned guest paused with `-S -qmp stdio`. Its structured
QMP stream uses IDs for `qmp_capabilities`, `human-monitor-command` with
`info mtree -f`, and `cont`, in that order. The greeting and every required
ID-matched response are validated. The exact HMP return string is persisted as
the raw topology artifact before it is parsed.

The strict parser follows QEMU 11.0.3's official FlatView output shape and
requires exactly one FlatView containing address space `memory`. Missing or
multiple matches fail closed. The selected address-space label identifies the
captured view only; RuntimeObservation `address_space_id` remains null because
R2 does not invent a globally stable identity.

`memory_map_id` hashes canonical resolved region semantics and excludes paths,
users, timestamps, and raw formatting. `memory_map_sha256` hashes the exact
same-process topology artifact. Both are written to `RuntimeTraceManifest`.

## Topology classifier and Runtime mapping

A raw access is promoted only if its full inclusive range
`[paddr, paddr + access_size - 1]` lies inside one unique resolved I/O leaf.
RAM/RAM-device accesses stay only in the raw artifact. Unmapped, overflowing,
boundary-crossing, ambiguous, or malformed cases fail closed and are not MMIO.

Promoted observations preserve the original raw sequence index; filtered RAM
events can therefore leave gaps. They use the sealed Phase 9B0
`MMIO_READ/MMIO_WRITE` kinds and `is_io=true`, meaning topology verification,
not the diagnostic plugin boolean. Metadata preserves classification source,
plugin diagnostics, topology region name, and any disagreement. `device_id`
and `address_space_id` remain null.

Dynamic Evidence remains interaction-agnostic. `verified=true` means the
observation and trace integrity contracts were verified; it does not verify a
vulnerability, interaction, causality, exploitability, or attack chain.

## Owned fixture and independent oracle

The owned/synthetic firmware keeps the audited A32 word `0xE5C01000`
(`strb r1, [r0]`), entry `0x40200000`, target PC `0x40200008`, target address
`0x09000000`, and width 1. Its ELF header explicitly declares no section table
(`e_shoff=e_shentsize=e_shnum=e_shstrndx=0`); instructions are unchanged.

The PL011 device trace is enabled only by the reference smoke/integration
configuration. It independently checks offset 0, value `0x41`, register `DR`.
It never participates in production classification or identity.

Before even probing or launching QEMU, the runner hashes the exact firmware
bytes and requires equality with the caller-supplied `firmware_sha256`. After a
successful QEMU exit it hashes the file again and requires pre-run, post-run,
and configured fingerprints to match. A mismatch is an explicit fail-closed
error; the runner never replaces an incorrect caller fingerprint silently.

## Build and real validation

The project does not download QEMU, compilers, headers, GLib, or plugins.
With a matching environment:

```powershell
$env:CHIPCHAIN_QEMU_SYSTEM_ARM = 'C:\path\to\qemu-system-arm.exe'
$env:QEMU_PLUGIN_INCLUDE = 'C:\path\to\headers'
$env:CHIPCHAIN_QEMU_PLUGIN_CC = 'C:\path\to\compiler.exe'
.\.venv\Scripts\python.exe tools\qemu_plugins\build.py
$env:CHIPCHAIN_QEMU_PLUGIN = 'C:\path\to\chipchain_runtime_observer.dll'
.\.venv\Scripts\python.exe scripts\qemu_phase9b1_smoke.py
$env:CHIPCHAIN_RUN_QEMU_TESTS = '1'
.\.venv\Scripts\python.exe -m pytest tests\test_qemu_real_integration.py -q
```

Only real QEMU, plugin load/API facts, complete instruction/raw access events,
same-process topology, topology-classified MMIO, clean shutdown, revalidation,
Dynamic Evidence, and the independent PL011 oracle together permit
`REAL_QEMU_STATUS = PASS`.
