# Owned ARM QEMU bare-metal fixture

This directory is an **owned, synthetic fixture**. It is not a real
vulnerability and not a benchmark. It exists only to validate the Phase 9B1
passive observation path.

The A32 firmware starts at `0x40000000`, executes a byte store to the QEMU
`virt` UART0 address, then exits through Arm semihosting `SYS_EXIT`. The UART
address `0x09000000` is ground truth only for the version-pinned QEMU 11.0.3
fixture. It is not an ARM architecture rule or a general MMIO heuristic, and
device addresses may differ in other QEMU versions or machines.

`generate_fixture.py` constructs a minimal deterministic ELF32 file from the
machine words annotated in `arm_qemu_mmio.S`. This avoids an unaudited binary
download when no ARM cross-toolchain is installed. Regenerate with:

```powershell
.\.venv\Scripts\python.exe tests\fixtures\qemu_arm_baremetal\generate_fixture.py
```

The fixture is loaded with QEMU's generic loader. Semihosting is enabled only
for this trusted owned fixture; never reuse that runner setting for untrusted
firmware. The exit convention follows the Arm semihosting `SYS_EXIT` operation
with reason `ADP_Stopped_ApplicationExit`.
