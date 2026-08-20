/*
 * Owned synthetic ARM A32 Phase 9B1 fixture; not a vulnerability or benchmark.
 * Link/load address: 0x40200000 for the version-pinned QEMU virt scenario.
 */

    .syntax unified
    .arm
    .global _start
_start:
    ldr r0, uart0_address
    mov r1, #'A'
mmio_write:
    strb r1, [r0]
    mov r0, #0x18              /* Arm semihosting SYS_EXIT */
    ldr r1, exit_reason
    svc 0x123456
exit_reason:
    .word 0x00020026           /* ADP_Stopped_ApplicationExit */
uart0_address:
    .word 0x09000000           /* QEMU 11.0.3 virt fixture ground truth only */
