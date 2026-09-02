/*
 * Owned synthetic AArch64 generic static-semantic decoder examples.
 *
 * This is an instruction-family fixture, not a vulnerable sequence, hardware
 * reproduction, executable test case, or benchmark Ground Truth.
 */

.section .text
.global owned_generic_semantic_inventory
owned_generic_semantic_inventory:
    ldr x0, [x1]
    str x0, [x1]
    ldxr x1, [x2]
    stxr w0, x1, [x2]
    mrs x0, par_el1
    msr par_el1, x0
    dsb ish
    dmb ish
    isb
    tlbi vmalle1is
    nop
    add x0, x0, #1
    ret

.global owned_exception_return_semantic
owned_exception_return_semantic:
    eret

/* The generated non-executable .data contains separated byte copies only. */
