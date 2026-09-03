/*
 * Owned benign synthetic AArch64 static-fusion fixture.
 *
 * This is not a vulnerability, runtime evidence, triggerability result,
 * exploit, verified attack chain, or Benchmark Ground Truth.
 */

.section .text
.global owned_fused_static_flow
owned_fused_static_flow:
    mrs x0, par_el1
    cbz x1, block_c
block_b:
    dsb ish
    b block_d
block_c:
    tlbi vmalle1is
    b block_d
block_d:
    isb
    ret

/* Generated .data contains separated non-executable decoy words only. */
