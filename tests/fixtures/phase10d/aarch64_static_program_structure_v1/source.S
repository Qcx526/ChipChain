/*
 * Owned synthetic AArch64 static program-structure fixture.
 *
 * This describes benign CFG shapes. It is not a real vulnerability, runtime
 * execution evidence, a triggerability claim, or benchmark Ground Truth.
 */

.section .text
.global owned_branching_structure
owned_branching_structure:
    cbz x0, owned_branch_target
    add x1, x1, #1
    ret
owned_branch_target:
    sub x1, x1, #1
    ret

.global owned_leaf_structure
owned_leaf_structure:
    ret

.global owned_self_loop_structure
owned_self_loop_structure:
    b owned_self_loop_structure

/* The generated .data section contains non-executable decoy bytes. */
