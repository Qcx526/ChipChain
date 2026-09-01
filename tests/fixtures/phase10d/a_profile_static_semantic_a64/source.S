/*
 * Owned synthetic AArch64 static-decoder examples.
 *
 * These isolated functions do not call one another and are not a CVE trigger,
 * reproducer, or vulnerable sequence. generate_fixture.py directly emits the
 * listed audited words so fixture reproduction needs no cross-toolchain.
 */

.section .text
.global owned_load_example
owned_load_example:
    ldr x0, [x1]
    ret

.global owned_store_exclusive_example
owned_store_exclusive_example:
    stxr w0, x1, [x2]
    ret

.global owned_par_el1_read_example
owned_par_el1_read_example:
    mrs x0, par_el1
    ret

.global owned_near_miss_examples
owned_near_miss_examples:
    str x0, [x1]
    ldxr x1, [x2]
    msr par_el1, x0
    mrs x0, far_el1
    ldur x0, [x1]
    ret

/* The generated non-executable .data contains separated byte copies only. */
