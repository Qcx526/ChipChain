/*
 * Owned synthetic Phase 9C Step 3A ARM A32 fixture.
 * The harmless arithmetic sequence appears twice but only the first function
 * is called. This is not a vulnerability or benchmark.
 */

    .syntax unified
    .arm
    .section .text
    .global _start
    .global executed_trigger
    .global not_called_trigger

_start:
    bl executed_trigger
    mov r0, #0x18
    ldr r1, exit_reason
    svc 0x123456
exit_reason:
    .word 0x00020026
hang:
    b hang

executed_trigger:
    mov r0, #1
    add r1, r0, #1
    mov r2, r1
    bx lr

not_called_trigger:
    mov r0, #1
    add r1, r0, #1
    mov r2, r1
    bx lr
