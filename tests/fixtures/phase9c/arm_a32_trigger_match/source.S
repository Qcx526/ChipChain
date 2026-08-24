/* Owned synthetic ARM A32 fixture. This is not a real vulnerability. */
.syntax unified
.arm
.text

.global synthetic_trigger_function
.type synthetic_trigger_function, %function
synthetic_trigger_function:
    mov r0, #1
    add r1, r0, #1
    mov r2, r1
    bx lr

.global synthetic_near_miss
.type synthetic_near_miss, %function
synthetic_near_miss:
    mov r0, #1
    add r1, r0, #2
    mov r2, r1
    bx lr

.data
.global synthetic_non_executable_copy
synthetic_non_executable_copy:
    .word 0xe3a00001
    .word 0xe2801001
    .word 0xe1a02001
