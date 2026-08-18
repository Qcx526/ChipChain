/* Synthetic ARM A32 source corresponding exactly to generate_fixture.py. */
.syntax unified
.arm
.text

.global driver_like_function
.type driver_like_function, %function
driver_like_function:
    movw r1, #0x0000
    movt r1, #0x4000
    str r0, [r1]
    str r0, [r1]
    ldr r4, [r1]
    movw r2, #0x1000
    movt r2, #0x2000
    str r0, [r2]
    ldr r4, [r2]
    str r0, [r3]
    ldr r4, [r5]
    bx lr

.global main
.type main, %function
main:
    mov r0, #1
    bl driver_like_function
    b .
