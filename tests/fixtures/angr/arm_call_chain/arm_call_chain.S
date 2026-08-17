/* Synthetic ARM A32 source corresponding exactly to generate_fixture.py. */
.syntax unified
.arm
.text

.global driver_like_function
.type driver_like_function, %function
driver_like_function:
    add r0, r0, #3
    bx lr

.global helper_function
.type helper_function, %function
helper_function:
    push {lr}
    add r0, r0, #2
    bl driver_like_function
    pop {pc}

.global parse_command
.type parse_command, %function
parse_command:
    push {lr}
    add r0, r0, #1
    bl helper_function
    pop {pc}

.global main
.type main, %function
main:
    push {lr}
    mov r0, #7
    bl parse_command
    pop {pc}

.global indirect_dispatch
.type indirect_dispatch, %function
indirect_dispatch:
    push {lr}
    blx r3
    pop {pc}
