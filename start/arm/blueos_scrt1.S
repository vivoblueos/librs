// Copyright (c) 2026 vivo Mobile Communication Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

    .syntax unified
    .thumb
    .text

    .globl  _start
    .type   _start, %function
    .thumb_func
_start:
    mov     r1, r0
    .align  2
    ldr.w   r0, .Lmain_got
    add     r0, pc
    b       .Lmain_load
.Lmain_got:
    .word   main(GOT_PREL)
.Lmain_load:
    ldr.w   r0, [r0]
    .align  2
    ldr.w   r12, .Lgot_slot
    add     r12, pc
    b       .Lcall
.Lgot_slot:
    .word   __librs_start_main(GOT_PREL)
.Lcall:
    ldr.w   r12, [r12]
    bx      r12
    .size   _start, .-_start
