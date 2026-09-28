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

    .text
    .globl _start
    .type _start, %function
_start:
    mov x1, x0
    adrp x0, :got:main
    ldr x0, [x0, :got_lo12:main]
    adrp x16, :got:__librs_start_main
    ldr x16, [x16, :got_lo12:__librs_start_main]
    br x16
    .size _start, .-_start

    .section .note.GNU-stack,"",%progbits
