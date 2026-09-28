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

// RV32IMC QEMU applications share the kernel's machine-mode address space.
    .text
    .globl disable_local_irq_save
    .hidden disable_local_irq_save
    .type disable_local_irq_save, @function
disable_local_irq_save:
    csrrci a0, mstatus, 8
    fence rw, rw
    ret
    .size disable_local_irq_save, .-disable_local_irq_save

    .globl enable_local_irq_restore
    .hidden enable_local_irq_restore
    .type enable_local_irq_restore, @function
enable_local_irq_restore:
    fence rw, rw
    csrw mstatus, a0
    ret
    .size enable_local_irq_restore, .-enable_local_irq_restore
