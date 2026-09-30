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

//! Runtime glue for the shared-libc DSO (`libc.so.1`).
//!
//! `librs/src/lib.rs` intentionally defines neither a global allocator nor a
//! panic handler: the static `librs`/`librs_swi` rlibs are never linked on
//! their own (the kernel image supplies both), and `newlib.rs` supplies them
//! for the newlib C/C++ staticlib. The `cdylib` DSO *is* linked, so it must
//! provide both itself. This module does so over the SWI syscall ABI only —
//! no ordinary kernel Rust/C symbol is referenced.
//!
//! It is pulled in exclusively by the `blueos_dso("libc")` target via the
//! `librs_dso` cfg; every other `librs` target compiles it out.

use core::alloc::{GlobalAlloc, Layout};

use blueos_header::syscalls::NR::{AllocMem, FreeMem};
use blueos_scal::bk_syscall;

/// SWI-backed global allocator for the shared libc.
///
/// Backs the Rust `alloc` crate (`Box`/`Vec`/`String`/… used throughout
/// librs) from the kernel allocator through the same `AllocMem`/`FreeMem`
/// SWI pair the user-facing `malloc`/`free` use, so internal and POSIX
/// allocations share one accounting domain. `#[global_allocator]` implies a
/// non-Sync, non-Send static; that matches the DSO's single-thread residency
/// and the loader's allocation-lease model.
struct DsoAllocator;

unsafe impl GlobalAlloc for DsoAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let mut ptr: *mut core::ffi::c_void = core::ptr::null_mut();
        let rc = bk_syscall!(
            AllocMem,
            &mut ptr as *mut *mut core::ffi::c_void,
            layout.size(),
            layout.align()
        );
        if rc != 0 {
            core::ptr::null_mut()
        } else {
            ptr as *mut u8
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        bk_syscall!(FreeMem, ptr as *mut core::ffi::c_void);
    }
}

#[global_allocator]
static GLOBAL: DsoAllocator = DsoAllocator;

/// Minimal abort-style panic handler. The DSO links with `-Cpanic=abort`, so
/// this is only the terminal landing pad; the runtime does not unwind or report
/// into the kernel. It must be `#[no_mangle]`-free (the symbol is internal to
/// the DSO) and never return.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // No semihosting dependency is present in the DSO sysroot; park the core
    // so the failure is observable under QEMU without pulling host symbols.
    loop {}
}
