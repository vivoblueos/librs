// Copyright (c) 2025 vivo Mobile Communication Co., Ltd.
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

// FIXME: We are using kernel's allocator currently. Formally, we should use mmap to implement malloc.
use blueos_header::syscalls::NR::{AllocMem, FreeMem, ReallocMem, Write};
use blueos_scal::bk_syscall;
use libc::{c_int, c_void, size_t, ENOMEM};

#[no_mangle]
pub unsafe extern "C" fn posix_memalign(
    ptr: *mut *mut c_void,
    align: size_t,
    size: size_t,
) -> c_int {
    let rc = bk_syscall!(AllocMem, ptr, size, align);
    if rc != 0 {
        return ENOMEM;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn free(ptr: *mut c_void) {
    bk_syscall!(FreeMem, ptr);
}

#[no_mangle]
pub unsafe extern "C" fn malloc(size: usize) -> *mut c_void {
    let mut ptr: *mut c_void = core::ptr::null_mut();
    let rc = posix_memalign(
        &mut ptr as *mut *mut c_void,
        core::mem::size_of::<usize>(),
        size,
    );
    if rc != 0 {
        return core::ptr::null_mut();
    }
    ptr
}

/// Resize an allocation, preserving its contents up to the smaller of the two
/// sizes.
///
/// The kernel performs the resize: only it knows the old block's size, and
/// reimplementing that here would mean either tracking sizes in `malloc` (which
/// changes the pointer every existing caller sees) or copying a length the
/// caller cannot supply.
#[no_mangle]
pub unsafe extern "C" fn realloc(ptr: *mut c_void, size: size_t) -> *mut c_void {
    let mut moved: *mut c_void = core::ptr::null_mut();
    // A zero size is the C "free and return null" case, and the kernel handler
    // reports it as failure; free here so the block is not leaked.
    if size == 0 {
        free(ptr);
        return core::ptr::null_mut();
    }
    let rc = bk_syscall!(ReallocMem, &mut moved as *mut *mut c_void, ptr, size);
    if rc != 0 {
        return core::ptr::null_mut();
    }
    moved
}

/// Allocate `count * size` zeroed bytes. `malloc` plus an explicit clear: the
/// kernel's `calloc` is not reachable from here and the zeroing is unambiguous
/// at this level.
#[no_mangle]
pub unsafe extern "C" fn calloc(count: size_t, size: size_t) -> *mut c_void {
    let Some(total) = count.checked_mul(size) else {
        return core::ptr::null_mut();
    };
    let ptr = malloc(total);
    if !ptr.is_null() {
        core::ptr::write_bytes(ptr as *mut u8, 0, total);
    }
    ptr
}

/// `memalign` is `posix_memalign` with C's return convention instead of the
/// error-code one.
#[no_mangle]
pub unsafe extern "C" fn memalign(alignment: size_t, size: size_t) -> *mut c_void {
    let mut ptr: *mut c_void = core::ptr::null_mut();
    if posix_memalign(&mut ptr as *mut *mut c_void, alignment, size) != 0 {
        return core::ptr::null_mut();
    }
    ptr
}

/// Terminal landing pad for `-Cpanic=abort`.
///
/// Prints a marker before parking: the DSO has no unwinder, so the only way a
/// failure here is diagnosable under QEMU is for it to say so on stderr before
/// it stops responding.
#[no_mangle]
pub extern "C" fn abort() -> ! {
    const MESSAGE: &[u8] = b"libc: abort()\n";
    unsafe {
        bk_syscall!(Write, 2, MESSAGE.as_ptr(), MESSAGE.len());
    }
    loop {
        core::hint::spin_loop();
    }
}
