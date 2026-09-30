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

//! POSIX runtime loader entry points. RTLD_LAZY uses the loader's eager NOW
//! relocation path. Init/fini run in this calling application thread, including
//! recursive dlopen/dlclose, before the kernel completes the operation token.

use blueos_header::{
    dlfcn::{BlueOsDlPlan, DL_PLAN_ABI_VERSION},
    syscalls::NR::{DlClose, DlExit, DlFinish, DlOpen, DlSym},
};
use blueos_scal::bk_syscall;
use core::{
    cell::RefCell,
    ffi::{c_char, c_int, c_void},
    fmt::{self, Write},
};

struct DlError {
    bytes: [u8; 256],
    len: usize,
    pending: bool,
}

impl Write for DlError {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let count = core::cmp::min(value.len(), self.bytes.len() - 1 - self.len);
        self.bytes[self.len..self.len + count].copy_from_slice(&value.as_bytes()[..count]);
        self.len += count;
        self.bytes[self.len] = 0;
        Ok(())
    }
}

#[thread_local]
static ERROR: RefCell<DlError> = RefCell::new(DlError {
    bytes: [0; 256],
    len: 0,
    pending: false,
});

fn fail(function: &str, errno: i32) {
    crate::errno::ERRNO.set(errno);
    let description = match errno {
        libc::ENOENT => "object or symbol not found",
        libc::ENOEXEC => "invalid ELF or unresolved relocation",
        libc::EINVAL => "invalid handle, flags, string or operation",
        libc::ENOMEM => "out of memory",
        libc::EPERM => "handle or operation does not belong to this application thread",
        libc::EBUSY => "object is initializing or unloading",
        libc::ENOSYS => "runtime loading is unavailable",
        libc::ECANCELED => "application is exiting",
        _ => "runtime loader operation failed",
    };
    let mut error = ERROR.borrow_mut();
    error.len = 0;
    error.pending = true;
    let _ = write!(error, "{function}: {description} (errno {errno})");
}

unsafe fn string_len(ptr: *const c_char) -> Result<usize, i32> {
    if ptr.is_null() {
        return Err(libc::EINVAL);
    }
    for index in 0..=256 {
        if *ptr.add(index) == 0 {
            return if index == 0 {
                Err(libc::EINVAL)
            } else {
                Ok(index)
            };
        }
    }
    Err(libc::EINVAL)
}

fn finish_plans(plan: &mut BlueOsDlPlan) -> Result<(), i32> {
    let mut error = 0;
    while plan.token != 0 {
        if plan.error != 0 {
            error = plan.error;
        }
        if plan.abi_version != DL_PLAN_ABI_VERSION
            || (plan.struct_size as usize) < core::mem::size_of::<BlueOsDlPlan>()
            || (plan.count != 0 && plan.entries.is_null())
        {
            return Err(libc::EINVAL);
        }
        for index in 0..plan.count {
            // Kernel-produced, validated code targets. Backings and this array
            // remain pinned until DlFinish, even through recursive callbacks.
            unsafe {
                let function: extern "C" fn() = core::mem::transmute(*plan.entries.add(index));
                function();
            }
        }
        let rc = bk_syscall!(DlFinish, plan.token, plan as *mut BlueOsDlPlan) as isize;
        if rc < 0 {
            return Err((-rc) as i32);
        }
    }
    if error == 0 {
        Ok(())
    } else {
        Err(error)
    }
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn dlopen(filename: *const c_char, flags: c_int) -> *mut c_void {
    let len = if filename.is_null() {
        0
    } else {
        match string_len(filename) {
            Ok(len) => len,
            Err(errno) => {
                fail("dlopen", errno);
                return core::ptr::null_mut();
            }
        }
    };
    let mut plan = BlueOsDlPlan::empty();
    let rc = bk_syscall!(
        DlOpen,
        filename as *const u8,
        len,
        flags,
        &mut plan as *mut BlueOsDlPlan
    ) as isize;
    if rc < 0 {
        fail("dlopen", (-rc) as i32);
        return core::ptr::null_mut();
    }
    let handle = plan.handle;
    if let Err(errno) = finish_plans(&mut plan) {
        fail("dlopen", errno);
        return core::ptr::null_mut();
    }
    handle as *mut c_void
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void {
    let len = match string_len(symbol) {
        Ok(len) => len,
        Err(errno) => {
            fail("dlsym", errno);
            return core::ptr::null_mut();
        }
    };
    let mut result = 0usize;
    let rc = bk_syscall!(
        DlSym,
        handle as usize,
        symbol as *const u8,
        len,
        &mut result as *mut usize
    ) as isize;
    if rc < 0 {
        fail("dlsym", (-rc) as i32);
        return core::ptr::null_mut();
    }
    result as *mut c_void
}

#[no_mangle]
#[linkage = "weak"]
pub extern "C" fn dlclose(handle: *mut c_void) -> c_int {
    let mut plan = BlueOsDlPlan::empty();
    let rc = bk_syscall!(DlClose, handle as usize, &mut plan as *mut BlueOsDlPlan) as isize;
    if rc < 0 {
        fail("dlclose", (-rc) as i32);
        return -1;
    }
    match finish_plans(&mut plan) {
        Ok(()) => 0,
        Err(errno) => {
            fail("dlclose", errno);
            -1
        }
    }
}

#[no_mangle]
#[linkage = "weak"]
pub extern "C" fn dlerror() -> *mut c_char {
    let mut error = ERROR.borrow_mut();
    if !error.pending {
        return core::ptr::null_mut();
    }
    error.pending = false;
    error.bytes.as_mut_ptr().cast()
}

#[cfg(librs_dso)]
pub(crate) fn close_at_exit() {
    let mut plan = BlueOsDlPlan::empty();
    if bk_syscall!(DlExit, &mut plan as *mut BlueOsDlPlan) as isize >= 0 {
        let _ = finish_plans(&mut plan);
    }
}
