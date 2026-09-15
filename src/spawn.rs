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

//! `spawn` — launch another application from a dynamic application.
//!
//! The stable C ABI `spawn(path, argv, envp)` converts POSIX-style inputs into a
//! versioned [`BlueOsApplicationLaunchRequest`] and issues the `ApplicationLaunch`
//! syscall. librs never touches a kernel `ApplicationManager` symbol; the whole
//! launch path crosses the SWI boundary. The kernel performs the real
//! bounded copy-in of the header and the pointed-to string views, then returns a
//! handle or errno through the syscall result.

use alloc::vec::Vec;

use blueos_header::{
    application::{
        BlueOsApplicationLaunchRequest, BlueOsStringView, APPLICATION_LAUNCH_REQUEST_ABI_VERSION,
    },
    syscalls::NR::ApplicationLaunch,
};
use blueos_scal::bk_syscall;
use core::ffi::{c_char, c_long};

/// Bounds applied to librs's own scan of the caller's null-terminated pointer
/// arrays. The kernel enforces its own (stricter) limits during copy-in;
/// these stop a runaway `argv`/`envp` in the shared address space from scanning
/// without bound.
const MAX_ARGC: usize = 128;
const MAX_TOTAL_BYTES: usize = 4096;

/// Convert one NUL-terminated C string into a [`BlueOsStringView`].
fn string_view(s: *const c_char) -> Option<BlueOsStringView> {
    if s.is_null() {
        return None;
    }
    // SAFETY: `s` is a caller-supplied NUL-terminated string. BlueOS uses a
    // shared privileged address space without a fault-safe page table, so a
    // malformed pointer is the caller's own memory-safety bug; the
    // kernel copy-in performs the authoritative bounded validation.
    let bytes = unsafe { crate::c_str::CStr::from_ptr(s).to_bytes() };
    Some(BlueOsStringView {
        data: bytes.as_ptr(),
        len: bytes.len(),
    })
}

/// Convert a NUL-terminated `char **` array into `Vec<BlueOsStringView>`,
/// bounding both the element count and the total byte length. A null head is an
/// empty array (argc/envc 0), matching a bare `main()` launch.
fn string_array(head: *const *const c_char) -> Option<Vec<BlueOsStringView>> {
    if head.is_null() {
        return Some(Vec::new());
    }
    let mut views = Vec::new();
    let mut total = 0usize;
    let mut p = head;
    loop {
        // SAFETY: `p` walks the caller's `char **` array, terminated by a null
        // entry; the array-length and total-byte bounds below bound the walk.
        let entry = unsafe { *p };
        if entry.is_null() {
            break;
        }
        if views.len() >= MAX_ARGC {
            return None;
        }
        let view = string_view(entry)?;
        total = total.checked_add(view.len)?;
        if total > MAX_TOTAL_BYTES {
            return None;
        }
        views.push(view);
        p = unsafe { p.add(1) };
    }
    Some(views)
}

/// Stable C ABI `spawn(path, argv, envp)`.
///
/// Returns the `ApplicationLaunch` syscall result: a generation handle on
/// success, or a negative errno. The kernel handler validates and copies the
/// request; the handle encoding is defined by that handler, never by librs.
#[linkage = "weak"]
#[no_mangle]
pub extern "C" fn spawn(
    path: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_long {
    let Some(path_view) = string_view(path) else {
        return -(libc::EINVAL as c_long);
    };
    let Some(argv_views) = string_array(argv) else {
        return -(libc::E2BIG as c_long);
    };
    let Some(envp_views) = string_array(envp) else {
        return -(libc::E2BIG as c_long);
    };

    let argv_ptr = if argv_views.is_empty() {
        core::ptr::null()
    } else {
        argv_views.as_ptr()
    };
    let envp_ptr = if envp_views.is_empty() {
        core::ptr::null()
    } else {
        envp_views.as_ptr()
    };

    let request = BlueOsApplicationLaunchRequest {
        abi_version: APPLICATION_LAUNCH_REQUEST_ABI_VERSION,
        struct_size: core::mem::size_of::<BlueOsApplicationLaunchRequest>() as u32,
        path: path_view,
        argv: argv_ptr,
        argc: argv_views.len(),
        envp: envp_ptr,
        envc: envp_views.len(),
    };

    // `argv_views`/`envp_views` stay alive through the syscall: the handler
    // copies the fixed header and the pointed-to string views before returning.
    let rc = bk_syscall!(
        ApplicationLaunch,
        &request as *const BlueOsApplicationLaunchRequest
    );
    rc as c_long
}
