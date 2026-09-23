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

#![cfg_attr(not(std), no_std)]
#![cfg_attr(test, feature(custom_test_frameworks))]
#![cfg_attr(test, test_runner(librs_test_runner))]
#![cfg_attr(test, reexport_test_harness_main = "librs_test_main")]
#![cfg_attr(test, no_main)]
#![allow(internal_features)]
#![feature(c_size_t)]
#![feature(slice_internals)]
#![feature(ptr_as_uninit)]
#![feature(linkage)]
#![feature(lang_items)]
#![feature(thread_local)]
#![feature(box_as_ptr)]
#![feature(atomic_from_mut)]
#![feature(c_variadic)]
#![feature(array_ptr_get)]
#![feature(sync_unsafe_cell)]

#[macro_use]
extern crate alloc;

#[cfg(test)]
extern crate rsrt;

#[cfg(librs_dso)]
use crate::application_context::LibcApplicationContext;
#[cfg(librs_dso)]
use blueos_header::syscalls::NR::{
    ApplicationBeginExit, ApplicationFinishExit, ApplicationInitComplete,
};
#[cfg(librs_dso)]
use blueos_scal::bk_syscall;
#[cfg(librs_dso)]
use core::ffi::{c_char, c_int};

// We don't expose any interfaces or types externally, rust-lang/libc is doing that.
#[cfg(armv7m)]
pub mod application_context;
pub mod c_str;
pub mod ctype;
pub mod direct;
#[cfg(librs_dso)]
mod dso_rt;
pub mod errno;
pub mod fcntl;
pub mod io;
pub mod iter;
pub mod misc;
pub mod mqueue;
pub mod net;
pub mod pthread;
pub mod sched;
pub mod semaphore;
pub mod signal;
#[cfg(librs_dso)]
pub mod spawn;
pub mod stat;
pub mod stdio;
pub mod stdlib;
pub mod string;
pub mod sync;
pub mod sys_mmap;
pub mod syscall;
pub mod time;
pub mod tls;
pub mod types;
pub mod unistd;

/// Static (non-dynamic) application entry, preserved for the `kernel/rsrt`
/// static `std` path and existing static apps. The dynamic DSO
/// entry is [`__librs_start_main`] with a `(main, info)` signature.
///
/// Compiled out of the shared libc: it calls the application's `main` symbol
/// directly, which a DSO must not reference (the dynamic entry receives `main`
/// as a parameter instead).
#[cfg(not(librs_dso))]
#[no_mangle]
pub extern "C" fn __librs_start_main_static() {
    crate::stdio::init();
    crate::pthread::register_my_posix_tcb();
    // TODO: Pass argc, argv and envp?
    // TODO: Before exit, we have to check owned threads' status and recycle them.
    extern "C" {
        fn main() -> i32;
    }
    unsafe {
        main();
    }
}

/// Dynamic application entry exported by `libc.so.1`.
///
/// `blueos_scrt1::_start` tail-calls this with the application's `main` and the
/// pinned `ApplicationStartInfo *`. It runs the whole application sequence —
/// validate → init plan → `ApplicationInitComplete` → `main(argc, argv, envp)`
/// → `ApplicationBeginExit` → atexit/fini → `ApplicationFinishExit` — and never
/// returns; the last step performs the retirement a trailing `ExitThread` would
/// otherwise do.
#[cfg(librs_dso)]
#[no_mangle]
pub extern "C" fn __librs_start_main(
    main: extern "C" fn(
        argc: c_int,
        argv: *const *const c_char,
        envp: *const *const c_char,
    ) -> c_int,
    info: *const blueos_header::application::BlueOsApplicationStartInfo,
) -> ! {
    // validate the versioned prefix and every nested count/pointer.
    let info = match validate_start_info(info) {
        Some(info) => info,
        None => park(),
    };

    crate::stdio::init();

    // register the main TCB and install the application context before
    // any constructor runs (a ctor may call `getauxval`/`atexit`/`pthread_create`).
    let context = match LibcApplicationContext::new(info) {
        Some(context) => context,
        None => park(),
    };
    crate::pthread::register_my_posix_tcb_with_context(context.clone());

    // run the init plan in storage order. The plan was validated
    // above; executing it is the one audited librs boundary that turns the
    // loader's `usize` targets back into function pointers.
    run_plan(&info.init_plan);

    // Signal init completion. The server derives the authoritative group and
    // generation handle from the current thread's membership.
    let _ = bk_syscall!(ApplicationInitComplete);

    // invoke the application.
    let status = main(info.argc as c_int, info.argv, info.envp);

    // forbid new threads and wait for the other members.
    let _ = bk_syscall!(ApplicationBeginExit, status);

    // application-owned atexit, reverse registration order.
    context.run_atexit();

    // fini plan is already stored reverse-order; walk storage order.
    run_plan(&info.fini_plan);

    // main-thread pthread-key/emutls destructors, then drop the TCB.
    crate::pthread::cleanup_my_tcb();

    // `ApplicationFinishExit` retires this thread and never unwinds the
    // startup frame. The TCB has released its context clone, so release the
    // entry's last strong reference (and its owned auxv copy) explicitly.
    drop(context);

    // finish the two-phase exit and retire. `finish_exit` never returns
    // (it performs `retire_me`), which subsumes the trailing `ExitThread`.
    let _ = bk_syscall!(ApplicationFinishExit);
    park()
}

/// Validate the start-info block and return a shared reference to it, or `None`
/// when the version, prefix size, or a nested count/pointer pair is inconsistent.
/// A `None` result is a fatal setup error: the entry parks.
#[cfg(librs_dso)]
fn validate_start_info(
    info: *const blueos_header::application::BlueOsApplicationStartInfo,
) -> Option<&'static blueos_header::application::BlueOsApplicationStartInfo> {
    use blueos_header::application::APPLICATION_START_INFO_ABI_VERSION;

    if info.is_null() {
        return None;
    }
    // SAFETY: `info` is the kernel-pinned start block handed to `_start`; the
    // null check above and the count/pointer checks below bound every read.
    let info = unsafe { &*info };
    if info.abi_version != APPLICATION_START_INFO_ABI_VERSION {
        return None;
    }
    if info.struct_size < core::mem::size_of_val(info) as u32 {
        return None;
    }
    // argv/envp are C `char **` arrays of the given length. A non-zero count
    // must be backed by a non-null pointer array; a zero count needs no array
    // (the kernel still emits a `[null]` terminator, so a non-null pointer with
    // zero count is valid and simply unused).
    if (info.argc > 0 && info.argv.is_null()) || (info.envc > 0 && info.envp.is_null()) {
        return None;
    }
    // auxv and both plans must be self-consistent too.
    if (info.auxv_count > 0 && info.auxv.is_null())
        || !plan_valid(&info.init_plan)
        || !plan_valid(&info.fini_plan)
    {
        return None;
    }
    Some(info)
}

/// Validate a constructor/destructor plan's versioned prefix. A
/// non-empty plan must be backed by a non-null target array; an empty plan needs
/// none (the array may still be present, so `count == 0` accepts either).
#[cfg(librs_dso)]
fn plan_valid(plan: &blueos_header::application::BlueOsFunctionPlan) -> bool {
    use blueos_header::application::FUNCTION_PLAN_ABI_VERSION;
    if plan.abi_version != FUNCTION_PLAN_ABI_VERSION {
        return false;
    }
    if plan.struct_size < core::mem::size_of_val(plan) as u32 {
        return false;
    }
    plan.count == 0 || !plan.entries.is_null()
}

/// Walk a validated plan in storage order, invoking each entry. This is the
/// audited librs boundary that re-materialises the loader's
/// `usize` targets as function pointers; the Thumb bit is part of
/// the stored address and is preserved by the `transmute`.
#[cfg(librs_dso)]
fn run_plan(plan: &blueos_header::application::BlueOsFunctionPlan) {
    for i in 0..plan.count {
        // SAFETY: `entries` is the kernel-pinned target array; `i < count` and
        // `plan_valid` confirmed the pointer/version/prefix. The target address
        // was installed by the loader with a live allocation lease.
        let target = unsafe { *plan.entries.add(i) };
        // SAFETY: the loader only emits canonical, executable Thumb entry
        // addresses here.
        let function: extern "C" fn() = unsafe { core::mem::transmute(target) };
        function();
    }
}

/// Terminal landing pad: park the core. Used on unrecoverable setup errors and
/// as the trailing `-> !` of the entry; `ApplicationFinishExit` retires before
/// this is ever reached on the normal path.
#[cfg(librs_dso)]
fn park() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

// FIXME: Remove this when we have a proper libc implementation.
#[cfg(feature = "linux_emulation")]
#[path = "../tests/linux_emulation_test/utils.rs"]
pub mod utils;

#[cfg(target_arch = "arm")]
#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn __aeabi_unwind_cpp_pr0() {
    panic!("Unwind not implemented")
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn _Unwind_Backtrace(
    _trace: *mut core::ffi::c_void,
    _arg: *mut core::ffi::c_void,
) -> core::ffi::c_int {
    todo!()
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn _Unwind_GetIP(_context: *mut core::ffi::c_void) -> core::ffi::c_int {
    todo!()
}

#[cfg(test)]
use semihosting::println;

#[cfg(test)]
pub fn librs_test_runner(tests: &[&dyn Fn()]) {
    crate::stdio::init();
    println!("Librs unittest started");
    println!("Running {} tests", tests.len());
    for test in tests {
        test();
    }
    println!("Librs unittest ended");

    #[cfg(coverage)]
    blueos::coverage::write_coverage_data();
}

#[cfg(test)]
#[no_mangle]
extern "C" fn main() -> i32 {
    pthread::register_my_posix_tcb();
    librs_test_main();
    0
}
