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

// Signal related posix interfaces
// NOTE: only support standard posix signals now, real time signals are not supported yet.
// and won't queue multiple same signals. it means only signals from 1 to NSIG-1  (31) are supported
// and only one signal can be queued for each signal number.

// we implement such an model as close as the posix 2008.1b required:
// 1. each thread has an blocked mask and a pending mask (follow posix standard)
// 2. each thread has it's own signal handlers (violate posix standard, should be per process)
// 3. kill and sigqueue send to the specified thread(violate posix standard, should be every thread in the process)
// 4. tgkill use tgid 0 for group param (violate posix standard, but follow posix in semantics)
// so we can simplify every thread's signal handling almost same with posix required process signal handling

use super::errno::ERRNO;
use blueos_header::syscalls::NR::{
    Kill, RtSigAction, RtSigPending, RtSigProcmask, RtSigQueueInfo, RtSigSuspend, RtSigTimedWait,
    SigAltStack, Tgkill, Tkill,
};
use blueos_scal::bk_syscall;
use core::{mem, ptr};
use libc::{
    c_int, c_ulong, c_void, pid_t, sigaction as sigaction_t, sighandler_t, siginfo_t, sigset_t,
    sigval, size_t, stack_t as sigaltstack_t, timespec, NSIG, SA_RESTART, SIG_DFL, SIG_ERR,
    SIG_IGN,
};

const SIGSET_BIT_WIDTH: usize = core::mem::size_of::<sigset_t>() * 8;
const SIGSET_FULL_MASK: sigset_t = if NSIG >= SIGSET_BIT_WIDTH {
    sigset_t::MAX
} else {
    ((1u128 << NSIG) - 1) as sigset_t
};

#[inline]
fn mask_for_signal(signo: c_int) -> sigset_t {
    let shift = (signo as usize - 1) as u32;
    (1u128 << shift) as sigset_t
}

#[no_mangle]
pub unsafe extern "C" fn sigaction(
    sig: c_int,
    act: *const sigaction_t,
    oact: *mut sigaction_t,
) -> c_int {
    bk_syscall!(
        RtSigAction,
        sig,
        act as *const libc::c_void,
        oact as *mut libc::c_void
    ) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn sigaddset(set: *mut sigset_t, signo: c_int) -> c_int {
    if signo <= 0 || signo as usize > NSIG {
        ERRNO.set(libc::EINVAL);
        return -1;
    }

    if let Some(set) = unsafe { set.as_mut() } {
        *set |= mask_for_signal(signo);
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn sigaltstack(
    ss: *const sigaltstack_t,
    old_ss: *mut sigaltstack_t,
) -> c_int {
    bk_syscall!(
        SigAltStack,
        ss as *const libc::c_void,
        old_ss as *mut libc::c_void
    ) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn sigdelset(set: *mut sigset_t, signo: c_int) -> c_int {
    if signo <= 0 || signo as usize > NSIG {
        ERRNO.set(libc::EINVAL);
        return -1;
    }

    if let Some(set) = unsafe { set.as_mut() } {
        *set &= !mask_for_signal(signo);
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn sigemptyset(set: *mut sigset_t) -> c_int {
    if let Some(set) = unsafe { set.as_mut() } {
        *set = 0;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn sigfillset(set: *mut sigset_t) -> c_int {
    if let Some(set) = unsafe { set.as_mut() } {
        *set = SIGSET_FULL_MASK;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn sigismember(set: *const sigset_t, signo: c_int) -> c_int {
    if signo <= 0 || signo as usize > NSIG {
        ERRNO.set(libc::EINVAL);
        return -1;
    }

    if let Some(set) = unsafe { set.as_ref() } {
        if *set & mask_for_signal(signo) != 0 {
            return 1;
        }
    }
    0
}

#[no_mangle]
pub extern "C" fn signal(
    sig: c_int,
    func: Option<extern "C" fn(c_int)>,
) -> Option<extern "C" fn(c_int)> {
    let sa_sigaction: sighandler_t = match func {
        None => SIG_DFL,
        Some(f) => f as usize as sighandler_t,
    };
    let sa = sigaction_t {
        sa_sigaction,
        sa_mask: sigset_t::default(),
        sa_flags: SA_RESTART as c_int,
        sa_restorer: None,
    };
    let mut old_sa = mem::MaybeUninit::uninit();
    unsafe {
        if sigaction(sig, &sa, old_sa.as_mut_ptr()) < 0 {
            return core::mem::transmute::<isize, Option<extern "C" fn(c_int)>>(SIG_ERR as isize);
        }
        let old = old_sa.assume_init().sa_sigaction;
        if old == SIG_DFL || old == SIG_IGN {
            None
        } else if old == SIG_ERR {
            core::mem::transmute::<isize, Option<extern "C" fn(c_int)>>(SIG_ERR as isize)
        } else {
            Some(core::mem::transmute::<usize, extern "C" fn(c_int)>(
                old as usize,
            ))
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn sigpending(set: *mut sigset_t) -> c_int {
    bk_syscall!(RtSigPending, set) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn sigprocmask(
    how: c_int,
    set: *const sigset_t,
    oset: *mut sigset_t,
) -> c_int {
    // only process posix standard signals
    bk_syscall!(RtSigProcmask, how, set, oset) as c_int
}

#[no_mangle]
pub extern "C" fn sigqueue(pid: pid_t, sig: c_int, val: sigval) -> c_int {
    let mut si: siginfo_t = unsafe { core::mem::zeroed() };
    si.si_signo = sig;
    si.si_errno = 0;
    si.si_code = val.sival_ptr as c_int;
    bk_syscall!(
        RtSigQueueInfo,
        pid,
        sig,
        (&mut si as *mut siginfo_t).cast::<c_void>()
    ) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn sigsuspend(sigmask: *const sigset_t) -> c_int {
    let ret = bk_syscall!(RtSigSuspend, sigmask) as c_int;
    if ret < 0 {
        // currently we only return EINTR
        ERRNO.set(libc::EINTR);
        -1
    } else {
        ret
    }
}

#[no_mangle]
pub unsafe extern "C" fn sigtimedwait(
    set: *const sigset_t,
    sig: *mut siginfo_t,
    tp: *const timespec,
) -> c_int {
    bk_syscall!(RtSigTimedWait, set, sig as *mut c_void, tp) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn sigwait(set: *const sigset_t, sig: *mut c_int) -> c_int {
    let mut pinfo = mem::MaybeUninit::<siginfo_t>::uninit();
    if sigtimedwait(set, pinfo.as_mut_ptr(), ptr::null_mut()) < 0 {
        return -1;
    }
    let info = pinfo.assume_init();
    (*sig) = info.si_signo;
    0
}

#[no_mangle]
pub unsafe extern "C" fn sigwaitinfo(set: *const sigset_t, sig: *mut siginfo_t) -> c_int {
    sigtimedwait(set, sig, core::ptr::null())
}

#[no_mangle]
pub extern "C" fn kill(pid: pid_t, sig: c_int) -> c_int {
    bk_syscall!(Kill, pid, sig) as c_int
}

#[no_mangle]
pub extern "C" fn tgkill(tgid: pid_t, pid: pid_t, sig: c_int) -> c_int {
    // use tgid 0 to represent all threads in the system
    bk_syscall!(Tgkill, tgid, pid, sig) as c_int
}

#[no_mangle]
pub extern "C" fn tkill(pid: pid_t, sig: c_int) -> c_int {
    bk_syscall!(Tkill, pid, sig) as c_int
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{pthread::gettid, time::usleep};
    use blueos_test_macro::test;
    use core::{
        ptr,
        sync::atomic::{AtomicUsize, Ordering},
    };
    use libc::{
        pthread_create, pthread_join, pthread_t, sigset_t, sigval, timespec, SIG_BLOCK, SIG_SETMASK,
    };

    use libc::{SIGUSR1, SIGUSR2};

    static SIGNAL_COUNT: AtomicUsize = AtomicUsize::new(0);
    static TEST_THREAD_TID: AtomicUsize = AtomicUsize::new(0);

    extern "C" fn handle_sigusr1(_signum: c_int) {
        SIGNAL_COUNT.fetch_add(1, Ordering::SeqCst);
    }

    extern "C" fn send_sigusr1(_arg: *mut c_void) -> *mut c_void {
        let tid = TEST_THREAD_TID.load(Ordering::SeqCst) as pid_t;
        for _ in 0..5 {
            tkill(tid, SIGUSR1);
            usleep(10_000);
        }
        ptr::null_mut()
    }

    extern "C" fn sigqueue_usr2(_arg: *mut c_void) -> *mut c_void {
        let tid = TEST_THREAD_TID.load(Ordering::SeqCst) as pid_t;
        let val = sigval {
            sival_ptr: 1234 as *mut c_void,
        };
        for _ in 0..3 {
            sigqueue(tid, SIGUSR2, val);
            usleep(10_000);
        }
        ptr::null_mut()
    }

    extern "C" fn delayed_usr1(_arg: *mut c_void) -> *mut c_void {
        let tid = TEST_THREAD_TID.load(Ordering::SeqCst) as pid_t;
        usleep(20_000);
        tkill(tid, SIGUSR1);
        ptr::null_mut()
    }

    #[test]
    fn check_sigset_ops() {
        unsafe {
            TEST_THREAD_TID.store(gettid() as usize, Ordering::SeqCst);
            let mut set: sigset_t = 0;
            assert_eq!(sigemptyset(&mut set as *mut _), 0);
            assert_eq!(sigismember(&set as *const _, SIGUSR1), 0);

            assert_eq!(sigaddset(&mut set as *mut _, SIGUSR1), 0);
            assert_eq!(sigismember(&set as *const _, SIGUSR1), 1);
            assert_eq!(sigdelset(&mut set as *mut _, SIGUSR1), 0);
            assert_eq!(sigismember(&set as *const _, SIGUSR1), 0);
        }
    }

    #[test]
    fn check_sigprocmask() {
        unsafe {
            TEST_THREAD_TID.store(gettid() as usize, Ordering::SeqCst);
            let mut set: sigset_t = 0;
            // Block SIGUSR1, then send it; it should become pending.
            assert_eq!(sigaddset(&mut set as *mut _, SIGUSR1), 0);
            let mut old: sigset_t = 0;
            assert_eq!(
                sigprocmask(SIG_BLOCK, &set as *const _, &mut old as *mut _),
                0
            );

            tkill(TEST_THREAD_TID.load(Ordering::SeqCst) as pid_t, SIGUSR1);
            usleep(5_000);

            let mut pending: sigset_t = 0;
            assert_eq!(sigpending(&mut pending as *mut _), 0);
            assert_eq!(sigismember(&pending as *const _, SIGUSR1), 1);

            // Restore mask.
            assert_eq!(
                sigprocmask(SIG_SETMASK, &old as *const _, ptr::null_mut()),
                0
            );
        }
    }

    #[test]
    fn check_sigqueue_handler() {
        unsafe {
            TEST_THREAD_TID.store(gettid() as usize, Ordering::SeqCst);
            SIGNAL_COUNT.store(0, Ordering::SeqCst);

            // Install handler for SIGUSR1.
            signal(SIGUSR1, Some(handle_sigusr1));

            let mut tid: pthread_t = 0;
            assert_eq!(
                pthread_create(
                    &mut tid as *mut _,
                    ptr::null(),
                    send_sigusr1,
                    ptr::null_mut()
                ),
                0
            );
            // Wait a moment for delivery.
            usleep(50_000);
            assert_eq!(pthread_join(tid, ptr::null_mut()), 0);
            assert_eq!(SIGNAL_COUNT.load(Ordering::SeqCst), 5);
        }
    }

    #[test]
    fn check_sigtimedwait() {
        unsafe {
            TEST_THREAD_TID.store(gettid() as usize, Ordering::SeqCst);

            // Block SIGUSR2 in this thread so that sigtimedwait can consume it.
            let mut set: sigset_t = 0;
            sigemptyset(&mut set as *mut _);
            sigaddset(&mut set as *mut _, SIGUSR2);
            sigprocmask(SIG_BLOCK, &set as *const _, ptr::null_mut());

            // Create a helper that sigqueue(SIGUSR2) a few times.
            let mut tid: pthread_t = 0;
            assert_eq!(
                pthread_create(
                    &mut tid as *mut _,
                    ptr::null(),
                    sigqueue_usr2,
                    ptr::null_mut()
                ),
                0
            );

            let mut info = mem::MaybeUninit::<siginfo_t>::uninit();
            let tp = timespec {
                tv_sec: 1,
                tv_nsec: 0,
            };
            let got = sigtimedwait(&set as *const _, info.as_mut_ptr(), &tp as *const _);
            assert_eq!(got, SIGUSR2);

            assert_eq!(pthread_join(tid, ptr::null_mut()), 0);

            // Restore: unblock everything.
            let mut empty: sigset_t = 0;
            sigemptyset(&mut empty as *mut _);
            sigprocmask(SIG_SETMASK, &empty as *const _, ptr::null_mut());
        }
    }

    #[test]
    fn check_sigwait() {
        unsafe {
            TEST_THREAD_TID.store(gettid() as usize, Ordering::SeqCst);

            // Block SIGUSR2 in this thread so that sigwait can consume it.
            let mut set: sigset_t = 0;
            sigemptyset(&mut set as *mut _);
            sigaddset(&mut set as *mut _, SIGUSR2);
            sigprocmask(SIG_BLOCK, &set as *const _, ptr::null_mut());

            // Deliver SIGUSR2 (tid-targeted), then wait for it.
            let val = sigval {
                sival_ptr: 1 as *mut c_void,
            };
            sigqueue(
                TEST_THREAD_TID.load(Ordering::SeqCst) as pid_t,
                SIGUSR2,
                val,
            );
            let mut signo: c_int = 0;
            assert_eq!(sigwait(&set as *const _, &mut signo as *mut _), 0);
            assert_eq!(signo, SIGUSR2);

            // Restore: unblock everything.
            let mut empty: sigset_t = 0;
            sigemptyset(&mut empty as *mut _);
            sigprocmask(SIG_SETMASK, &empty as *const _, ptr::null_mut());
        }
    }

    #[test]
    fn check_sigsuspend() {
        unsafe {
            TEST_THREAD_TID.store(gettid() as usize, Ordering::SeqCst);

            // Block SIGUSR1 in this thread; sigsuspend will temporarily unblock it.
            let mut block_usr1: sigset_t = 0;
            sigemptyset(&mut block_usr1 as *mut _);
            sigaddset(&mut block_usr1 as *mut _, SIGUSR1);
            sigprocmask(SIG_BLOCK, &block_usr1 as *const _, ptr::null_mut());

            // During sigsuspend, keep SIGUSR2 blocked but allow SIGUSR1 to be delivered.
            let mut during: sigset_t = 0;
            sigemptyset(&mut during as *mut _);
            sigaddset(&mut during as *mut _, SIGUSR2);

            let mut tid2: pthread_t = 0;
            assert_eq!(
                pthread_create(
                    &mut tid2 as *mut _,
                    ptr::null(),
                    delayed_usr1,
                    ptr::null_mut()
                ),
                0
            );

            let rc = sigsuspend(&during as *const _);
            assert_eq!(rc, -1);
            assert_eq!(ERRNO.get(), libc::EINTR);

            assert_eq!(pthread_join(tid2, ptr::null_mut()), 0);

            // Restore: unblock everything.
            let mut empty: sigset_t = 0;
            sigemptyset(&mut empty as *mut _);
            sigprocmask(SIG_SETMASK, &empty as *const _, ptr::null_mut());
        }
    }
}
