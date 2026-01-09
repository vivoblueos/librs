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
//

use blueos_header::syscalls::NR::{
    SchedGetPriorityMax, SchedGetPriorityMin, SchedRrGetInterval, SchedYield,
};
use blueos_scal::bk_syscall;
use libc::{c_int, pid_t, timespec};

#[allow(non_camel_case_types)]
pub struct sched_param {
    pub sched_priority: c_int,
}

pub const SCHED_RR: c_int = 1;

#[no_mangle]
pub extern "C" fn sched_get_priority_max(policy: c_int) -> c_int {
    bk_syscall!(SchedGetPriorityMax, policy) as c_int
}
#[no_mangle]
pub extern "C" fn sched_get_priority_min(policy: c_int) -> c_int {
    bk_syscall!(SchedGetPriorityMin, policy) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn sched_rr_get_interval(pid: pid_t, time: *mut timespec) -> c_int {
    bk_syscall!(SchedRrGetInterval, pid as c_int, time) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn sched_setscheduler(
    _pid: pid_t,
    _policy: c_int,
    _param: *const sched_param,
) -> c_int {
    -libc::ENOTSUP
}

// see https://pubs.opengroup.org/onlinepubs/9799919799/functions/sched_getscheduler.html
#[no_mangle]
pub unsafe extern "C" fn sched_getscheduler(_pid: pid_t) -> c_int {
    SCHED_RR
}

#[no_mangle]
pub extern "C" fn sched_yield() -> c_int {
    bk_syscall!(SchedYield);
    // always succeed
    0
}

// define stubs for implementation defined functions
#[no_mangle]
pub unsafe extern "C" fn sched_getparam(_pid: pid_t, _param: *mut sched_param) -> c_int {
    -libc::ENOTSUP
}

#[no_mangle]
pub unsafe extern "C" fn sched_setparam(_pid: pid_t, _param: *const sched_param) -> c_int {
    -libc::ENOTSUP
}

#[cfg(test)]
mod tests {
    use super::*;
    use blueos_test_macro::test;
    #[test]
    fn check_sched_get_priority_max_min() {
        let max = super::sched_get_priority_max(super::SCHED_RR);
        let min = super::sched_get_priority_min(super::SCHED_RR);
        assert!(max > min);
    }

    #[test]
    fn check_sched_get_rr_interval() {
        let mut ts = timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let ret = unsafe { sched_rr_get_interval(0, &mut ts as *mut timespec) };
        assert_eq!(ret, 0);
        assert!(ts.tv_sec >= 0);
    }
}
