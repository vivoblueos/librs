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
// This code is based on relibc (original license follows):
// https://github.com/redox-os/relibc/blob/master/LICENSE
// standard MIT license

use crate::errno::ERRNO;
use core::ptr;
use libc::{c_char, c_int, c_uint, clockid_t, sem_t, timespec, CLOCK_MONOTONIC, EINVAL, ETIMEDOUT};

pub type RsSemaphore = crate::sync::semaphore::Semaphore;

#[no_mangle]
pub unsafe extern "C" fn sem_close(sem: *mut sem_t) -> c_int {
    ptr::drop_in_place(sem.cast::<RsSemaphore>());
    0
}

#[no_mangle]
pub unsafe extern "C" fn sem_destroy(sem: *mut sem_t) -> c_int {
    ptr::drop_in_place(sem.cast::<RsSemaphore>());
    0
}

#[no_mangle]
pub unsafe extern "C" fn sem_getvalue(sem: *mut sem_t, sval: *mut c_int) -> c_int {
    sval.write(get(sem).value() as c_int);

    0
}

#[no_mangle]
pub unsafe extern "C" fn sem_init(sem: *mut sem_t, _pshared: c_int, value: c_uint) -> c_int {
    sem.cast::<RsSemaphore>()
        .write(RsSemaphore::new(value as usize));

    0
}

/// See <https://pubs.opengroup.org/onlinepubs/9799919799/functions/sem_open.html>.
// TODO: va_list
// #[no_mangle]
pub unsafe extern "C" fn sem_open(
    _name: *const c_char,
    _oflag: c_int, /* (va_list) value: c_uint */
) -> *mut sem_t {
    todo!("named semaphores")
}

#[no_mangle]
pub unsafe extern "C" fn sem_post(sem: *mut sem_t) -> c_int {
    get(sem).post(1);

    0
}

#[no_mangle]
pub unsafe extern "C" fn sem_trywait(sem: *mut sem_t) -> c_int {
    if get(sem).try_wait() == 0 {
        ERRNO.set(libc::EAGAIN);
        -1
    } else {
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn sem_unlink(_name: *const c_char) -> c_int {
    todo!("named semaphores")
}

#[no_mangle]
pub unsafe extern "C" fn sem_wait(sem: *mut sem_t) -> c_int {
    if get(sem).wait(None) {
        0
    } else {
        ERRNO.set(ETIMEDOUT);
        -1
    }
}

#[no_mangle]
pub unsafe extern "C" fn sem_timedwait(sem: *mut sem_t, abs_timeout: *const timespec) -> c_int {
    if abs_timeout.is_null() {
        ERRNO.set(EINVAL);
        return -1;
    }

    if get(sem).wait(Some(&*abs_timeout)) {
        0
    } else {
        ERRNO.set(ETIMEDOUT);
        -1
    }
}

#[no_mangle]
pub unsafe extern "C" fn sem_clockwait(
    sem: *mut sem_t,
    clock_id: clockid_t,
    abs_timeout: *const timespec,
) -> c_int {
    if abs_timeout.is_null() {
        ERRNO.set(EINVAL);
        return -1;
    }
    if clock_id != CLOCK_MONOTONIC {
        ERRNO.set(EINVAL);
        return -1;
    }

    if get(sem).wait(Some(&*abs_timeout)) {
        0
    } else {
        ERRNO.set(ETIMEDOUT);
        -1
    }
}

unsafe fn get<'any>(sem: *mut sem_t) -> &'any RsSemaphore {
    &*sem.cast()
}

#[cfg(test)]
mod tests {
    use super::*;
    use blueos_test_macro::test;
    use core::mem::MaybeUninit;

    #[test]
    fn check_sem_timedwait() {
        let mut sem = MaybeUninit::<RsSemaphore>::uninit();
        unsafe {
            assert_eq!(sem_init(sem.as_mut_ptr().cast::<sem_t>(), 0, 0), 0);
            assert_eq!(
                sem_timedwait(sem.as_mut_ptr().cast::<sem_t>(), ptr::null()),
                -1
            );
            assert_eq!(ERRNO.get(), EINVAL);
            assert_eq!(sem_destroy(sem.as_mut_ptr().cast::<sem_t>()), 0);
        }
    }

    #[test]
    fn check_sem_clockwait() {
        let mut sem = MaybeUninit::<RsSemaphore>::uninit();
        unsafe {
            assert_eq!(sem_init(sem.as_mut_ptr().cast::<sem_t>(), 0, 0), 0);
            let timeout = timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };

            assert_eq!(
                sem_clockwait(
                    sem.as_mut_ptr().cast::<sem_t>(),
                    CLOCK_MONOTONIC,
                    ptr::null()
                ),
                -1
            );
            assert_eq!(ERRNO.get(), EINVAL);

            assert_eq!(
                sem_clockwait(sem.as_mut_ptr().cast::<sem_t>(), 0, &timeout),
                -1
            );
            assert_eq!(ERRNO.get(), EINVAL);

            assert_eq!(
                sem_clockwait(sem.as_mut_ptr().cast::<sem_t>(), CLOCK_MONOTONIC, &timeout),
                -1
            );
            assert_eq!(ERRNO.get(), ETIMEDOUT);
            assert_eq!(sem_destroy(sem.as_mut_ptr().cast::<sem_t>()), 0);
        }
    }
}
