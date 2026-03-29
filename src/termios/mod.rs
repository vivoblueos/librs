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

use crate::errno::ERRNO;
use blueos_header::syscalls::NR::Ioctl;
use blueos_scal::bk_syscall;
use libc::{
    c_int, c_ulong, speed_t, B0, B38400, B4000000, B57600, EINVAL, TCFLSH, TCGETS, TCSBRK, TCSETS,
    TCSETSF, TCSETSW, TCXONC,
};

// librs target is compatible with posix termios interface
// almost all unix os use the same ioctl numbers for termios

// ioctl numbers
// e.g pub const TCGETS: c_ulong = 0x5401;

// c_iflags
// e.g pub const IGNBRK: usize = 0o000_001;

// c_cc special control characters
// e.g pub const VINTR: usize = 0;

// c_cflags
// e.g pub const B0: usize = 0o000_000;

// c_lflags
// e.g pub const ISIG: usize = 0o000_001;

// consistent with blueos termios definition
#[repr(C)]
#[derive(Default, Clone)]
pub struct termios {
    pub c_iflag: u32,
    pub c_oflag: u32,
    pub c_cflag: u32,
    pub c_lflag: u32,
    pub c_cc: [u8; 12],
    pub __c_ispeed: u32,
    pub __c_ospeed: u32,
}

// guarantee ABI match when linked against libc
// static_assertions::assert_eq_size!(termios, libc::termios);
// static_assertions::assert_eq_align!(termios, libc::termios);

#[no_mangle]
pub unsafe extern "C" fn tcgetattr(fd: c_int, out: *mut termios) -> c_int {
    bk_syscall!(Ioctl, fd, TCGETS, out as *mut core::ffi::c_void) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn tcsetattr(fd: c_int, act: c_int, value: *const termios) -> c_int {
    if !(0..=2).contains(&act) {
        ERRNO.set(EINVAL);
        return -1;
    }
    bk_syscall!(
        Ioctl,
        fd,
        [TCSETS, TCSETSW, TCSETSF][act as usize],
        value as *mut core::ffi::c_void
    ) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn tcflush(fd: c_int, queue: c_int) -> c_int {
    bk_syscall!(Ioctl, fd, TCFLSH, queue as *mut core::ffi::c_void) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn tcdrain(fd: c_int) -> c_int {
    // non-zero arg means wait for output to be transmitted
    bk_syscall!(Ioctl, fd, TCSBRK, 1 as c_int as *mut core::ffi::c_void) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn tcsendbreak(fd: c_int, dur: c_int) -> c_int {
    if dur < 0 {
        ERRNO.set(EINVAL);
        return -1;
    }
    bk_syscall!(Ioctl, fd, TCSBRK, 0 as c_int as *mut core::ffi::c_void) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn tcflow(fd: c_int, action: c_int) -> c_int {
    bk_syscall!(Ioctl, fd, TCXONC, action as *mut core::ffi::c_void) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn cfgetispeed(termios_p: *const termios) -> speed_t {
    (*termios_p).__c_ispeed
}

#[no_mangle]
pub unsafe extern "C" fn cfgetospeed(termios_p: *const termios) -> speed_t {
    (*termios_p).__c_ospeed
}

#[no_mangle]
pub unsafe extern "C" fn cfsetispeed(termios_p: *mut termios, speed: speed_t) -> c_int {
    match speed {
        B0..=B38400 | B57600..=B4000000 => {
            (*termios_p).__c_ispeed = speed;
            0
        }
        _ => {
            ERRNO.set(EINVAL);
            -1
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn cfsetospeed(termios_p: *mut termios, speed: speed_t) -> c_int {
    match speed {
        B0..=B38400 | B57600..=B4000000 => {
            (*termios_p).__c_ospeed = speed;
            0
        }
        _ => {
            ERRNO.set(EINVAL);
            -1
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn cfsetspeed(termios_p: *mut termios, speed: speed_t) -> c_int {
    let r = cfsetispeed(termios_p, speed);
    if r < 0 {
        return r;
    }
    cfsetospeed(termios_p, speed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use blueos_test_macro::test;
    use libc::{STDIN_FILENO, STDOUT_FILENO, TCIOFF, TCION, TCSADRAIN, TCSAFLUSH, TCSANOW};

    fn new_termios() -> termios {
        termios::default()
    }

    unsafe fn reset_errno() {
        ERRNO.set(0);
    }

    unsafe fn capture_termios(fd: c_int) -> termios {
        let mut t = new_termios();
        assert_eq!(tcgetattr(fd, &mut t), 0);
        t
    }

    #[test]
    #[cfg_attr(
        target_board = "qemu_mps3_an547",
        ignore = "need check qemu console emulation flags in mps3_an547"
    )]
    fn check_tcgetattr_for_stdin() {
        unsafe {
            let mut t = new_termios();

            assert_eq!(tcgetattr(STDIN_FILENO, &mut t), 0);
        }
    }

    #[test]
    #[cfg_attr(target_board = "qemu_mps3_an547", ignore)]
    fn check_tcsetattr_invalid() {
        unsafe {
            reset_errno();
            let current = capture_termios(STDIN_FILENO);
            assert_eq!(tcsetattr(STDIN_FILENO, 3, &current), -1);
            assert_eq!(ERRNO.get(), EINVAL);
        }
    }

    #[test]
    #[cfg_attr(target_board = "qemu_mps3_an547", ignore)]
    fn check_tcsetattr_valid() {
        unsafe {
            let current = capture_termios(STDIN_FILENO);
            for &action in &[TCSANOW, TCSADRAIN, TCSAFLUSH] {
                assert_eq!(tcsetattr(STDIN_FILENO, action, &current), 0);
            }
        }
    }

    #[test]
    #[cfg_attr(target_board = "qemu_mps3_an547", ignore)]
    fn check_tcdrain_stdout() {
        unsafe {
            assert_eq!(tcdrain(STDOUT_FILENO), 0);
        }
    }

    #[test]
    fn check_tcsendbreak_invalid() {
        unsafe {
            reset_errno();
            assert_eq!(tcsendbreak(STDOUT_FILENO, -1), -1);
            assert_eq!(ERRNO.get(), EINVAL);
        }
    }

    #[test]
    #[ignore = "the default 250ms break duration will cause test timeout"]
    fn check_tcsendbreak_valid() {
        unsafe {
            assert_eq!(tcsendbreak(STDOUT_FILENO, 0), 0);
        }
    }

    #[test]
    #[cfg_attr(target_board = "qemu_mps3_an547", ignore)]
    fn check_tcflow_ioff_ion() {
        unsafe {
            assert_eq!(tcflow(STDIN_FILENO, TCIOFF), 0);
            assert_eq!(tcflow(STDIN_FILENO, TCION), 0);
        }
    }
}
