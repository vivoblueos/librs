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
use libc::{c_int, c_ulong};

// for now, our target is  support two type devices ioctl
// termio and network devices

#[no_mangle]
pub unsafe extern "C" fn ioctl(fd: c_int, request: c_ulong, out: *mut core::ffi::c_void) -> c_int {
    bk_syscall!(Ioctl, fd, request, out) as c_int
}
