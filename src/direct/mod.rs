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

use crate::{
    c_str::CStr,
    errno::{Errno, ERRNO},
    stdio::File,
    stdlib::malloc::{free, malloc},
    string::memcpy,
    syscall::{Sys, Syscall},
};

use alloc::{boxed::Box, vec::Vec};
use blueos_header::syscalls::NR::{Close, Fcntl, GetDents, Lseek, Mount, Umount};
use blueos_scal::bk_syscall;
use core::{ptr, slice};
use libc::{c_char, c_int, c_long, c_ulong, c_void, off_t, EINVAL, EIO, ENOMEM, SEEK_SET};

const INITIAL_BUFSIZE: usize = 512;
pub struct DIR {
    pub file: File,
    pub name: *const c_char,
    pub buf: Vec<u8>,
    pub buf_offset: usize,
    pub opaque_offset: usize,
}

impl DIR {
    pub fn new(path: CStr) -> Result<Box<Self>, Errno> {
        Ok(Box::new(Self {
            file: File::open(path, libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC)?,
            name: path.as_ptr(),
            buf: Vec::with_capacity(INITIAL_BUFSIZE),
            buf_offset: 0,
            opaque_offset: 0,
        }))
    }
    fn next_dirent(&mut self) -> Result<*mut libc::dirent, Errno> {
        let mut this_dent = self.buf.get(self.buf_offset..).ok_or(Errno(EIO))?;
        if this_dent.is_empty() {
            let size = loop {
                self.buf.resize(self.buf.capacity(), 0_u8);

                match Sys::getdents(*self.file, &mut self.buf) {
                    Ok(size) => break size,
                    Err(Errno(EINVAL)) => {
                        self.buf
                            .try_reserve_exact(self.buf.len())
                            .map_err(|_| Errno(ENOMEM))?;
                        continue;
                    }
                    Err(Errno(other)) => return Err(Errno(other)),
                }
            };

            self.buf.truncate(size);
            self.buf_offset = 0;

            if size == 0 {
                return Ok(core::ptr::null_mut());
            }
            this_dent = &self.buf;
        }
        let (this_reclen, this_next_opaque) = unsafe {
            let dent = this_dent.as_ptr() as *const libc::dirent;
            ((*dent).d_reclen as usize, (*dent).d_off as usize)
        };
        let next_off = self.buf_offset.checked_add(this_reclen).ok_or(Errno(EIO))?;
        if next_off > self.buf.len() {
            return Err(Errno(EIO));
        }

        if this_dent.len() < this_reclen {
            return Err(Errno(EIO));
        }
        let dent_ptr = this_dent.as_ptr() as *mut libc::dirent;

        self.opaque_offset = this_next_opaque;
        self.buf_offset = next_off;
        Ok(dent_ptr)
    }
    fn seek(&mut self, off: u64) {
        // NOTE: just use blueos syscall, it's internal function
        // we won't adpat internal interface
        let ret = bk_syscall!(Lseek, *self.file, off as usize, SEEK_SET) as off_t;
        if ret < 0 {
            return;
        }
        self.buf.clear();
        self.buf_offset = 0;
        self.opaque_offset = off as usize;
    }
    fn rewind(&mut self) {
        self.opaque_offset = 0;
        // NOTE: just use blueos syscall, it's internal function
        // we won't adpat internal interface
        bk_syscall!(Lseek, *self.file, 0, SEEK_SET);
        self.buf.clear();
        self.buf_offset = 0;
        self.opaque_offset = 0;
    }
    fn close(mut self) -> Result<(), Errno> {
        self.file.reference = true;
        // NOTE: just use blueos syscall, it's internal function
        // we won't adpat internal interface
        let err = bk_syscall!(Close, *self.file) as c_int;
        if err < 0 {
            return Err(Errno(err));
        }
        Ok(())
    }
}

/// See <https://pubs.opengroup.org/onlinepubs/9799919799/functions/closedir.html>.
#[no_mangle]
pub extern "C" fn closedir(dir: Box<DIR>) -> c_int {
    dir.close().map(|_| 0).unwrap_or(-1)
}

/// See <https://pubs.opengroup.org/onlinepubs/9799919799/functions/fdopendir.html>.
#[no_mangle]
pub unsafe extern "C" fn fdopendir(fd: c_int) -> *mut DIR {
    let cloexec = bk_syscall!(Fcntl, fd, libc::F_GETFD, 0) as c_int;
    if cloexec < 0 {
        ERRNO.set(-cloexec);
        return ptr::null_mut();
    }

    if (cloexec & libc::FD_CLOEXEC) == 0 {
        let ret = bk_syscall!(
            Fcntl,
            fd,
            libc::F_SETFD,
            (cloexec | libc::FD_CLOEXEC) as usize
        ) as c_int;
        if ret < 0 {
            ERRNO.set(-ret);
            return ptr::null_mut();
        }
    }

    let dir = Box::new(DIR {
        file: File::new(fd),
        name: ptr::null(),
        buf: Vec::with_capacity(INITIAL_BUFSIZE),
        buf_offset: 0,
        opaque_offset: 0,
    });
    Box::into_raw(dir)
}

/// See <https://pubs.opengroup.org/onlinepubs/9799919799/functions/opendir.html>.
#[no_mangle]
pub unsafe extern "C" fn opendir(path: *const c_char) -> *mut DIR {
    let path = unsafe { CStr::from_ptr(path) };

    let od = DIR::new(path);
    match od {
        Ok(dir) => Box::into_raw(dir),
        Err(Errno(errno)) => {
            ERRNO.set(errno);
            core::ptr::null_mut()
        }
    }
}

/// See <https://pubs.opengroup.org/onlinepubs/9799919799/functions/dirfd.html>.
#[no_mangle]
pub unsafe extern "C" fn dirfd(dirp: *mut DIR) -> c_int {
    if dirp.is_null() {
        ERRNO.set(EINVAL);
        return -1;
    }
    *(*dirp).file
}

#[no_mangle]
pub unsafe extern "C" fn posix_getdents(fd: c_int, buf: *mut c_void, nbyte: usize) -> isize {
    if buf.is_null() {
        ERRNO.set(EINVAL);
        return -1;
    }

    let ret = bk_syscall!(GetDents, fd, buf, nbyte) as isize;
    if ret < 0 {
        ERRNO.set((-ret) as c_int);
        return -1;
    }
    ret
}

/// See <https://pubs.opengroup.org/onlinepubs/9799919799/functions/readdir.html>.
#[no_mangle]
pub extern "C" fn readdir(dir: &mut DIR) -> *mut libc::dirent {
    let nd = dir.next_dirent();
    match nd {
        Ok(ptr) => ptr,
        Err(Errno(errno)) => {
            ERRNO.set(errno);
            core::ptr::null_mut()
        }
    }
}

/// See <https://pubs.opengroup.org/onlinepubs/9799919799/functions/readdir.html>.
///
/// # Deprecation
/// The `readdir_r()` function was marked obsolescent in the Open Group Base
/// Specifications Issue 8.
#[deprecated]
// #[no_mangle]
pub extern "C" fn readdir_r(
    _dir: *mut DIR,
    _entry: *mut libc::dirent,
    _result: *mut *mut libc::dirent,
) -> *mut libc::dirent {
    unimplemented!(); // plus, deprecated
}

/// See <https://pubs.opengroup.org/onlinepubs/9799919799/functions/rewinddir.html>.
#[no_mangle]
pub extern "C" fn rewinddir(dir: &mut DIR) {
    dir.rewind();
}

/// See <https://pubs.opengroup.org/onlinepubs/9799919799/functions/scandir.html>.
#[no_mangle]
pub unsafe extern "C" fn scandir(
    dirp: *const c_char,
    namelist: *mut *mut *mut libc::dirent,
    filter: Option<extern "C" fn(_: *const libc::dirent) -> c_int>,
    compare: Option<
        extern "C" fn(_: *mut *const libc::dirent, _: *mut *const libc::dirent) -> c_int,
    >,
) -> c_int {
    let dir = unsafe { opendir(dirp) };
    if dir.is_null() {
        return -1;
    }

    let mut vec = Vec::with_capacity(4);

    let old_errno = ERRNO.get();
    ERRNO.set(0);

    loop {
        let entry: *mut libc::dirent = readdir(unsafe { &mut *dir });
        if entry.is_null() {
            break;
        }

        if let Some(filter) = filter {
            if filter(entry) == 0 {
                continue;
            }
        }

        let copy = unsafe { malloc((*entry).d_reclen as usize) };
        if copy.is_null() {
            break;
        }
        unsafe {
            memcpy(
                copy as *mut core::ffi::c_void,
                entry as *const core::ffi::c_void,
                (*entry).d_reclen as usize,
            )
        };
        vec.push(copy);
    }

    closedir(unsafe { Box::from_raw(dir) });

    let len = vec.len();
    vec.shrink_to_fit();

    if ERRNO.get() != 0 {
        for ptr in &mut vec {
            unsafe { free(*ptr as *mut c_void) };
        }
        -1
    } else {
        unsafe {
            *namelist = vec.leak().as_mut_ptr() as *mut *mut libc::dirent;
        }

        ERRNO.set(old_errno);
        if let Some(compare) = compare {
            let slice = unsafe { slice::from_raw_parts_mut(*namelist, len) };
            slice.sort_by(|a, b| {
                let mut a_ptr = *a as *const libc::dirent;
                let mut b_ptr = *b as *const libc::dirent;
                compare(&mut a_ptr, &mut b_ptr).cmp(&0)
            });
        }
        len as c_int
    }
}

/// See <https://pubs.opengroup.org/onlinepubs/9799919799/functions/alphasort.html>.
#[no_mangle]
pub unsafe extern "C" fn alphasort(
    a: *mut *const libc::dirent,
    b: *mut *const libc::dirent,
) -> c_int {
    if a.is_null() || b.is_null() {
        return 0;
    }
    let a_name = (*(*a)).d_name.as_ptr() as *const c_char;
    let b_name = (*(*b)).d_name.as_ptr() as *const c_char;
    crate::string::strcoll(a_name, b_name)
}

/// See <https://pubs.opengroup.org/onlinepubs/9799919799/functions/seekdir.html>.
#[no_mangle]
pub extern "C" fn seekdir(dir: &mut DIR, off: c_long) {
    dir.seek(
        off.try_into()
            .expect("off must come from telldir, thus never negative"),
    );
}

/// See <https://pubs.opengroup.org/onlinepubs/9799919799/functions/telldir.html>.
#[no_mangle]
pub extern "C" fn telldir(dir: &mut DIR) -> c_long {
    dir.opaque_offset as c_long
}
#[no_mangle]
pub unsafe extern "C" fn mount(
    _source: *const c_char,
    _target: *const c_char,
    _filesystemtype: *const c_char,
    _mountflags: c_ulong,
    _data: *const c_void,
) -> c_int {
    // NOTE: not posix call
    bk_syscall!(Mount, _source, _target, _filesystemtype, _mountflags, _data) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn umount(_target: *const c_char) -> c_int {
    // NOTE: not posix call
    bk_syscall!(Umount, _target) as c_int
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::println;
    use blueos_test_macro::test;

    #[cfg(enable_vfs)]
    #[test]
    fn test_scandir() {
        let path = CStr::from_bytes_with_nul(b"/\0").unwrap();
        let mut namelist: *mut *mut libc::dirent = ptr::null_mut();
        let count = unsafe { scandir(path.as_ptr(), &mut namelist, None, None) };
        assert!(count >= 0);
        if count > 0 {
            unsafe {
                for i in 0..count as usize {
                    let entry = *namelist.add(i);
                    println!(
                        "Entry {}: {}",
                        i,
                        CStr::from_ptr((*entry).d_name.as_ptr() as *const c_char)
                            .to_str()
                            .unwrap()
                    );
                    free(entry as *mut c_void);
                }
                free(namelist as *mut c_void);
            }
        }
    }
}
