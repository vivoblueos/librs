// FIXME: This file currently supports only the ESP32-C3 platform and has not
// received maintainability improvements yet. Rework it for broader support
// and better maintainability in a future update.
#![cfg_attr(librs_esp32_flash_shared, no_std)]

#[cfg(not(librs_esp32_flash_shared))]
pub use librs_esp32_flash_shared::*;

#[cfg(librs_esp32_flash_shared)]
mod shared {
    pub const ESP32_FLASH_DEVICE_NAME: &str = "esp32-flash0";

    pub const ESP32_FLASH_ERASE_RANGE: u32 = 0x40;
    pub const ESP32_FLASH_MAP_EXEC: u32 = 0x44;
    pub const ESP32_FLASH_UNMAP: u32 = 0x45;
    pub const FLASH_IOCTL_ABI_VERSION: u32 = 1;
    pub const ESP32_FLASH_QUERY_DRAM_SAFE: u32 = 0x46;

    pub const ESP_FLASH_SECTOR_SIZE: usize = 4096;

    #[repr(C)]
    pub struct EraseRangeRequest {
        pub version: u32,
        pub size: u32,
        pub flags: u32,
        pub region_offset: u32,
        pub length: u32,
    }

    #[repr(C)]
    pub struct MapExecRequest {
        pub version: u32,
        pub size: u32,
        pub flags: u32,
        pub region_offset: u32,
        pub image_size: u32,
        pub mapped_address: u32,
    }

    #[derive(Debug, Clone, Copy, Eq, PartialEq)]
    pub enum EspFlashError {
        OutOfBounds,
        ProtectedRange,
        InvalidLength,
        UnalignedErase,
        UnalignedWrite,
        Busy,
        RomError(i32),
        VerifyFailed,
    }

    #[derive(Debug, Clone, Copy)]
    pub struct InternalFlashRegion {
        base: u32,
        size: u32,
    }

    impl InternalFlashRegion {
        pub const fn new(base: u32, size: u32) -> Self {
            Self { base, size }
        }

        pub const fn size(&self) -> u32 {
            self.size
        }

        pub const fn base(&self) -> u32 {
            self.base
        }

        pub fn absolute_offset(
            &self,
            relative_offset: u32,
            len: usize,
        ) -> Result<u32, EspFlashError> {
            let len = u32::try_from(len).map_err(|_| EspFlashError::OutOfBounds)?;
            let relative_end = relative_offset
                .checked_add(len)
                .ok_or(EspFlashError::OutOfBounds)?;
            if relative_end > self.size {
                return Err(EspFlashError::OutOfBounds);
            }
            self.base
                .checked_add(relative_offset)
                .ok_or(EspFlashError::OutOfBounds)
        }

        pub fn validate(&self, flash_capacity: u32) -> Result<(), EspFlashError> {
            if self.base % ESP_FLASH_SECTOR_SIZE as u32 != 0 {
                return Err(EspFlashError::UnalignedErase);
            }
            if self.size % ESP_FLASH_SECTOR_SIZE as u32 != 0 {
                return Err(EspFlashError::UnalignedErase);
            }
            let end = self
                .base
                .checked_add(self.size)
                .ok_or(EspFlashError::OutOfBounds)?;
            if end > flash_capacity {
                return Err(EspFlashError::OutOfBounds);
            }
            Ok(())
        }
    }
}

#[cfg(librs_esp32_flash_shared)]
pub use shared::*;
