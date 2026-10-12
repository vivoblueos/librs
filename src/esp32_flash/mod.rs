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

pub const ESP32_FLASH_DEVICE_NAME: &str = "esp32-flash0";

pub const ESP32_FLASH_ERASE_RANGE: u32 = 0x40;
pub const ESP32_FLASH_MAP_EXEC: u32 = 0x44;
pub const ESP32_FLASH_UNMAP: u32 = 0x45;
pub const ESP32_FLASH_QUERY_DRAM_SAFE: u32 = 0x46;
pub const ESP32_FLASH_MAP_DROM: u32 = 0x47;
pub const FLASH_IOCTL_ABI_VERSION: u32 = 1;

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

#[repr(C)]
pub struct MapDromRequest {
    pub version: u32,
    pub size: u32,
    pub flags: u32,
    pub region_offset: u32,
    pub image_size: u32,
    pub drom_vaddr: u32,
    pub mapped_address: u32,
}
