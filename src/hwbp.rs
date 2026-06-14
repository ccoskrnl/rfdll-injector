#[allow(unused_imports)]

use obfuse::obfuse;

use anyhow::{Result, anyhow, Ok};

use crate::nt_api::*;
use crate::parse_pe::*;

use crate::{debug_eprintln, debug_println};

use winapi::ctypes::c_void;
use winapi::vc::excpt::{EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH};
use winapi::um::errhandlingapi::{AddVectoredExceptionHandler, RemoveVectoredExceptionHandler};
use winapi::um::winnt::{HANDLE, EXCEPTION_POINTERS, CONTEXT, CONTEXT_DEBUG_REGISTERS, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE};
use winapi::um::minwinbase::EXCEPTION_SINGLE_STEP;
use winapi::um::processthreadsapi::GetCurrentThread;
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
use winapi::um::memoryapi::{VirtualAlloc, VirtualFree};
use winapi::shared::ntdef::PCSTR;


const SYSCALL_STUB: [u8; 6] = [
    0x4C, 0x8B, 0xD1, // mov r10, rcx
    0x0F, 0x05, // syscall
    0xC3, // ret
];

static mut SSN_0: u32 = 0;
static mut SSN_1: u32 = 0;
static mut SSN_2: u32 = 0;
static mut SSN_3: u32 = 0;
static mut STUB_ADDR: *mut u8 = std::ptr::null_mut();


unsafe extern "system" fn exception_handler(exception_info: *mut EXCEPTION_POINTERS) -> i32 {
    unsafe {
        let info = &*exception_info;
        let record = &*info.ExceptionRecord;
        let ctx = &mut *info.ContextRecord;

        if record.ExceptionCode == EXCEPTION_SINGLE_STEP {
            // let breakpoint_addr = ctx.Dr0;

            if record.ExceptionAddress as u64 == ctx.Dr0 {
                ctx.Rax = SSN_0 as u64;
                ctx.Rip = STUB_ADDR as u64;
                ctx.Dr0 = 0;
                ctx.Dr7 = set_dr7_bit(ctx.Dr7, 0 << 1, 1, 0);

                return EXCEPTION_CONTINUE_EXECUTION;
            }

            if record.ExceptionAddress as u64 == ctx.Dr1 {
                ctx.Rax = SSN_1 as u64;
                ctx.Rip = STUB_ADDR as u64;
                ctx.Dr1 = 0;
                ctx.Dr7 = set_dr7_bit(ctx.Dr7, 1 << 1, 1, 0);

                return EXCEPTION_CONTINUE_EXECUTION;
            }

            if record.ExceptionAddress as u64 == ctx.Dr2 {
                ctx.Rax = SSN_2 as u64;
                ctx.Rip = STUB_ADDR as u64;
                ctx.Dr2 = 0;
                ctx.Dr7 = set_dr7_bit(ctx.Dr7, 2 << 1, 1, 0);

                return EXCEPTION_CONTINUE_EXECUTION;
            }

            if record.ExceptionAddress as u64 == ctx.Dr3 {
                ctx.Rax = SSN_3 as u64;
                ctx.Rip = STUB_ADDR as u64;
                ctx.Dr3 = 0;
                ctx.Dr7 = set_dr7_bit(ctx.Dr7, 3 << 1, 1, 0);

                return EXCEPTION_CONTINUE_EXECUTION;
            }

        }

        EXCEPTION_CONTINUE_SEARCH
    }

}


pub unsafe fn hwbp_init() -> Result<()> {

    unsafe {

        // Allocate memory for the syscall stub and copy the stub code into it
        let stub_size = SYSCALL_STUB.len();
        // let anticipated_addr * c= std::ptr::null_mut(*c_void);
        let stub_addr = VirtualAlloc(
            std::ptr::null_mut(),
            stub_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );

        if stub_addr.is_null() {
            return Err(anyhow!("[ERROR] Failed to allocate memory for syscall stub."));
        }

        std::ptr::copy_nonoverlapping(SYSCALL_STUB.as_ptr(), stub_addr as *mut u8, stub_size);
        STUB_ADDR = stub_addr as *mut u8;

        debug_println!("[INFO] Syscall stub allocated at: 0x{:X}", STUB_ADDR as usize);

        // Add the vectored exception handler
        let handler = AddVectoredExceptionHandler(1, Some(exception_handler));
        if handler.is_null() {
            return Err(anyhow!("[ERROR] Failed to add vectored exception handler."));
        }

        debug_println!("[INFO] Vectored exception handler added successfully.");

    }


    // Placeholder for any initialization logic if needed in the future
    Ok(())
}

pub unsafe fn hwbp_cleanup() -> Result<()> {
    unsafe {
        // Remove the vectored exception handler
        RemoveVectoredExceptionHandler(exception_handler as *mut c_void);

        debug_println!("[INFO] Vectored exception handler removed successfully.");

        // Free the allocated memory for the syscall stub
        if !STUB_ADDR.is_null() {
            let _ = VirtualFree(STUB_ADDR as *mut _, 0, MEM_RELEASE);
            debug_println!("[INFO] Syscall stub memory freed.");
        }

        SSN_0 = 0;
        SSN_1 = 0;
        SSN_2 = 0;
        SSN_3 = 0;
    }

    Ok(())
}

pub enum DR {
    Dr0,
    Dr1,
    Dr2,
    Dr3,
}

fn set_dr7_bit(current_dr7: u64, start_pos: u32, num_bits: u32, new_value: u64) -> u64 {
    let mask: u64 = if num_bits >= 64 {
        !0u64
    } else {
        (1u64 << num_bits) - 1
    };

    let cleared_dr7 = current_dr7 & !(mask << start_pos);

    cleared_dr7 | ((new_value & mask) << start_pos)
}

unsafe fn set_drbp_register(ctx: &mut CONTEXT, dr: &DR, address: usize) {
    match dr {
        DR::Dr0 => ctx.Dr0 = address as u64,
        DR::Dr1 => ctx.Dr1 = address as u64,
        DR::Dr2 => ctx.Dr2 = address as u64,
        DR::Dr3 => ctx.Dr3 = address as u64,
    }
}

fn dr_to_index(dr: &DR) -> u32 {
    match dr {
        DR::Dr0 => 0,
        DR::Dr1 => 1,
        DR::Dr2 => 2,
        DR::Dr3 => 3,
    }
}

fn dr_to_ssn(dr: &DR, ssn: u32) {
    match dr {
        DR::Dr0 => unsafe { SSN_0 = ssn; },
        DR::Dr1 => unsafe { SSN_1 = ssn; },
        DR::Dr2 => unsafe { SSN_2 = ssn; },
        DR::Dr3 => unsafe { SSN_3 = ssn; },
    }
}


unsafe fn set_dr_with_ssn(dr: &DR, address: *const u8, ssn: u32) -> Result<()> {

    unsafe {


        let mut ctx: CONTEXT = std::mem::zeroed();
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        let status = zw_get_context_thread(
            GetCurrentThread(),
        &mut ctx as *mut CONTEXT,
        ZW_SSN[ZwIndex::ZwGetContextThread as usize].ssn,
        ZW_SSN[ZwIndex::ZwGetContextThread as usize].syscall_ret
        );

        if status != 0 {
            return Err(anyhow!("[ERROR] ZwGetContextThread failed with status: 0x{:X}", status));
        }

        set_drbp_register(&mut ctx, dr, address as usize);

        dr_to_ssn(dr, ssn);

        let dr_index: u32 = dr_to_index(dr);
        ctx.Dr7 = set_dr7_bit(ctx.Dr7, dr_index << 1u8, 1, 1);

        let status = zw_set_context_thread(
            GetCurrentThread(),
            &mut ctx as *mut CONTEXT,
            ZW_SSN[ZwIndex::ZwSetContextThread as usize].ssn,
            ZW_SSN[ZwIndex::ZwSetContextThread as usize].syscall_ret
        );

        if status != 0 {
            return Err(anyhow!("[ERROR] ZwSetContextThread failed with status: 0x{:X}", status));
        }

    }
    

    Ok(())
}


pub unsafe fn set_hwbp(dr: &DR, func_name: &str) -> Result<()> {


    unsafe {

        let obfused_ntdll_dll = obfuse!("ntdll.dll");
        let ntdll_str = obfused_ntdll_dll.as_str();

        let ntdll_ptr = unsafe { get_module_handle(ntdll_str) };
        let parser = PeModuleParser::new(ntdll_ptr);
        let Some(func_addr) = parser.get_func_addr(func_name) else { anyhow::bail!("[ERROR] Failed to find address of NTTE. ")};

        debug_println!("[INFO] Setting hardware breakpoint on {func_name} at address: 0x{:X}", func_addr as usize);

        let bytes = std::slice::from_raw_parts(func_addr as *const u8, 32);

        let mut ssn = 0;
        for i in 0..bytes.len().saturating_sub(4) {
            if bytes[i] == 0xB8 {
                ssn = u32::from_le_bytes([bytes[i + 1], bytes[i + 2], bytes[i + 3], bytes[i + 4]]);
                break;
            }
        }

        if ssn == 0 {
            return Err(anyhow!("[ERROR] Failed to find syscall number for {func_name}"));
        }

        set_dr_with_ssn(dr, func_addr as *const u8, ssn)?;

        debug_println!("[INFO] Hardware breakpoint set successfully on {func_name} (SSN: 0x{:X})", ssn);

    }




    Ok(())
}

pub unsafe fn unset_hwbp(dr: &DR) -> Result<()> {

    unsafe {
        let mut ctx: CONTEXT = std::mem::zeroed();
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        let status = zw_get_context_thread(
            GetCurrentThread(),
            &mut ctx as *mut CONTEXT,
            ZW_SSN[ZwIndex::ZwGetContextThread as usize].ssn,
            ZW_SSN[ZwIndex::ZwGetContextThread as usize].syscall_ret
        );

        if status != 0 {
            return Err(anyhow!("[ERROR] ZGCT failed with status: 0x{:X}", status));
        }

        set_drbp_register(&mut ctx, dr, 0);

        let dr_index: u32 = dr_to_index(dr);
        ctx.Dr7 = set_dr7_bit(ctx.Dr7, dr_index << 1u8, 1, 0);

        let status = zw_set_context_thread(
            GetCurrentThread(),
            &mut ctx as *mut CONTEXT,
            ZW_SSN[ZwIndex::ZwSetContextThread as usize].ssn,
            ZW_SSN[ZwIndex::ZwSetContextThread as usize].syscall_ret
        );

        if status != 0 {
            return Err(anyhow!("[ERROR] ZSCT failed with status: 0x{:X}", status));
        }

    }

    debug_println!("[INFO] hwbp on DR{} unset successfully.", dr_to_index(dr));

    Ok(())

}
