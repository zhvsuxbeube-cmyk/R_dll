/*
 * Copyright 2014 Stas'M Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Rust port of rdpwrap.dll (src-x86-x64-Fusix variant)
 *
 * This file corresponds to:
 *   - dllmain.cpp     (DllMain entry point)
 *   - RDPWrap.cpp     (all logic)
 *   - Export.def      (ServiceMain + SvchostPushServiceGlobals exports)
 */

#![no_std]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(clippy::missing_safety_doc)]

// We pull in the alloc crate so we can use Vec/String without std.
// (panic = "abort" in Cargo.toml means we never need an unwinder.)
extern crate alloc;

// The winapi crate pulls in its own core/alloc, so we do not need std.
use alloc::vec;
use alloc::vec::Vec;
use alloc::string::{String, ToString};
use alloc::format;

use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};

use winapi::shared::minwindef::{BOOL, DWORD, HMODULE, LPVOID, TRUE};
use winapi::shared::winerror::S_OK;
use winapi::um::libloaderapi::{
    GetModuleFileNameW, GetModuleHandleExW, GetProcAddress, LoadLibraryW,
    FindResourceW, LoadResource, LockResource, SizeofResource,
};
use winapi::um::fileapi::{CreateFileW, SetFilePointer, WriteFile, OPEN_ALWAYS};
use winapi::um::winbase::FILE_END;
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::memoryapi::{ReadProcessMemory, WriteProcessMemory};
use winapi::um::processthreadsapi::{GetCurrentProcess, GetCurrentProcessId, GetCurrentThreadId, OpenThread};
use winapi::um::tlhelp32::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use winapi::um::winnt::{
    FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE,
    GENERIC_WRITE, THREAD_SUSPEND_RESUME,
};
use winapi::um::processthreadsapi::{ResumeThread, SuspendThread};
use winapi::um::libloaderapi::GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS;

use winapi::shared::ntdef::{LPCWSTR, PCWSTR, PVOID};

mod ini_file;
use ini_file::IniFile;

// ---------------------------------------------------------------------------
// Platform-width integer — mirrors `PLATFORM_DWORD` in the C++ code.
// usize is 4 bytes on x86, 8 bytes on x86_64.
// ---------------------------------------------------------------------------
type PlatformDword = usize;

// ---------------------------------------------------------------------------
// FARJMP — machine-code trampolines for hooking
//
//  x64:  48 B8 <ptr64> 50 C3   (mov rax, ptr; push rax; ret)
//  x86:  68 <ptr32> C3          (push ptr; ret)
// ---------------------------------------------------------------------------
#[repr(C, packed)]
#[derive(Copy, Clone)]
struct FarJmpX64 {
    mov_op: u8,       // 0x48
    mov_reg_arg: u8,  // 0xB8
    mov_arg: u64,     // target address
    push_rax_op: u8,  // 0x50
    ret_op: u8,       // 0xC3
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
struct FarJmpX86 {
    push_op: u8,  // 0x68
    push_arg: u32, // target address
    ret_op: u8,   // 0xC3
}

// We use a tagged union to hold either variant and always pass by raw bytes.
#[derive(Copy, Clone)]
enum FarJmp {
    X64(FarJmpX64),
    X86(FarJmpX86),
}

impl FarJmp {
    fn as_bytes(&self) -> &[u8] {
        match self {
            FarJmp::X64(j) => unsafe {
                core::slice::from_raw_parts(j as *const FarJmpX64 as *const u8, core::mem::size_of::<FarJmpX64>())
            },
            FarJmp::X86(j) => unsafe {
                core::slice::from_raw_parts(j as *const FarJmpX86 as *const u8, core::mem::size_of::<FarJmpX86>())
            },
        }
    }
    fn size(&self) -> usize {
        match self {
            FarJmp::X64(_) => core::mem::size_of::<FarJmpX64>(),
            FarJmp::X86(_) => core::mem::size_of::<FarJmpX86>(),
        }
    }
}

#[cfg(target_arch = "x86_64")]
fn make_stub(target: PlatformDword) -> FarJmp {
    FarJmp::X64(FarJmpX64 {
        mov_op: 0x48,
        mov_reg_arg: 0xB8,
        mov_arg: target as u64,
        push_rax_op: 0x50,
        ret_op: 0xC3,
    })
}

#[cfg(target_arch = "x86")]
fn make_stub(target: PlatformDword) -> FarJmp {
    FarJmp::X86(FarJmpX86 {
        push_op: 0x68,
        push_arg: target as u32,
        ret_op: 0xC3,
    })
}

fn farjmp_size() -> usize {
    #[cfg(target_arch = "x86_64")]
    { core::mem::size_of::<FarJmpX64>() }
    #[cfg(target_arch = "x86")]
    { core::mem::size_of::<FarJmpX86>() }
}

// ---------------------------------------------------------------------------
// FILE_VERSION — mirrors the C++ FILE_VERSION struct
// ---------------------------------------------------------------------------
#[derive(Default, Copy, Clone)]
struct FileVersion {
    major: u16,
    minor: u16,
    release: u16,
    build: u16,
}

// ---------------------------------------------------------------------------
// Function-pointer types — mirrors typedefs in stdafx.h
// ---------------------------------------------------------------------------
type ServiceMainFn        = unsafe extern "system" fn(dw_argc: DWORD, lpsz_argv: *mut *mut u16);
type SvchostPushFn        = unsafe extern "system" fn(lp_global_data: PVOID);
type SlGetInfoFn          = unsafe extern "system" fn(pwsz: PCWSTR, pdw: *mut DWORD) -> i32;

// ---------------------------------------------------------------------------
// Global state — all wrapped in UnsafeCell / AtomicBool because we live
// inside a DLL that svchost loads, single-initialised by ServiceMain or
// SvchostPushServiceGlobals.
// ---------------------------------------------------------------------------

static ALREADY_HOOKED: AtomicBool = AtomicBool::new(false);

/// All mutable globals are kept in a single struct behind a raw pointer so
/// we can use them from `unsafe` blocks exactly as the C++ code does with
/// global variables.  The struct is heap-allocated once during `hook()`.
struct Globals {
    ini_file: Option<IniFile>,
    log_file: [u16; 256],       // wide-char path, NUL-terminated
    h_termsrv: HMODULE,
    h_slc: HMODULE,
    termsrv_base: PlatformDword,
    fv: FileVersion,
    service_main: Option<ServiceMainFn>,
    svchost_push: Option<SvchostPushFn>,
    sl_get_info: Option<SlGetInfoFn>,
    /// The original bytes at the SLGetWindowsInformationDWORD entry point
    /// (saved so we can temporarily restore them in New_SLGetWindowsInformationDWORD).
    old_sl_bytes: Vec<u8>,
    /// The stub FARJMP that redirects SLGetWindowsInformationDWORD to our hook.
    stub_sl: Option<FarJmp>,
}

// SAFETY: rdpwrap.dll is loaded and used by svchost in a single-threaded
// initialisation path.  After hook() returns the globals are never mutated
// again (only read), so Send+Sync is safe for our purposes.
unsafe impl Send for Globals {}
unsafe impl Sync for Globals {}

static mut GLOBALS_PTR: *mut Globals = ptr::null_mut();

fn globals() -> &'static mut Globals {
    // SAFETY: always non-null after first use; the DLL is loaded before any
    // call reaches here.
    unsafe { &mut *GLOBALS_PTR }
}

// ---------------------------------------------------------------------------
// Logging — mirrors WriteToLog(LPSTR)
// ---------------------------------------------------------------------------

fn write_to_log(text: &str) {
    let g = globals();
    let log_path = &g.log_file;
    // Find NUL terminator
    let end = log_path.iter().position(|&c| c == 0).unwrap_or(256);
    if end == 0 {
        return;
    }

    let bytes = text.as_bytes();
    let mut written: DWORD = 0;
    unsafe {
        let h = CreateFileW(
            log_path.as_ptr(),
            GENERIC_WRITE,
            FILE_SHARE_WRITE | FILE_SHARE_READ,
            ptr::null_mut(),
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        );
        if h == INVALID_HANDLE_VALUE {
            return;
        }
        SetFilePointer(h, 0, ptr::null_mut(), FILE_END);
        WriteFile(
            h,
            bytes.as_ptr() as *const _,
            bytes.len() as DWORD,
            &mut written,
            ptr::null_mut(),
        );
        CloseHandle(h);
    }
}

// ---------------------------------------------------------------------------
// GetCurrentModule — mirrors GetCurrentModule() in C++
// ---------------------------------------------------------------------------
fn get_current_module() -> HMODULE {
    let mut hmod: HMODULE = ptr::null_mut();
    unsafe {
        let ok = GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
            get_current_module as *const () as LPCWSTR,
            &mut hmod,
        );
        if ok == 0 {
            return ptr::null_mut();
        }
    }
    hmod
}

// ---------------------------------------------------------------------------
// GetModuleCodeSectionInfo — mirrors GetModuleCodeSectionInfo in C++
// Returns (base_addr, code_size) or None on failure.
// ---------------------------------------------------------------------------
fn get_module_code_section_info(hmodule: HMODULE) -> Option<(PlatformDword, PlatformDword)> {
    if hmodule.is_null() {
        return None;
    }
    // The PE header layout:
    //   [DOS_HEADER] [... e_lfanew ...] ["PE\0\0"] [FILE_HEADER] [OPTIONAL_HEADER]
    let base = hmodule as usize;
    unsafe {
        let dos = base as *const u8;
        // e_lfanew is at offset 0x3C
        let e_lfanew = *(dos.add(0x3C) as *const u32) as usize;
        // Skip "PE\0\0" (4 bytes) + IMAGE_FILE_HEADER (20 bytes) = 24 bytes to OPTIONAL_HEADER
        let opt_header = dos.add(e_lfanew + 4 + 20);
        // SizeOfCode is at offset 4 in IMAGE_OPTIONAL_HEADER
        let size_of_code = *(opt_header.add(4) as *const u32) as PlatformDword;
        if size_of_code == 0 {
            return None;
        }
        Some((base, size_of_code))
    }
}

// ---------------------------------------------------------------------------
// SetThreadsState — mirrors SetThreadsState(bool Resume) in C++
// ---------------------------------------------------------------------------
fn set_threads_state(resume: bool) {
    let curr_thread = unsafe { GetCurrentThreadId() };
    let curr_proc   = unsafe { GetCurrentProcessId() };

    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snap == INVALID_HANDLE_VALUE {
        return;
    }

    let mut entry = THREADENTRY32 {
        dwSize: core::mem::size_of::<THREADENTRY32>() as DWORD,
        cntUsage: 0,
        th32ThreadID: 0,
        th32OwnerProcessID: 0,
        tpBasePri: 0,
        tpDeltaPri: 0,
        dwFlags: 0,
    };

    if unsafe { Thread32First(snap, &mut entry) } == 0 {
        unsafe { CloseHandle(snap) };
        return;
    }

    loop {
        if entry.th32ThreadID != curr_thread && entry.th32OwnerProcessID == curr_proc {
            let hthread = unsafe {
                OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID)
            };
            if !hthread.is_null() {
                unsafe {
                    if resume {
                        ResumeThread(hthread);
                    } else {
                        SuspendThread(hthread);
                    }
                    CloseHandle(hthread);
                }
            }
        }
        if unsafe { Thread32Next(snap, &mut entry) } == 0 {
            break;
        }
    }
    unsafe { CloseHandle(snap) };
}

// ---------------------------------------------------------------------------
// GetModuleVersion — mirrors GetModuleVersion in C++ (reads VS_VERSIONINFO
// from a loaded module's resource section).
// ---------------------------------------------------------------------------
fn get_module_version(module_name: &[u16]) -> Option<FileVersion> {
    unsafe {
        let hmod = {
            let mut tmp = module_name.to_vec();
            if tmp.last().copied() != Some(0) { tmp.push(0); }
            winapi::um::libloaderapi::GetModuleHandleW(tmp.as_ptr())
        };
        if hmod.is_null() {
            return None;
        }
        read_version_from_module(hmod)
    }
}

/// Shared helper — read the embedded VS_FIXEDFILEINFO out of a module handle.
unsafe fn read_version_from_module(hmod: HMODULE) -> Option<FileVersion> {
    // RT_VERSION = 0x10, resource id = 1
    let hri = FindResourceW(hmod, 1usize as LPCWSTR, 0x10usize as LPCWSTR);
    if hri.is_null() {
        return None;
    }
    let res = LoadResource(hmod, hri);
    if res.is_null() {
        return None;
    }
    let resource_size = SizeofResource(hmod, hri) as usize;
    if resource_size < 56 {
        return None;
    }
    let base = LockResource(res) as *const u8;
    if base.is_null() {
        return None;
    }
    // VS_VERSIONINFO layout (little-endian Windows):
    //   WORD  wLength        +0
    //   WORD  wValueLength   +2
    //   WORD  wType          +4
    //   WCHAR szKey[16]      +6  (32 bytes)
    //   WORD  Padding1       +38
    //   VS_FIXEDFILEINFO     +40
    //     dwSignature        +40
    //     dwStrucVersion     +44
    //     dwFileVersionMS    +48
    //     dwFileVersionLS    +52
    let ms = *(base.add(48) as *const u32);
    let ls = *(base.add(52) as *const u32);
    Some(FileVersion {
        major:   (ms >> 16) as u16,
        minor:   (ms & 0xFFFF) as u16,
        release: (ls >> 16) as u16,
        build:   (ls & 0xFFFF) as u16,
    })
}

// ---------------------------------------------------------------------------
// INI helpers — mirrors INIReadDWordHex and INIReadString
// ---------------------------------------------------------------------------

fn ini_read_dword_hex(section: &str, name: &str, default: PlatformDword) -> PlatformDword {
    let g = globals();
    if let Some(ref ini) = g.ini_file {
        if let Some(var) = ini.get_dword(section, name) {
            return var.value_hex as PlatformDword;
        }
    }
    default
}

fn ini_read_string(section: &str, name: &str, default: &str) -> String {
    let g = globals();
    if let Some(ref ini) = g.ini_file {
        if let Some(var) = ini.get_string(section, name) {
            return var.value;
        }
    }
    default.to_string()
}

// ---------------------------------------------------------------------------
// OverrideSL — mirrors OverrideSL in C++
// ---------------------------------------------------------------------------
fn override_sl(value_name: &[u16]) -> Option<DWORD> {
    let name = IniFile::wide_to_string(value_name);
    let g = globals();
    if let Some(ref ini) = g.ini_file {
        if ini.variable_exists("SLPolicy", &name) {
            let dw = ini.get_dword("SLPolicy", &name)
                .map(|v| v.value_dec as DWORD)
                .unwrap_or(0);
            return Some(dw);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// New_SLGetWindowsInformationDWORD
// Mirrors HRESULT WINAPI New_SLGetWindowsInformationDWORD(…) in C++
//
// This is the hook that replaces SLGetWindowsInformationDWORD in slc.dll
// for Vista / Windows 7.
// ---------------------------------------------------------------------------
unsafe extern "system" fn new_sl_get_windows_information_dword(
    pwsz_value_name: PCWSTR,
    pd_value: *mut DWORD,
) -> i32 {
    // Build a wide slice for the value name so we can convert it
    let mut len = 0usize;
    while *pwsz_value_name.add(len) != 0 { len += 1; }
    let name_slice = core::slice::from_raw_parts(pwsz_value_name, len);

    // Log the query
    {
        let name_str = String::from_utf16_lossy(name_slice);
        let msg = format!("Policy query: {}\r\n", name_str);
        write_to_log(&msg);
    }

    // Check if we should override this policy value
    if let Some(dw) = override_sl(name_slice) {
        *pd_value = dw;
        let msg = format!("Policy rewrite: {}\r\n", dw);
        write_to_log(&msg);
        return S_OK;
    }

    // Temporarily restore the original bytes, call through, then re-hook.
    let g = globals();
    let sl_fn_ptr = g.sl_get_info.expect("SLGetWindowsInformationDWORD not loaded");
    let target_addr = sl_fn_ptr as *mut u8;

    // Restore original bytes
    let mut bw: usize = 0;
    if !g.old_sl_bytes.is_empty() {
        WriteProcessMemory(
            GetCurrentProcess(),
            target_addr as LPVOID,
            g.old_sl_bytes.as_ptr() as *const _,
            g.old_sl_bytes.len(),
            &mut bw,
        );
    }

    // Call the real function
    let result = sl_fn_ptr(pwsz_value_name, pd_value);

    if result == S_OK {
        let msg = format!("Policy result: {}\r\n", *pd_value);
        write_to_log(&msg);
    } else {
        write_to_log("Policy request failed\r\n");
    }

    // Re-install our stub
    if let Some(stub) = g.stub_sl {
        let bytes = stub.as_bytes();
        WriteProcessMemory(
            GetCurrentProcess(),
            target_addr as LPVOID,
            bytes.as_ptr() as *const _,
            bytes.len(),
            &mut bw,
        );
    }

    result
}

// ---------------------------------------------------------------------------
// New_Win8SL
// Mirrors HRESULT __fastcall New_Win8SL(…) in C++
//
// Used on Windows 8+ where SLGetWindowsInformationDWORDWrapper is an
// unexported internal function in termsrv.dll.  Because Rust does not have
// __fastcall on x64 (the ABI unifies them), we use "C" which is correct
// for x64.  On x86 we must use fastcall.
// ---------------------------------------------------------------------------
#[cfg(target_arch = "x86_64")]
unsafe extern "C" fn new_win8_sl(pwsz_value_name: PCWSTR, pd_value: *mut DWORD) -> i32 {
    new_win8_sl_impl(pwsz_value_name, pd_value)
}

#[cfg(target_arch = "x86")]
unsafe extern "fastcall" fn new_win8_sl(pwsz_value_name: PCWSTR, pd_value: *mut DWORD) -> i32 {
    new_win8_sl_impl(pwsz_value_name, pd_value)
}

unsafe fn new_win8_sl_impl(pwsz_value_name: PCWSTR, pd_value: *mut DWORD) -> i32 {
    let mut len = 0usize;
    while *pwsz_value_name.add(len) != 0 { len += 1; }
    let name_slice = core::slice::from_raw_parts(pwsz_value_name, len);
    let name_str = String::from_utf16_lossy(name_slice);

    let msg = format!("Policy query: {}\r\n", name_str);
    write_to_log(&msg);

    if let Some(dw) = override_sl(name_slice) {
        *pd_value = dw;
        let msg = format!("Policy rewrite: {}\r\n", dw);
        write_to_log(&msg);
        return S_OK;
    }

    let g = globals();
    if let Some(sl_fn) = g.sl_get_info {
        let result = sl_fn(pwsz_value_name, pd_value);
        if result == S_OK {
            let msg = format!("Policy result: {}\r\n", *pd_value);
            write_to_log(&msg);
        } else {
            write_to_log("Policy request failed\r\n");
        }
        return result;
    }
    winapi::shared::winerror::E_FAIL
}

// ---------------------------------------------------------------------------
// New_Win8SL_CP — x86-only Consumer Preview variant
// Mirrors HRESULT __fastcall New_Win8SL_CP(DWORD, DWORD*, PWSTR, DWORD)
// The calling convention has pwszValueName in the third argument slot.
// ---------------------------------------------------------------------------
#[cfg(target_arch = "x86")]
unsafe extern "fastcall" fn new_win8_sl_cp(
    _arg1: DWORD,
    pd_value: *mut DWORD,
    pwsz_value_name: PCWSTR,
    _arg4: DWORD,
) -> i32 {
    new_win8_sl_impl(pwsz_value_name, pd_value)
}

// ---------------------------------------------------------------------------
// New_CSLQuery_Initialize
// Mirrors HRESULT WINAPI New_CSLQuery_Initialize() in C++
// ---------------------------------------------------------------------------
unsafe extern "system" fn new_csl_query_initialize() -> i32 {
    write_to_log(">>> CSLQuery::Initialize\r\n");

    let g = globals();
    let fv = g.fv;
    let termsrv_base = g.termsrv_base;

    let sect = format!(
        "{}.{}.{}.{}-SLInit",
        fv.major, fv.minor, fv.release, fv.build
    );

    let ini_opt: Option<&IniFile> = g.ini_file.as_ref();

    if let Some(ini) = ini_opt {
        if ini.section_exists(&sect) {
            #[cfg(target_arch = "x86_64")]
            let suffix = "x64";
            #[cfg(target_arch = "x86")]
            let suffix = "x86";

            macro_rules! read_ptr {
                ($key:expr) => {{
                    let full_key = format!("{}.{}", $key, suffix);
                    let offset = ini_read_dword_hex(&sect, &full_key, 0);
                    if offset != 0 {
                        termsrv_base.checked_add(offset).map(|addr| addr as *mut DWORD)
                    } else {
                        None
                    }
                }};
            }

            let b_server_sku        = read_ptr!("bServerSku");
            let b_remote_conn       = read_ptr!("bRemoteConnAllowed");
            let b_fus_enabled       = read_ptr!("bFUSEnabled");
            let b_app_server        = read_ptr!("bAppServerAllowed");
            let b_multimon          = read_ptr!("bMultimonAllowed");
            let l_max_user          = read_ptr!("lMaxUserSessions");
            let ul_max_debug        = read_ptr!("ulMaxDebugSessions");
            let b_initialized       = read_ptr!("bInitialized");

            macro_rules! apply {
                ($ptr_opt:expr, $sl_key:expr, $default:expr) => {
                    if let Some(ptr) = $ptr_opt {
                        let val = ini_read_dword_hex("SLInit", $sl_key, $default) as DWORD;
                        *ptr = val;
                        let msg = format!(
                            "SLInit [0x{:p}] {} = {}\r\n",
                            ptr as *const (), $sl_key, val
                        );
                        write_to_log(&msg);
                    }
                };
            }

            apply!(b_server_sku,  "bServerSku",         1);
            apply!(b_remote_conn, "bRemoteConnAllowed",  1);
            apply!(b_fus_enabled, "bFUSEnabled",         1);
            apply!(b_app_server,  "bAppServerAllowed",   1);
            apply!(b_multimon,    "bMultimonAllowed",    1);
            apply!(l_max_user,    "lMaxUserSessions",    0);
            apply!(ul_max_debug,  "ulMaxDebugSessions",  0);
            apply!(b_initialized, "bInitialized",        1);
        }
    }

    write_to_log("<<< CSLQuery::Initialize\r\n");
    S_OK
}

// ---------------------------------------------------------------------------
// Helper: write a FARJMP trampoline into an address inside the target process
// ---------------------------------------------------------------------------
unsafe fn write_jump(target: *mut u8, jump: &FarJmp) {
    let mut bw: usize = 0;
    WriteProcessMemory(
        GetCurrentProcess(),
        target as LPVOID,
        jump.as_bytes().as_ptr() as *const _,
        jump.size(),
        &mut bw,
    );
}

// ---------------------------------------------------------------------------
// hook() — the big initialisation function; mirrors Hook() in C++
// ---------------------------------------------------------------------------
unsafe fn hook() {
    ALREADY_HOOKED.store(true, Ordering::SeqCst);

    // ---- build the log file path (DLL dir + "rdpwrap.txt") ----------------
    let mut log_file = [0u16; 256];
    let hmod_self = get_current_module();
    GetModuleFileNameW(hmod_self, log_file.as_mut_ptr(), 255);
    // Find last backslash and replace the filename portion
    let last_bs = log_file.iter().rposition(|&c| c == b'\\' as u16).unwrap_or(0);
    let suffix: Vec<u16> = "rdpwrap.txt\0".encode_utf16().collect();
    let mut i = last_bs + 1;
    for &w in &suffix {
        if i < 256 { log_file[i] = w; i += 1; }
    }
    // Zero-fill the rest
    for j in i..256 { log_file[j] = 0; }

    // ---- find the INI config file (DLL dir + "rdpwrap.ini") ---------------
    let mut config_file = [0u16; 256];
    GetModuleFileNameW(hmod_self, config_file.as_mut_ptr(), 255);
    let last_bs2 = config_file.iter().rposition(|&c| c == b'\\' as u16).unwrap_or(0);
    let ini_suffix: Vec<u16> = "rdpwrap.ini\0".encode_utf16().collect();
    let mut i2 = last_bs2 + 1;
    for &w in &ini_suffix {
        if i2 < 256 { config_file[i2] = w; i2 += 1; }
    }
    for j in i2..256 { config_file[j] = 0; }

    // ---- allocate the global state struct ---------------------------------
    let g_box = alloc::boxed::Box::new(Globals {
        ini_file: None,
        log_file,
        h_termsrv: ptr::null_mut(),
        h_slc: ptr::null_mut(),
        termsrv_base: 0,
        fv: FileVersion::default(),
        service_main: None,
        svchost_push: None,
        sl_get_info: None,
        old_sl_bytes: Vec::new(),
        stub_sl: None,
    });
    GLOBALS_PTR = alloc::boxed::Box::into_raw(g_box);

    write_to_log("Loading configuration...\r\n");

    {
        let msg = format!("Configuration file: {}\r\n", String::from_utf16_lossy(&config_file));
        write_to_log(&msg);
    }

    // Open INI
    let ini = IniFile::open(&config_file);
    globals().ini_file = ini;

    // Optionally override log path from INI
    if let Some(ref ini) = globals().ini_file {
        if let Some(var) = ini.get_string("Main", "LogFile") {
            // Convert ASCII value to wide and store
            let wide: Vec<u16> = var.value.encode_utf16().collect();
            let n = wide.len().min(255);
            globals().log_file.fill(0);
            globals().log_file[..n].copy_from_slice(&wide[..n]);
            globals().log_file[n] = 0;
        }
    }

    write_to_log("Initializing RDP Wrapper...\r\n");

    // ---- Load termsrv.dll -------------------------------------------------
    let termsrv_name: Vec<u16> = "termsrv.dll\0".encode_utf16().collect();
    let h_termsrv = LoadLibraryW(termsrv_name.as_ptr());
    if h_termsrv.is_null() {
        write_to_log("Error: Failed to load Terminal Services library\r\n");
        return;
    }
    globals().h_termsrv = h_termsrv;

    // Resolve exported functions
    let svc_main_name = b"ServiceMain\0";
    let push_name     = b"SvchostPushServiceGlobals\0";
    let svc_main_fn   = GetProcAddress(h_termsrv, svc_main_name.as_ptr() as *const i8);
    let push_fn       = GetProcAddress(h_termsrv, push_name.as_ptr() as *const i8);

    if !svc_main_fn.is_null() {
        globals().service_main = Some(core::mem::transmute(svc_main_fn));
    }
    if !push_fn.is_null() {
        globals().svchost_push = Some(core::mem::transmute(push_fn));
    }

    {
        let msg = format!(
            "Base addr:  0x{:p}\r\nSvcMain:    termsrv.dll+0x{:x}\r\nSvcGlobals: termsrv.dll+0x{:x}\r\n",
            h_termsrv,
            svc_main_fn as usize - h_termsrv as usize,
            push_fn as usize - h_termsrv as usize,
        );
        write_to_log(&msg);
    }

    // ---- Detect termsrv.dll version ---------------------------------------
    let termsrv_wide: Vec<u16> = "termsrv.dll\0".encode_utf16().collect();
    let fv = match get_module_version(&termsrv_wide) {
        Some(v) => v,
        None => {
            write_to_log("Error: Failed to detect Terminal Services version\r\n");
            return;
        }
    };
    globals().fv = fv;

    let ver: u16 = (fv.minor as u16) | ((fv.major as u16) << 8);
    if ver == 0 {
        write_to_log("Error: Failed to detect Terminal Services version\r\n");
        return;
    }

    {
        let msg = format!(
            "Version:    {}.{}.{}.{}\r\n",
            fv.major, fv.minor, fv.release, fv.build
        );
        write_to_log(&msg);
    }

    // ---- Freeze all threads -----------------------------------------------
    write_to_log("Freezing threads...\r\n");
    set_threads_state(false);

    // ---- Windows Vista (0x0600) SL hook -----------------------------------
    let hook_nt60 = globals().ini_file.as_ref()
        .and_then(|i| i.get_bool("Main", "SLPolicyHookNT60"))
        .unwrap_or(true);

    if ver == 0x0600 && hook_nt60 {
        install_sl_hook();
    }

    // ---- Windows 7 (0x0601) SL hook ---------------------------------------
    let hook_nt61 = globals().ini_file.as_ref()
        .and_then(|i| i.get_bool("Main", "SLPolicyHookNT61"))
        .unwrap_or(true);

    if ver == 0x0601 && hook_nt61 {
        install_sl_hook();
    }

    // Windows 8 (0x0602) — load slc.dll but don't hook the exported fn
    if ver == 0x0602 {
        let slc_wide: Vec<u16> = "slc.dll\0".encode_utf16().collect();
        let h_slc = LoadLibraryW(slc_wide.as_ptr());
        globals().h_slc = h_slc;
        let sl_name = b"SLGetWindowsInformationDWORD\0";
        let sl_fn = GetProcAddress(h_slc, sl_name.as_ptr() as *const i8);
        if !sl_fn.is_null() {
            globals().sl_get_info = Some(core::mem::transmute(sl_fn));
        }
    }
    // Windows 8.1 (0x0603) and Windows 10 (0x0604) use inline SL policy code.

    // ---- Per-version patch section ----------------------------------------
    let sect_name = format!("{}.{}.{}.{}", fv.major, fv.minor, fv.release, fv.build);

    let section_present = globals().ini_file.as_ref()
        .map(|i| i.section_exists(&sect_name))
        .unwrap_or(false);

    if section_present {
        if let Some((ts_base, _ts_size)) = get_module_code_section_info(h_termsrv) {
            globals().termsrv_base = ts_base;

            #[cfg(target_arch = "x86_64")]
            let arch = "x64";
            #[cfg(target_arch = "x86")]
            let arch = "x86";

            apply_binary_patch(&sect_name, arch, ts_base);
        }
    }

    // ---- Resume all threads -----------------------------------------------
    write_to_log("Resuming threads...\r\n"); // Note: original had typo "Resumimg"
    set_threads_state(true);
}

// ---------------------------------------------------------------------------
// install_sl_hook — shared logic for Vista / Win7 SL hook
// ---------------------------------------------------------------------------
unsafe fn install_sl_hook() {
    let slc_wide: Vec<u16> = "slc.dll\0".encode_utf16().collect();
    let h_slc = LoadLibraryW(slc_wide.as_ptr());
    if h_slc.is_null() {
        return;
    }
    globals().h_slc = h_slc;

    let sl_name = b"SLGetWindowsInformationDWORD\0";
    let sl_fn_raw = GetProcAddress(h_slc, sl_name.as_ptr() as *const i8);
    if sl_fn_raw.is_null() {
        return;
    }

    let sl_fn: SlGetInfoFn = core::mem::transmute(sl_fn_raw);
    globals().sl_get_info = Some(sl_fn);

    write_to_log("Hook SLGetWindowsInformationDWORD\r\n");

    let stub = make_stub(new_sl_get_windows_information_dword as PlatformDword);
    let fn_ptr = sl_fn_raw as *mut u8;
    let stub_size = farjmp_size();

    // Save the original bytes
    let mut old_bytes = vec![0u8; stub_size];
    let mut bw: usize = 0;
    let read_ok = ReadProcessMemory(
        GetCurrentProcess(),
        fn_ptr as LPVOID,
        old_bytes.as_mut_ptr() as LPVOID,
        stub_size,
        &mut bw,
    );
    if read_ok == 0 || bw != stub_size {
        write_to_log("Error: Failed to save original SLGetWindowsInformationDWORD bytes\r\n");
        return;
    }
    globals().old_sl_bytes = old_bytes;
    globals().stub_sl = Some(stub);

    // Write the hook
    write_jump(fn_ptr, &stub);
}

// ---------------------------------------------------------------------------
// apply_binary_patch — handles the per-section patching / hooking logic
// that mirrors the large if-block inside Hook() after the per-version checks.
// ---------------------------------------------------------------------------
unsafe fn apply_binary_patch(sect: &str, arch: &str, ts_base: PlatformDword) {
    // ---- LocalOnly patch (CEnforcementCore::GetInstanceOfTSLicense) -------
    {
        let patch_key  = format!("LocalOnlyPatch.{}", arch);
        let offset_key = format!("LocalOnlyOffset.{}", arch);
        let code_key   = format!("LocalOnlyCode.{}", arch);

        let do_patch = globals().ini_file.as_ref()
            .and_then(|i| i.get_bool(sect, &patch_key))
            .unwrap_or(false);

        if do_patch {
            write_to_log("Patch CEnforcementCore::GetInstanceOfTSLicense\r\n");
            let offset = ini_read_dword_hex(sect, &offset_key, 0);
            let patch_name = ini_read_string(sect, &code_key, "");
            if !patch_name.is_empty() {
                if let Some(ref ini) = globals().ini_file {
                    if let Some(ba) = ini.get_bytearray("PatchCodes", &patch_name) {
                        if let Some(sign_ptr) = ts_base.checked_add(offset) {
                            if sign_ptr > ts_base && !ba.value.is_empty() {
                                let mut bw: usize = 0;
                                WriteProcessMemory(
                                    GetCurrentProcess(),
                                    sign_ptr as LPVOID,
                                    ba.value.as_ptr() as *const _,
                                    ba.value.len(),
                                    &mut bw,
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    // ---- SingleUser patch (CSessionArbitrationHelper::IsSingleSessionPerUserEnabled)
    {
        let patch_key  = format!("SingleUserPatch.{}", arch);
        let offset_key = format!("SingleUserOffset.{}", arch);
        let code_key   = format!("SingleUserCode.{}", arch);

        let do_patch = globals().ini_file.as_ref()
            .and_then(|i| i.get_bool(sect, &patch_key))
            .unwrap_or(false);

        if do_patch {
            write_to_log("Patch CSessionArbitrationHelper::IsSingleSessionPerUserEnabled\r\n");
            let offset = ini_read_dword_hex(sect, &offset_key, 0);
            let patch_name = ini_read_string(sect, &code_key, "");
            if !patch_name.is_empty() {
                if let Some(ref ini) = globals().ini_file {
                    if let Some(ba) = ini.get_bytearray("PatchCodes", &patch_name) {
                        if let Some(sign_ptr) = ts_base.checked_add(offset) {
                            if sign_ptr > ts_base && !ba.value.is_empty() {
                                let mut bw: usize = 0;
                                WriteProcessMemory(
                                    GetCurrentProcess(),
                                    sign_ptr as LPVOID,
                                    ba.value.as_ptr() as *const _,
                                    ba.value.len(),
                                    &mut bw,
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    // ---- DefPolicy patch (CDefPolicy::Query) --------------------------------
    {
        let patch_key  = format!("DefPolicyPatch.{}", arch);
        let offset_key = format!("DefPolicyOffset.{}", arch);
        let code_key   = format!("DefPolicyCode.{}", arch);

        let do_patch = globals().ini_file.as_ref()
            .and_then(|i| i.get_bool(sect, &patch_key))
            .unwrap_or(false);

        if do_patch {
            write_to_log("Patch CDefPolicy::Query\r\n");
            let offset = ini_read_dword_hex(sect, &offset_key, 0);
            let patch_name = ini_read_string(sect, &code_key, "");
            if !patch_name.is_empty() {
                if let Some(ref ini) = globals().ini_file {
                    if let Some(ba) = ini.get_bytearray("PatchCodes", &patch_name) {
                        if let Some(sign_ptr) = ts_base.checked_add(offset) {
                            if sign_ptr > ts_base && !ba.value.is_empty() {
                                let mut bw: usize = 0;
                                WriteProcessMemory(
                                    GetCurrentProcess(),
                                    sign_ptr as LPVOID,
                                    ba.value.as_ptr() as *const _,
                                    ba.value.len(),
                                    &mut bw,
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    // ---- SLPolicy internal hook (SLGetWindowsInformationDWORDWrapper) -----
    {
        let flag_key   = format!("SLPolicyInternal.{}", arch);
        let offset_key = format!("SLPolicyOffset.{}", arch);
        let func_key   = format!("SLPolicyFunc.{}", arch);

        let do_hook = globals().ini_file.as_ref()
            .and_then(|i| i.get_bool(sect, &flag_key))
            .unwrap_or(false);

        if do_hook {
            write_to_log("Hook SLGetWindowsInformationDWORDWrapper\r\n");
            let offset = ini_read_dword_hex(sect, &offset_key, 0);
            let func_name = ini_read_string(sect, &func_key, "New_Win8SL");

            // Choose the target function pointer
            #[cfg(target_arch = "x86_64")]
            let target_fn: PlatformDword = {
                // On x64 the only variant is New_Win8SL
                new_win8_sl as PlatformDword
            };
            #[cfg(target_arch = "x86")]
            let target_fn: PlatformDword = {
                if func_name == "New_Win8SL_CP" {
                    new_win8_sl_cp as PlatformDword
                } else {
                    new_win8_sl as PlatformDword
                }
            };
            let _ = func_name; // suppress unused-variable on x64

            let jump = make_stub(target_fn);
            if let Some(sign_ptr) = ts_base.checked_add(offset) {
                if sign_ptr > ts_base {
                    write_jump(sign_ptr as *mut u8, &jump);
                }
            }
        }
    }

    // ---- SLInit hook (CSLQuery::Initialize) --------------------------------
    {
        let flag_key   = format!("SLInitHook.{}", arch);
        let offset_key = format!("SLInitOffset.{}", arch);
        let func_key   = format!("SLInitFunc.{}", arch);

        let do_hook = globals().ini_file.as_ref()
            .and_then(|i| i.get_bool(sect, &flag_key))
            .unwrap_or(false);

        if do_hook {
            write_to_log("Hook CSLQuery::Initialize\r\n");
            let offset = ini_read_dword_hex(sect, &offset_key, 0);
            let _func_name = ini_read_string(sect, &func_key, "New_CSLQuery_Initialize");
            // Only one function is ever used here
            let jump = make_stub(new_csl_query_initialize as PlatformDword);
            if let Some(sign_ptr) = ts_base.checked_add(offset) {
                if sign_ptr > ts_base {
                    write_jump(sign_ptr as *mut u8, &jump);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Exported functions — match Export.def exactly:
//   ServiceMain
//   SvchostPushServiceGlobals
// ---------------------------------------------------------------------------

/// Mirrors: void WINAPI ServiceMain(DWORD dwArgc, LPTSTR *lpszArgv)
#[no_mangle]
pub unsafe extern "system" fn ServiceMain(dw_argc: DWORD, lpsz_argv: *mut *mut u16) {
    write_to_log(">>> ServiceMain\r\n");

    if !ALREADY_HOOKED.load(Ordering::SeqCst) {
        hook();
    }

    if let Some(f) = globals().service_main {
        f(dw_argc, lpsz_argv);
    }

    write_to_log("<<< ServiceMain\r\n");
}

/// Mirrors: void WINAPI SvchostPushServiceGlobals(void *lpGlobalData)
#[no_mangle]
pub unsafe extern "system" fn SvchostPushServiceGlobals(lp_global_data: PVOID) {
    write_to_log(">>> SvchostPushServiceGlobals\r\n");

    if !ALREADY_HOOKED.load(Ordering::SeqCst) {
        hook();
    }

    if let Some(f) = globals().svchost_push {
        f(lp_global_data);
    }

    write_to_log("<<< SvchostPushServiceGlobals\r\n");
}

// ---------------------------------------------------------------------------
// DllMain — mirrors dllmain.cpp (simply returns TRUE)
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "system" fn DllMain(
    _h_module: HMODULE,
    _ul_reason: DWORD,
    _lp_reserved: LPVOID,
) -> BOOL {
    TRUE
}

// ---------------------------------------------------------------------------
// Panic handler — required when #![no_std] + panic = "abort"
// (no unwinding; any panic aborts the process)
// ---------------------------------------------------------------------------
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // We configured panic = "abort" in Cargo.toml so the linker will
    // replace this with an abort intrinsic.  This body is unreachable
    // but required to satisfy the compiler.
    loop {}
}

// ---------------------------------------------------------------------------
// Allocator — we use the system allocator (HeapAlloc/HeapFree via winapi).
// ---------------------------------------------------------------------------
use core::alloc::{GlobalAlloc, Layout};

struct WindowsAllocator;

unsafe impl GlobalAlloc for WindowsAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        use winapi::um::heapapi::{GetProcessHeap, HeapAlloc};
        use winapi::um::winnt::HEAP_ZERO_MEMORY;
        HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, layout.size()) as *mut u8
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        use winapi::um::heapapi::{GetProcessHeap, HeapFree};
        HeapFree(GetProcessHeap(), 0, ptr as LPVOID);
    }

    unsafe fn realloc(&self, ptr: *mut u8, _layout: Layout, new_size: usize) -> *mut u8 {
        use winapi::um::heapapi::{GetProcessHeap, HeapReAlloc};
        HeapReAlloc(GetProcessHeap(), 0, ptr as LPVOID, new_size) as *mut u8
    }
}

#[global_allocator]
static ALLOCATOR: WindowsAllocator = WindowsAllocator;
