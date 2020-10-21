use registry::Hive;
use winapi::{shared::ntdef::LUID, um::{processthreadsapi::OpenProcessToken, securitybaseapi::AdjustTokenPrivileges, winbase::LookupPrivilegeValueW, winnt::LUID_AND_ATTRIBUTES, winnt::{HANDLE, SE_BACKUP_NAME, SE_PRIVILEGE_ENABLED, SE_RESTORE_NAME, TOKEN_PRIVILEGES}}};
use winapi::um::processthreadsapi::GetCurrentProcess;
use winapi::um::winnt::TOKEN_ADJUST_PRIVILEGES;
use std::convert::TryInto;
use utfx::U16CString;
fn main() -> Result<(), std::io::Error> {
    let mut token = std::ptr::null_mut();
    let r = unsafe {OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &mut token) };
    if r == 0 {
        return Err(std::io::Error::last_os_error());
    }

    set_privilege(token, SE_RESTORE_NAME)?;
    set_privilege(token, SE_BACKUP_NAME)?;
    Hive::LocalMachine.load("example", r"C:\Users\Default\NTUSER.DAT").unwrap();
    Ok(())
}

fn set_privilege(handle: HANDLE, name: &str) -> Result<(), std::io::Error> {
    let mut luid: LUID = LUID {
        LowPart: 0,
        HighPart: 0,
    };
    let name: U16CString = name.try_into().unwrap();
    let r = unsafe {LookupPrivilegeValueW(std::ptr::null(),name.as_ptr(), &mut luid )};
    if r == 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut privilege = TOKEN_PRIVILEGES{
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {Luid: luid, Attributes: SE_PRIVILEGE_ENABLED}],
    };

    let r = unsafe {
        AdjustTokenPrivileges(handle, false as i32, &mut privilege, std::mem::size_of::<TOKEN_PRIVILEGES>() as u32, std::ptr::null_mut(), std::ptr::null_mut())
    };

    if r == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
