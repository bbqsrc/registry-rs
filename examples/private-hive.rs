use registry::{Hive, Security};
use windows::{core::PCWSTR, Win32::{Foundation::{HANDLE, LUID}, Security::{AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_BACKUP_NAME, SE_PRIVILEGE_ENABLED, SE_RESTORE_NAME, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES}, System::Threading::{GetCurrentProcess, OpenProcessToken}}};

fn main() -> Result<(), windows::core::Error> {
    let mut token = HANDLE::default();
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &mut token)? };

    set_privilege(token, SE_RESTORE_NAME)?;
    set_privilege(token, SE_BACKUP_NAME)?;
    let hive_key = Hive::load_file(
        r"C:\Users\Default\NTUSER.DAT",
        Security::Read | Security::Write,
    )
    .unwrap();

    let keys: Vec<_> = hive_key.keys().map(|k| k.unwrap().to_string()).collect();

    println!("{:?}", keys);
    Ok(())
}

fn set_privilege(handle: HANDLE, name: PCWSTR) -> Result<(), windows::core::Error> {
    let mut luid: LUID = LUID {
        LowPart: 0,
        HighPart: 0,
    };
    unsafe { LookupPrivilegeValueW(None, name, &mut luid)? };

    let mut privilege = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };

    unsafe {
        AdjustTokenPrivileges(
            handle,
            false,
            Some(&mut privilege),
            std::mem::size_of::<TOKEN_PRIVILEGES>() as u32,
            None,
            None,
        )?
    };

    Ok(())
}
