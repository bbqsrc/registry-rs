use std::{convert::TryInto, fmt::Display};

use utfx::{U16CStr, U16CString};
use windows::Win32::{
    Foundation::PWSTR,
    System::Registry::{
        HKEY_CLASSES_ROOT, HKEY_CURRENT_CONFIG, HKEY_CURRENT_USER, HKEY_CURRENT_USER_LOCAL_SETTINGS,
        HKEY_LOCAL_MACHINE, HKEY_PERFORMANCE_DATA, HKEY_USERS, HKEY, RegLoadAppKeyW
    }
};

use crate::key::{self, Error};
use crate::{sec::Security, RegKey};

/// All hives of the Windows Registry. Start here to get to a registry key.
#[derive(Debug, Copy, Clone)]
#[non_exhaustive]
pub enum Hive {
    ClassesRoot,
    CurrentConfig,
    CurrentUser,
    CurrentUserLocalSettings,
    LocalMachine,
    PerformanceData,
    Users,

    #[doc(hidden)]
    Application,
}

impl Hive {
    #[inline]
    fn as_hkey(&self) -> HKEY {
        match self {
            Hive::ClassesRoot => HKEY_CLASSES_ROOT,
            Hive::CurrentConfig => HKEY_CURRENT_CONFIG,
            Hive::CurrentUser => HKEY_CURRENT_USER,
            Hive::CurrentUserLocalSettings => HKEY_CURRENT_USER_LOCAL_SETTINGS,
            Hive::LocalMachine => HKEY_LOCAL_MACHINE,
            Hive::PerformanceData => HKEY_PERFORMANCE_DATA,
            Hive::Users => HKEY_USERS,
            Hive::Application => panic!("as_hkey must not be called for Application hives"),
        }
    }

    #[inline]
    pub fn open<P>(&self, path: P, sec: Security) -> Result<RegKey, Error>
    where
        P: TryInto<U16CString>,
        P::Error: Into<Error>,
    {
        let path = path.try_into().map_err(Into::into)?;
        key::open_hkey(self.as_hkey(), &path, sec).map(|handle| RegKey {
            hive: *self,
            handle,
            path,
        })
    }

    #[inline]
    pub fn write<P>(&self, file_path: P) -> Result<(), Error>
    where
        P: TryInto<U16CString>,
        P::Error: Into<Error>,
    {
        let path = file_path.try_into().map_err(Into::into)?;
        key::save_hkey(self.as_hkey(), &path)
    }

    #[inline]
    pub fn create<P>(&self, path: P, sec: Security) -> Result<RegKey, Error>
    where
        P: TryInto<U16CString>,
        P::Error: Into<Error>,
    {
        let path = path.try_into().map_err(Into::into)?;
        key::create_hkey(self.as_hkey(), &path, sec).map(|handle| RegKey {
            hive: *self,
            handle,
            path,
        })
    }

    #[inline]
    pub fn delete<P>(&self, path: P, is_recursive: bool) -> Result<(), Error>
    where
        P: TryInto<U16CString>,
        P::Error: Into<Error>,
    {
        let path = path.try_into().map_err(Into::into)?;
        key::delete_hkey(self.as_hkey(), path, is_recursive)
    }

    #[inline]
    pub fn load_file<P: AsRef<std::path::Path>>(
        file_path: P,
        sec: Security,
    ) -> Result<RegKey, std::io::Error> {
        if !file_path.as_ref().exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("No hive found at path: {:?}", file_path.as_ref()),
            ));
        }
        let path = U16CString::from_os_str(file_path.as_ref().as_os_str())
            .expect("Path must always be UTF-16 on Windows");
        load_appkey(&path, sec).map(|handle| RegKey {
            hive: Hive::Application,
            handle,
            path: "".try_into().unwrap(),
        })
    }
}

impl Display for Hive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Hive::ClassesRoot => "HKEY_CLASSES_ROOT",
            Hive::CurrentConfig => "HKEY_CURRENT_CONFIG",
            Hive::CurrentUser => "HKEY_CURRENT_USER",
            Hive::CurrentUserLocalSettings => "HKEY_CURRENT_USER_LOCAL_SETTINGS",
            Hive::LocalMachine => "HKEY_LOCAL_MACHINE",
            Hive::PerformanceData => "HKEY_PERFORMANCE_DATA",
            Hive::Users => "HKEY_USERS",
            Hive::Application => "<App>",
        })
    }
}

#[inline]
pub(crate) fn load_appkey<P>(path: P, sec: Security) -> Result<HKEY, std::io::Error>
where
    P: AsRef<U16CStr>,
{
    let path = path.as_ref();
    let mut hkey = HKEY::default();
    let result = unsafe { RegLoadAppKeyW(PWSTR(path.as_ptr() as *mut u16), &mut hkey, sec.bits(), 0, 0) };

    if result.0 == 0 {
        return Ok(hkey);
    }

    Err(std::io::Error::from_raw_os_error(result.0))
}
