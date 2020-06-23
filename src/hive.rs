use std::fmt::Display;

use widestring::U16CStr;
use winapi::shared::minwindef::HKEY;
use winapi::um::winreg::{
    HKEY_CLASSES_ROOT, HKEY_CURRENT_CONFIG, HKEY_CURRENT_USER, HKEY_CURRENT_USER_LOCAL_SETTINGS,
    HKEY_LOCAL_MACHINE, HKEY_PERFORMANCE_DATA, HKEY_USERS,
};

use crate::key::{self, Error};
use crate::{sec::Security, RegKey};

#[derive(Debug)]
pub enum Hive {
    ClassesRoot,
    CurrentConfig,
    CurrentUser,
    CurrentUserLocalSettings,
    LocalMachine,
    PerformanceData,
    Users,
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
        }
    }

    #[inline]
    pub fn open<P>(&self, path: P, sec: Security) -> Result<RegKey, Error>
    where
        P: AsRef<U16CStr>,
    {
        key::open_hkey(self.as_hkey(), path, sec).map(RegKey)
    }

    #[inline]
    pub fn create<P>(&self, path: P, sec: Security) -> Result<RegKey, Error>
    where
        P: AsRef<U16CStr>,
    {
        key::create_hkey(self.as_hkey(), path, sec).map(RegKey)
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
        })
    }
}
