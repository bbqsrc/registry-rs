use std::ptr::null_mut;

use widestring::{U16CStr, U16CString, U16String};
use winapi::shared::minwindef::HKEY;
use winapi::um::winreg::{RegCloseKey, RegCreateKeyExW, RegOpenCurrentUser, RegOpenKeyExW};

use crate::iter;
use crate::sec::Security;
use crate::value;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Provided path not found: {0:?}")]
    NotFound(String, #[source] std::io::Error),

    #[error("Permission denied for given path: {0:?}")]
    PermissionDenied(String, #[source] std::io::Error),

    #[error("Invalid null found in provided path")]
    InvalidNul(#[from] widestring::NulError<u16>),

    #[error("An unknown IO error occurred for given path: {0:?}")]
    Unknown(String, #[source] std::io::Error),
}

#[repr(transparent)]
#[derive(Debug)]
pub struct RegKey(pub(crate) HKEY);

impl Drop for RegKey {
    fn drop(&mut self) {
        // No point checking the return value here.
        unsafe { RegCloseKey(self.0) };
    }
}

impl RegKey {
    #[inline]
    pub fn open<P>(&self, path: P, sec: Security) -> Result<RegKey, Error>
    where
        P: Into<U16String>,
    {
        let path = U16CString::new(path.into())?;
        open_hkey(self.0, path, sec).map(RegKey)
    }

    #[inline]
    pub fn create<P>(&self, path: P, sec: Security) -> Result<RegKey, Error>
    where
        P: Into<U16String>,
    {
        let path = U16CString::new(path.into())?;
        create_hkey(self.0, path, sec).map(RegKey)
    }

    #[inline]
    pub fn value<S>(&self, value_name: S) -> Result<value::Data, value::Error>
    where
        S: AsRef<U16CStr>,
    {
        value::query_value(self.0, value_name)
    }

    #[inline]
    pub fn set_value<S>(&self, value_name: S, data: &value::Data) -> Result<(), value::Error>
    where
        S: AsRef<U16CStr>,
    {
        value::set_value(self.0, value_name, data)
    }

    #[inline]
    pub fn keys(&self) -> iter::Keys<'_> {
        match iter::Keys::new(self) {
            Ok(v) => v,
            Err(e) => panic!(e),
        }
    }

    #[inline]
    pub fn values(&self) -> iter::Values<'_> {
        match iter::Values::new(self) {
            Ok(v) => v,
            Err(e) => panic!(e),
        }
    }

    pub fn open_current_user(sec: Security) -> Result<RegKey, Error> {
        let mut hkey = null_mut();

        let result = unsafe { RegOpenCurrentUser(sec.bits(), &mut hkey) };

        if result == 0 {
            return Ok(RegKey(hkey));
        }

        let io_error = std::io::Error::from_raw_os_error(result);
        let path = "<current user>".to_string();
        match io_error.kind() {
            std::io::ErrorKind::NotFound => Err(Error::NotFound(path, io_error)),
            std::io::ErrorKind::PermissionDenied => Err(Error::PermissionDenied(path, io_error)),
            _ => Err(Error::Unknown(path, io_error)),
        }
    }
}

#[inline]
pub(crate) fn open_hkey<P>(base: HKEY, path: P, sec: Security) -> Result<HKEY, Error>
where
    P: Into<U16CString>,
{
    let path = path.into();
    let mut hkey = std::ptr::null_mut();
    let result = unsafe { RegOpenKeyExW(base, path.as_ptr(), 0, sec.bits(), &mut hkey) };

    if result == 0 {
        return Ok(hkey);
    }

    let io_error = std::io::Error::from_raw_os_error(result);
    let path = path.to_string().unwrap_or_else(|_| "<unknown>".into());
    match io_error.kind() {
        std::io::ErrorKind::NotFound => Err(Error::NotFound(path, io_error)),
        std::io::ErrorKind::PermissionDenied => Err(Error::PermissionDenied(path, io_error)),
        _ => Err(Error::Unknown(path, io_error)),
    }
}

#[inline]
pub(crate) fn create_hkey<P>(base: HKEY, path: P, sec: Security) -> Result<HKEY, Error>
where
    P: AsRef<U16CStr>,
{
    let path = path.as_ref();
    let mut hkey = std::ptr::null_mut();
    let result = unsafe {
        RegCreateKeyExW(
            base,
            path.as_ptr(),
            0,
            std::ptr::null_mut(),
            0,
            sec.bits(),
            std::ptr::null_mut(),
            &mut hkey,
            std::ptr::null_mut(),
        )
    };

    if result == 0 {
        return Ok(hkey);
    }

    let io_error = std::io::Error::from_raw_os_error(result);
    let path = path.to_string().unwrap_or_else(|_| "<unknown>".into());
    match io_error.kind() {
        std::io::ErrorKind::NotFound => Err(Error::NotFound(path, io_error)),
        std::io::ErrorKind::PermissionDenied => Err(Error::PermissionDenied(path, io_error)),
        _ => Err(Error::Unknown(path, io_error)),
    }
}
