use std::{
    fmt::{Debug, Display},
    ptr::null_mut,
};

use utfx::{U16CString, U16String};
use winapi::shared::winerror::ERROR_NO_MORE_ITEMS;
use winapi::um::winreg::{RegEnumKeyExW, RegQueryInfoKeyW};

use crate::key::RegKey;
use crate::sec::Security;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("Invalid UTF-16")]
    InvalidUtf16(#[from] std::string::FromUtf16Error),

    #[error("Missing null terminator in string")]
    MissingNul(#[from] utfx::MissingNulError<u16>),

    #[error("Invalid null found in string")]
    InvalidNul(#[from] utfx::NulError<u16>),
}

#[derive(Debug)]
pub struct Keys<'a> {
    regkey: &'a RegKey,
    buf: Vec<u16>,
    index: u32,
}

pub struct KeyRef<'a> {
    regkey: &'a RegKey,
    name: U16CString,
}

impl Display for KeyRef<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.name.to_string_lossy())
    }
}

impl<'a> Debug for KeyRef<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("KeyRef")
            .field(&self.name.to_string_lossy())
            .finish()
    }
}

impl<'a> KeyRef<'a> {
    #[inline]
    pub fn open(&self, sec: Security) -> Result<RegKey, crate::key::Error> {
        let path = self.regkey.path.to_ustring();
        let suffix = self.name.to_ustring();
        let bs = U16String::from_str("\\");
        let chars = path
            .as_slice()
            .iter()
            .chain(bs.as_slice())
            .chain(suffix.as_slice())
            .copied()
            .collect::<Vec<u16>>();

        let path = U16CString::new(chars)?;
        crate::key::open_hkey(self.regkey.handle, &self.name, sec).map(|handle| RegKey {
            hive: self.regkey.hive,
            handle,
            path,
        })
    }
}

impl<'a> Iterator for Keys<'a> {
    type Item = Result<KeyRef<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        // Reset first byte, just in case.
        self.buf[0] = 0;
        let mut len = self.buf.len() as u32;

        let result = unsafe {
            RegEnumKeyExW(
                self.regkey.handle,
                self.index,
                self.buf.as_mut_ptr(),
                &mut len,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
            )
        };

        if result == ERROR_NO_MORE_ITEMS as i32 {
            return None;
        }

        self.index += 1;

        if result != 0 {
            // TODO: don't panic
            panic!();
        }

        let name = match U16CString::new(&self.buf[0..len as usize]) {
            Ok(v) => v,
            Err(e) => return Some(Err(Error::InvalidNul(e))),
        };

        Some(Ok(KeyRef {
            regkey: self.regkey,
            name,
        }))
    }
}

impl<'a> Keys<'a> {
    pub fn new(regkey: &'a RegKey) -> Result<Keys<'a>, std::io::Error> {
        let mut subkeys_max_str_len = 0u32;
        // let mut subkeys_len = 0u32;

        let result = unsafe {
            RegQueryInfoKeyW(
                regkey.handle,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(), // &mut subkeys_len,
                &mut subkeys_max_str_len,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
            )
        };

        if result == 0 {
            return Ok(Keys {
                regkey,
                buf: vec![0u16; subkeys_max_str_len as usize + 1],
                index: 0,
            });
        }

        Err(std::io::Error::from_raw_os_error(result))
    }
}
