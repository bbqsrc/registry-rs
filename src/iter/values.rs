use std::{convert::TryInto, fmt::Debug, ptr::null_mut};

use widestring::{U16CStr, U16CString};
use winapi::shared::winerror::ERROR_NO_MORE_ITEMS;
use winapi::um::winreg::{RegEnumValueW, RegQueryInfoKeyW};

use crate::key::RegKey;
use crate::{Data, U16AlignedU8Vec};

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("Invalid UTF-16")]
    InvalidUtf16(#[from] std::string::FromUtf16Error),

    #[error("Missing null terminator in string")]
    MissingNul(#[from] widestring::MissingNulError<u16>),

    #[error("Invalid null found in string")]
    InvalidNul(#[from] widestring::NulError<u16>),

    #[error("Error parsing data")]
    Data(#[from] crate::value::Error),

    #[error("An unknown IO error occurred for index: {0:?}")]
    Unknown(u32, #[source] std::io::Error),
}

#[derive(Debug)]
pub struct Values<'a> {
    regkey: &'a RegKey,
    name_buf: Vec<u16>,
    data_buf: U16AlignedU8Vec,
    index: u32,
}

pub struct ValueRef<'a> {
    regkey: &'a RegKey,
    name: U16CString,
    data: Data,
}

impl<'a> Debug for ValueRef<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ValueRef")
            .field(&self.name.to_string_lossy())
            .field(&self.data)
            .finish()
    }
}

impl<'a> ValueRef<'a> {
    pub fn set_name<S>(&mut self, name: S) -> Result<(), Error>
    where
        S: TryInto<U16CString>,
        S::Error: Into<Error>,
    {
        let mut name = name.try_into().map_err(Into::into)?;
        std::mem::swap(&mut name, &mut self.name);

        self.regkey.set_value(&self.name, &self.data)?;
        self.regkey.delete_value(name)?;
        Ok(())
    }

    pub fn set_data(&mut self, data: Data) -> Result<(), Error> {
        self.data = data;
        self.regkey.set_value(&self.name, &self.data)?;
        Ok(())
    }

    pub fn name(&self) -> &U16CStr {
        &self.name
    }

    pub fn data(&self) -> &Data {
        &self.data
    }

    pub fn into_name(self) -> U16CString {
        self.name
    }

    pub fn into_data(self) -> Data {
        self.data
    }

    pub fn into_inner(self) -> (U16CString, Data) {
        (self.name, self.data)
    }
}

impl<'a> Iterator for Values<'a> {
    type Item = Result<ValueRef<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        self.name_buf[0] = 0;
        let mut name_len = self.name_buf.len() as u32;

        for v in &mut self.data_buf.0 {
            *v = 0;
        }
        let mut data_type: u32 = 0u32;
        let mut data_len = self.data_buf.len() as u32;

        let result = unsafe {
            RegEnumValueW(
                self.regkey.handle,
                self.index,
                self.name_buf.as_mut_ptr(),
                &mut name_len,
                null_mut(),
                &mut data_type,
                self.data_buf.as_mut_ptr(),
                &mut data_len,
            )
        };

        if result == ERROR_NO_MORE_ITEMS as i32 {
            return None;
        }

        if result != 0 {
            return Some(Err(Error::Unknown(
                self.index,
                std::io::Error::from_raw_os_error(result),
            )));
        }

        self.index += 1;

        let name = match U16CString::new(&self.name_buf[0..name_len as usize]) {
            Ok(v) => v,
            Err(e) => return Some(Err(Error::InvalidNul(e))),
        };

        let data = match crate::value::parse_value_type_data(data_type, self.data_buf.clone()) {
            Ok(v) => v,
            Err(e) => return Some(Err(Error::Data(e))),
        };

        Some(Ok(ValueRef {
            regkey: self.regkey,
            name,
            data,
        }))
    }
}

impl<'a> Values<'a> {
    pub fn new(regkey: &'a RegKey) -> Result<Values<'a>, std::io::Error> {
        let mut value_count = 0u32;
        let mut max_value_name_len = 0u32;
        let mut max_value_data_len = 0u32;

        let result = unsafe {
            RegQueryInfoKeyW(
                regkey.handle,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                &mut value_count,
                &mut max_value_name_len,
                &mut max_value_data_len,
                null_mut(),
                null_mut(),
            )
        };

        if result == 0 {
            return Ok(Values {
                regkey,
                name_buf: vec![0u16; max_value_name_len as usize + 1],
                data_buf: U16AlignedU8Vec::new(max_value_data_len as usize),
                index: 0,
            });
        }

        Err(std::io::Error::from_raw_os_error(result))
    }
}
