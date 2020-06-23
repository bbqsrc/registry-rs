use std::ptr::null_mut;

use widestring::{U16CStr, U16CString, U16Str};
use winapi::shared::minwindef::HKEY;
use winapi::um::winreg::{RegQueryValueExW, RegSetValueExW};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Error determining required buffer size for value '{0}'")]
    BufferSize(String, #[source] std::io::Error),

    #[error("Data not found for value with name '{0}'")]
    NotFound(String, #[source] std::io::Error),

    #[error("Permission denied for given value name: '{0}'")]
    PermissionDenied(String, #[source] std::io::Error),

    #[error("Unhandled type: 0x{0:x}")]
    UnhandledType(u32),

    #[error("Invalid buffer size for UTF-16 string: {0}")]
    InvalidBufferSize(usize),

    #[error("Missing null terminator in string")]
    MissingNul(#[from] widestring::MissingNulError<u16>),

    #[error("Missing null terminator in multi string")]
    MissingMultiNul,

    #[error("Invalid UTF-16")]
    InvalidUtf16(#[from] std::string::FromUtf16Error),

    #[error("An unknown IO error occurred for given value name: '{0}'")]
    Unknown(String, #[source] std::io::Error),
}

#[repr(u32)]
pub(crate) enum Type {
    None = 0,
    String = 1,
    ExpandString = 2,
    Binary = 3,
    U32 = 4,
    U32BE = 5,
    Link = 6,
    MultiString = 7,
    ResourceList = 8,
    FullResourceDescriptor = 9,
    ResourceRequirementsList = 10,
    U64 = 11,
}

impl Type {
    const MAX: u32 = 11;
}

pub enum Data {
    None,
    String(String),
    ExpandString(String),
    Binary(Vec<u8>),
    U32(u32),
    U32BE(u32),
    Link,
    MultiString(Vec<String>),
    ResourceList,
    FullResourceDescriptor,
    ResourceRequirementsList,
    U64(u64),
}

impl Data {
    fn as_type(&self) -> Type {
        match self {
            Data::None => Type::None,
            Data::String(_) => Type::String,
            Data::ExpandString(_) => Type::ExpandString,
            Data::Binary(_) => Type::Binary,
            Data::U32(_) => Type::U32,
            Data::U32BE(_) => Type::U32BE,
            Data::Link => Type::Link,
            Data::MultiString(_) => Type::MultiString,
            Data::ResourceList => Type::ResourceList,
            Data::FullResourceDescriptor => Type::FullResourceDescriptor,
            Data::ResourceRequirementsList => Type::ResourceRequirementsList,
            Data::U64(_) => Type::U64,
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        match self {
            Data::None => vec![],
            Data::String(s) => string_to_utf16_byte_vec(s),
            Data::ExpandString(s) => string_to_utf16_byte_vec(s),
            Data::Binary(x) => x.to_vec(),
            Data::U32(x) => x.to_le_bytes().to_vec(),
            Data::U32BE(x) => x.to_be_bytes().to_vec(),
            Data::Link => vec![],
            Data::MultiString(x) => multi_string_bytes(x),
            Data::ResourceList => vec![],
            Data::FullResourceDescriptor => vec![],
            Data::ResourceRequirementsList => vec![],
            Data::U64(x) => x.to_le_bytes().to_vec(),
        }
    }
}

#[inline(always)]
fn multi_string_bytes(s: &[String]) -> Vec<u8> {
    let mut vec = s
        .iter()
        .flat_map(|x| string_to_utf16_byte_vec(&*x))
        .collect::<Vec<u8>>();
    vec.push(0);
    vec.push(0);
    vec
}

#[inline(always)]
fn string_to_utf16_byte_vec(s: &str) -> Vec<u8> {
    // TODO: don't unwrap
    U16CString::from_str(s)
        .unwrap()
        .into_vec_with_nul()
        .into_iter()
        .flat_map(|x| x.to_le_bytes().to_vec())
        .collect()
}

fn parse_wide_string_nul(mut vec: Vec<u8>) -> Result<String, Error> {
    if vec.len() % 2 != 0 {
        return Err(Error::InvalidBufferSize(vec.len()));
    }

    // SAFETY: we check above that it is a multiple of 2, and that it is aligned where
    // it is allocated.
    #[allow(clippy::cast_ptr_alignment)]
    let buf =
        unsafe { std::slice::from_raw_parts_mut(vec.as_mut_ptr() as *mut u16, vec.len() / 2) };

    let c_str = U16CStr::from_slice_with_nul(buf)?;
    Ok(c_str.to_string()?)
}

fn parse_wide_multi_string(mut vec: Vec<u8>) -> Result<Vec<String>, Error> {
    if vec.len() % 2 != 0 {
        return Err(Error::InvalidBufferSize(vec.len()));
    }

    // SAFETY: we check above that it is a multiple of 2, and that it is aligned where
    // it is allocated.
    #[allow(clippy::cast_ptr_alignment)]
    let buf =
        unsafe { std::slice::from_raw_parts_mut(vec.as_mut_ptr() as *mut u16, vec.len() / 2) };

    let len = buf.len();

    if len < 2 {
        return Err(Error::InvalidBufferSize(len));
    }

    if buf[len - 1] != 0 || buf[len - 2] != 0 {
        return Err(Error::MissingMultiNul);
    }

    (&buf[0..buf.len() - 1])
        .split(|x| *x == 0)
        .map(|x| U16Str::from_slice(x))
        .map(U16Str::to_string)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Error::InvalidUtf16)
}

#[inline]
pub(crate) fn set_value<S: AsRef<U16CStr>>(
    base: HKEY,
    value_name: S,
    data: &Data,
) -> Result<(), Error> {
    let value_name = value_name.as_ref();
    let raw_ty = data.as_type() as u32;
    let vec = data.to_bytes();
    let result = unsafe {
        RegSetValueExW(
            base,
            value_name.as_ptr(),
            0,
            raw_ty,
            vec.as_ptr(),
            vec.len() as u32,
        )
    };

    if result != 0 {
        let io_error = std::io::Error::from_raw_os_error(result);
        let value_name = value_name
            .to_string()
            .unwrap_or_else(|_| "<unknown>".into());
        return match io_error.kind() {
            std::io::ErrorKind::NotFound => Err(Error::NotFound(value_name, io_error)),
            std::io::ErrorKind::PermissionDenied => {
                Err(Error::PermissionDenied(value_name, io_error))
            }
            _ => Err(Error::Unknown(value_name, io_error)),
        };
    }

    Ok(())
}

#[inline(always)]
fn u16_aligned_u8_vec(size: usize) -> Vec<u8> {
    let remainder = size % 2;

    let mut buf = vec![0u16; size / 2 + remainder];
    let (ptr, len, capacity) = (buf.as_mut_ptr(), buf.len(), buf.capacity());
    std::mem::forget(buf);

    let mut buf = unsafe { Vec::from_raw_parts(ptr as *mut u8, len * 2, capacity * 2) };
    buf.truncate(size);
    debug_assert!(buf.len() == size);
    buf
}

#[inline]
pub(crate) fn query_value<S: AsRef<U16CStr>>(base: HKEY, value_name: S) -> Result<Data, Error> {
    let value_name = value_name.as_ref();
    let mut sz: u32 = 0;

    // Get the required buffer size first
    let result = unsafe {
        RegQueryValueExW(
            base,
            value_name.as_ptr(),
            null_mut(),
            null_mut(),
            null_mut(),
            &mut sz,
        )
    };

    if result != 0 {
        return Err(Error::BufferSize(
            value_name
                .to_string()
                .unwrap_or_else(|_| "<unknown>".into()),
            std::io::Error::from_raw_os_error(result),
        ));
    }

    let mut buf = u16_aligned_u8_vec(sz as usize);
    let mut ty = 0u32;

    // Get the actual value
    let result = unsafe {
        RegQueryValueExW(
            base,
            value_name.as_ptr(),
            null_mut(),
            &mut ty,
            buf.as_mut_ptr(),
            &mut sz,
        )
    };

    if result != 0 {
        let io_error = std::io::Error::from_raw_os_error(result);
        let value_name = value_name
            .to_string()
            .unwrap_or_else(|_| "<unknown>".into());
        return match io_error.kind() {
            std::io::ErrorKind::NotFound => Err(Error::NotFound(value_name, io_error)),
            std::io::ErrorKind::PermissionDenied => {
                Err(Error::PermissionDenied(value_name, io_error))
            }
            _ => Err(Error::Unknown(value_name, io_error)),
        };
    }

    if ty > Type::MAX {
        return Err(Error::UnhandledType(ty));
    }

    // SAFETY: This is safe because we check if the value will fit just above.
    let ty: Type = unsafe { std::mem::transmute::<u32, Type>(ty) };

    match ty {
        Type::None => Ok(Data::None),
        Type::String => parse_wide_string_nul(buf).map(Data::String),
        Type::ExpandString => parse_wide_string_nul(buf).map(Data::ExpandString),
        Type::Binary => Ok(Data::Binary(buf)),
        Type::U32 => Ok(Data::U32(u32::from_le_bytes([
            buf[0], buf[1], buf[2], buf[3],
        ]))),
        Type::U32BE => Ok(Data::U32BE(u32::from_be_bytes([
            buf[3], buf[2], buf[1], buf[0],
        ]))),
        Type::Link => Ok(Data::Link),
        Type::MultiString => parse_wide_multi_string(buf).map(Data::MultiString),
        Type::ResourceList => Ok(Data::ResourceList),
        Type::FullResourceDescriptor => Ok(Data::FullResourceDescriptor),
        Type::ResourceRequirementsList => Ok(Data::ResourceRequirementsList),
        Type::U64 => Ok(Data::U64(u64::from_le_bytes([
            buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
        ]))),
    }
}
