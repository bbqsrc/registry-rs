use std::{
    convert::{Infallible, TryFrom, TryInto},
    fmt::{Debug, Display},
    io,
    ptr::null_mut,
};

use utfx::U16CString;
use winapi::shared::minwindef::HKEY;
use winapi::um::winreg::{RegDeleteValueW, RegQueryValueExW, RegSetValueExW};

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("Data not found for value with name '{0}'")]
    NotFound(String, #[source] io::Error),

    #[error("Permission denied for given value name: '{0}'")]
    PermissionDenied(String, #[source] io::Error),

    #[error("Unhandled type: 0x{0:x}")]
    UnhandledType(u32),

    #[error("Invalid null found in string")]
    InvalidNul(#[from] utfx::NulError<u16>),

    #[error("Missing null terminator in string")]
    MissingNul(#[from] utfx::MissingNulError<u16>),

    #[error("Missing null terminator in multi string")]
    MissingMultiNul,

    #[error("Invalid UTF-16")]
    InvalidUtf16(#[from] std::string::FromUtf16Error),

    #[error("An unknown IO error occurred for given value name: '{0}'")]
    Unknown(String, #[source] io::Error),

    #[deprecated(note = "not used")]
    #[error("Error determining required buffer size for value '{0}'")]
    BufferSize(String, #[source] io::Error),

    #[deprecated(note = "not used")]
    #[error("Invalid buffer size for UTF-16 string: {0}")]
    InvalidBufferSize(usize),
}

impl Error {
    #[cfg(test)]
    pub(crate) fn is_not_found(&self) -> bool {
        match self {
            Error::NotFound(_, _) => true,
            _ => false,
        }
    }

    fn from_code(code: i32, value_name: String) -> Self {
        let err = std::io::Error::from_raw_os_error(code);

        return match err.kind() {
            io::ErrorKind::NotFound => Error::NotFound(value_name, err),
            io::ErrorKind::PermissionDenied => Error::PermissionDenied(value_name, err),
            _ => Error::Unknown(value_name, err),
        };
    }
}

impl From<Infallible> for Error {
    fn from(_: Infallible) -> Self {
        unsafe { std::hint::unreachable_unchecked() }
    }
}

#[repr(u32)]
#[derive(Debug, Copy, Clone)]
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

/// A type-safe wrapper around Windows Registry value data.
#[derive(Clone)]
pub enum Data {
    None,
    String(U16CString),
    ExpandString(U16CString),
    Binary(Vec<u8>),
    U32(u32),
    U32BE(u32),
    Link,
    MultiString(Vec<U16CString>),
    ResourceList,
    FullResourceDescriptor,
    ResourceRequirementsList,
    U64(u64),
}

impl Debug for Data {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Data::None => f.write_str("None"),
            Data::String(s) => {
                write!(f, "String({:?})", s.to_string_lossy())
            }
            Data::ExpandString(s) => {
                write!(f, "ExpandString({:?})", s.to_string_lossy())
            }
            Data::Binary(s) => write!(f, "Binary({:?})", s),
            Data::U32(x) => write!(f, "U32({})", x),
            Data::U32BE(x) => write!(f, "U32BE({})", x),
            Data::Link => f.write_str("Link"),
            x @ Data::MultiString(_) => {
                write!(f, "MultiString({})", x.to_string())
            }
            Data::ResourceList => f.write_str("ResourceList"),
            Data::FullResourceDescriptor => f.write_str("FullResourceDescriptor"),
            Data::ResourceRequirementsList => f.write_str("ResourceRequirementsList"),
            Data::U64(x) => write!(f, "U64({})", x),
        }
    }
}

impl Display for Data {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Data::None => f.write_str("<None>"),
            Data::String(s) => f.write_str(&s.to_string_lossy()),
            Data::ExpandString(s) => f.write_str(&s.to_string_lossy()),
            Data::Binary(s) => write!(
                f,
                "<{}>",
                s.iter()
                    .map(|x| format!("{:02x}", x))
                    .collect::<Vec<_>>()
                    .join(" ")
            ),
            Data::U32(x) => write!(f, "0x{:016x}", x),
            Data::U32BE(x) => write!(f, "0x{:016x}", x),
            Data::Link => f.write_str("<Link>"),
            Data::MultiString(x) => f
                .debug_list()
                .entries(x.iter().map(|x| x.to_string_lossy()))
                .finish(),
            Data::ResourceList => f.write_str("<Resource List>"),
            Data::FullResourceDescriptor => f.write_str("<Full Resource Descriptor>"),
            Data::ResourceRequirementsList => f.write_str("<Resource Requirements List>"),
            Data::U64(x) => write!(f, "0x{:032x}", x),
        }
    }
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
fn multi_string_bytes(s: &[U16CString]) -> Vec<u8> {
    let mut vec = s
        .iter()
        .flat_map(|x| string_to_utf16_byte_vec(&*x))
        .collect::<Vec<u8>>();
    vec.push(0);
    vec.push(0);
    vec
}

#[inline(always)]
fn string_to_utf16_byte_vec(s: &U16CString) -> Vec<u8> {
    s.to_owned()
        .into_vec_with_nul()
        .into_iter()
        .flat_map(|x| x.to_le_bytes().to_vec())
        .collect()
}

fn parse_wide_string_nul(vec: Vec<u16>) -> Result<U16CString, Error> {
    Ok(U16CString::from_vec_with_nul(vec)?)
}

fn parse_wide_multi_string(vec: Vec<u16>) -> Result<Vec<U16CString>, Error> {
    let len = vec.len();
    if len < 2 || vec[len - 1] != 0 || vec[len - 2] != 0 {
        return Err(Error::MissingMultiNul);
    }

    (&vec[0..vec.len() - 2])
        .split(|x| *x == 0)
        .map(U16CString::new)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Error::InvalidNul)
}

#[inline]
pub(crate) fn set_value<S>(base: HKEY, value_name: S, data: &Data) -> Result<(), Error>
where
    S: TryInto<U16CString>,
    S::Error: Into<Error>,
{
    let value_name = value_name.try_into().map_err(Into::into)?;
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
        return Err(Error::from_code(result, value_name.to_string_lossy()));
    }

    Ok(())
}

#[inline]
pub(crate) fn delete_value<S>(base: HKEY, value_name: S) -> Result<(), Error>
where
    S: TryInto<U16CString>,
    S::Error: Into<Error>,
{
    let value_name = value_name.try_into().map_err(Into::into)?;
    let result = unsafe { RegDeleteValueW(base, value_name.as_ptr()) };

    if result != 0 {
        return Err(Error::from_code(result, value_name.to_string_lossy()));
    }

    Ok(())
}

#[inline]
pub(crate) fn query_value<S>(base: HKEY, value_name: S) -> Result<Data, Error>
where
    S: TryInto<U16CString>,
    S::Error: Into<Error>,
{
    let value_name = value_name.try_into().map_err(Into::into)?;
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
        return Err(Error::from_code(result, value_name.to_string_lossy()));
    }

    // sz is size in bytes, we'll make a u16 vec.
    let mut buf: Vec<u16> = vec![0u16; (sz / 2 + sz % 2) as usize];
    let mut ty = 0u32;

    // Get the actual value
    let result = unsafe {
        RegQueryValueExW(
            base,
            value_name.as_ptr(),
            null_mut(),
            &mut ty,
            buf.as_mut_ptr() as *mut u8,
            &mut sz,
        )
    };

    if result != 0 {
        return Err(Error::from_code(result, value_name.to_string_lossy()));
    }

    parse_value_type_data(ty, buf)
}

pub fn u16_to_u8_vec(mut vec: Vec<u16>) -> Vec<u8> {
    unsafe {
        let capacity = vec.capacity();
        let len = vec.len();
        let ptr = vec.as_mut_ptr();
        std::mem::forget(vec);
        Vec::from_raw_parts(ptr as *mut u8, 2 * len, 2 * capacity)
    }
}

#[inline(always)]
pub(crate) fn parse_value_type_data(ty: u32, buf: Vec<u16>) -> Result<Data, Error> {
    let ty = Type::try_from(ty).map_err(|_| Error::UnhandledType(ty))?;

    match ty {
        Type::None => return Ok(Data::None),
        Type::String => return parse_wide_string_nul(buf).map(Data::String),
        Type::ExpandString => return parse_wide_string_nul(buf).map(Data::ExpandString),
        Type::Link => return Ok(Data::Link),
        Type::MultiString => return parse_wide_multi_string(buf).map(Data::MultiString),
        Type::ResourceList => return Ok(Data::ResourceList),
        Type::FullResourceDescriptor => return Ok(Data::FullResourceDescriptor),
        Type::ResourceRequirementsList => return Ok(Data::ResourceRequirementsList),
        _ => {}
    }

    let buf = u16_to_u8_vec(buf);

    match ty {
        Type::Binary => Ok(Data::Binary(buf)),
        Type::U32 => Ok(Data::U32(u32::from_le_bytes([
            buf[0], buf[1], buf[2], buf[3],
        ]))),
        Type::U32BE => Ok(Data::U32BE(u32::from_be_bytes([
            buf[0], buf[1], buf[2], buf[3],
        ]))),
        Type::U64 => Ok(Data::U64(u64::from_le_bytes([
            buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
        ]))),
        _ => unreachable!(),
    }
}

#[derive(Debug, thiserror::Error)]
#[error("Invalid or unknown type value: {0:#x}")]
pub struct TryIntoTypeError(u32);

impl TryFrom<u32> for Type {
    type Error = TryIntoTypeError;
    fn try_from(ty: u32) -> Result<Self, Self::Error> {
        if ty > Type::MAX {
            return Err(TryIntoTypeError(ty));
        }

        // SAFETY: This is safe because we check if the value will fit just
        // above and Type has repr(u32).
        Ok(unsafe { std::mem::transmute::<u32, Type>(ty) })
    }
}
