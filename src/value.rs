use std::{
    convert::{Infallible, TryFrom, TryInto},
    fmt::Display,
    ptr::null_mut,
};

use utfx::U16CString;
use winapi::shared::minwindef::HKEY;
use winapi::um::winreg::{RegDeleteValueW, RegQueryValueExW, RegSetValueExW};

use crate::util::U16AlignedU8Vec;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
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

    #[error("Invalid null found in string")]
    InvalidNul(#[from] utfx::NulError<u16>),

    #[error("Missing null terminator in string")]
    MissingNul(#[from] utfx::MissingNulError<u16>),

    #[error("Missing null terminator in multi string")]
    MissingMultiNul,

    #[error("Invalid UTF-16")]
    InvalidUtf16(#[from] std::string::FromUtf16Error),

    #[error("An unknown IO error occurred for given value name: '{0}'")]
    Unknown(String, #[source] std::io::Error),
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

#[derive(Debug, Clone)]
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
    if vec[len - 1] != 0 || vec[len - 2] != 0 {
        return Err(Error::MissingMultiNul);
    }

    (&vec[0..vec.len() - 1])
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

#[inline]
pub(crate) fn delete_value<S>(base: HKEY, value_name: S) -> Result<(), Error>
where
    S: TryInto<U16CString>,
    S::Error: Into<Error>,
{
    let value_name = value_name.try_into().map_err(Into::into)?;
    let result = unsafe { RegDeleteValueW(base, value_name.as_ptr()) };

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
        return Err(Error::BufferSize(
            value_name
                .to_string()
                .unwrap_or_else(|_| "<unknown>".into()),
            std::io::Error::from_raw_os_error(result),
        ));
    }

    let mut buf = U16AlignedU8Vec::new(sz as usize);
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

    parse_value_type_data(ty, buf)
}

#[inline(always)]
pub(crate) fn parse_value_type_data(ty: u32, buf: U16AlignedU8Vec) -> Result<Data, Error> {
    let ty = Type::try_from(ty).map_err(|_| Error::UnhandledType(ty))?;

    match ty {
        Type::None => Ok(Data::None),
        Type::String => parse_wide_string_nul(buf.into_u16_vec()).map(Data::String),
        Type::ExpandString => parse_wide_string_nul(buf.into_u16_vec()).map(Data::ExpandString),
        Type::Binary => Ok(Data::Binary(buf.0)),
        Type::U32 => Ok(Data::U32(u32::from_le_bytes([
            buf[0], buf[1], buf[2], buf[3],
        ]))),
        Type::U32BE => Ok(Data::U32BE(u32::from_be_bytes([
            buf[0], buf[1], buf[2], buf[3],
        ]))),
        Type::Link => Ok(Data::Link),
        Type::MultiString => parse_wide_multi_string(buf.into_u16_vec()).map(Data::MultiString),
        Type::ResourceList => Ok(Data::ResourceList),
        Type::FullResourceDescriptor => Ok(Data::FullResourceDescriptor),
        Type::ResourceRequirementsList => Ok(Data::ResourceRequirementsList),
        Type::U64 => Ok(Data::U64(u64::from_le_bytes([
            buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
        ]))),
    }
}

#[derive(Debug, thiserror::Error)]
#[error("Invalid or unknown type value: 0x{0:x}")]
pub struct TryIntoTypeError(u32);

impl TryFrom<u32> for Type {
    type Error = TryIntoTypeError;
    fn try_from(ty: u32) -> Result<Self, Self::Error> {
        if ty > Type::MAX {
            return Err(TryIntoTypeError(ty));
        }

        // SAFETY: This is safe because we check if the value will fit just above and Type has repr(u32).
        Ok(unsafe { std::mem::transmute::<u32, Type>(ty) })
    }
}
