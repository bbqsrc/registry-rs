#![cfg(windows)]
#![deny(rust_2018_idioms)]

mod hive;
mod iter;
mod key;
mod sec;
mod value;

pub use hive::Hive;
pub use key::RegKey;
pub use sec::Security;
use std::ops::{Deref, DerefMut};
pub use value::Data;

#[repr(transparent)]
#[derive(Debug, Clone)]
pub(crate) struct U16AlignedU8Vec(pub Vec<u8>);

impl U16AlignedU8Vec {
    #[inline(always)]
    pub fn new(size: usize) -> U16AlignedU8Vec {
        let remainder = size % 2;

        let mut buf = vec![0u16; size / 2 + remainder];
        let (ptr, len, capacity) = (buf.as_mut_ptr(), buf.len(), buf.capacity());
        std::mem::forget(buf);

        let mut buf = unsafe { Vec::from_raw_parts(ptr as *mut u8, len * 2, capacity * 2) };
        buf.truncate(size);
        U16AlignedU8Vec(buf)
    }
}

impl Deref for U16AlignedU8Vec {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for U16AlignedU8Vec {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_key() {
        let result = Hive::LocalMachine
            .open(r"SOFTWARE\Microsoft".to_string(), Security::AllAccess)
            .unwrap();
        println!("{:#?}", result);
    }

    #[test]
    fn iter_keys() {
        let regkey = Hive::LocalMachine
            .open(
                r"SOFTWARE\Microsoft\Windows".to_string(),
                Security::AllAccess,
            )
            .unwrap();
        let results = regkey.keys().collect::<Result<Vec<_>, _>>().unwrap();
        println!("{:?}", &results);
    }

    #[test]
    fn iter_values() {
        let regkey = Hive::CurrentUser
            .open(r"Keyboard Layout\Preload".to_string(), Security::Read)
            .unwrap();
        let results = regkey.values().collect::<Result<Vec<_>, _>>().unwrap();
        println!("{:?}", &results);
    }
}
