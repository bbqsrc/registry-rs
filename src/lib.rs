#![cfg(windows)]
#![deny(rust_2018_idioms)]

mod hive;
pub mod iter;
pub mod key;
mod sec;
pub mod value;

pub use hive::Hive;
pub use key::RegKey;
pub use sec::Security;
pub use value::Data;

use std::ops::{Deref, DerefMut};

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
            .open(r"SOFTWARE\Microsoft", Security::AllAccess)
            .unwrap();
        println!("{:#?}", result);
    }

    #[test]
    fn iter_keys() {
        let regkey = Hive::LocalMachine
            .open(r"SOFTWARE\Microsoft\Windows", Security::AllAccess)
            .unwrap();
        let results = regkey.keys().collect::<Result<Vec<_>, _>>().unwrap();
        println!("{:?}", &results);
    }

    #[test]
    fn iter_values() {
        let regkey = Hive::CurrentUser
            .open(r"Keyboard Layout\Preload", Security::Read)
            .unwrap();
        let results = regkey.values().collect::<Result<Vec<_>, _>>().unwrap();
        println!("{:?}", &results);
    }

    #[test]
    fn set_value_and_delete() {
        let regkey = Hive::CurrentUser
            .create(r"Test\registry-rust-crate", Security::AllAccess)
            .unwrap();
        regkey
            .set_value("test", &Data::String("Meow meow".to_string()))
            .unwrap();

        Hive::CurrentUser.delete("Test", true).unwrap();
    }
}
