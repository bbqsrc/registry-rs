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

    pub fn into_u16_vec(mut self) -> Vec<u16> {
        let remainder = self.len() % 2;

        if remainder > 0 {
            self.0.push(0);
        }
        self.shrink_to_fit();

        let (ptr, len, capacity) = (self.as_mut_ptr(), self.len(), self.capacity());
        std::mem::forget(self);

        unsafe { Vec::from_raw_parts(ptr as *mut u16, len / 2, capacity / 2) }
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
    use std::convert::TryInto;

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
            .set_value("test", &Data::String("Meow meow".try_into().unwrap()))
            .unwrap();
        regkey
            .set_value(
                "test2",
                &Data::MultiString(vec![
                    "Meow meow".try_into().unwrap(),
                    "Woop woop".try_into().unwrap(),
                ]),
            )
            .unwrap();
        regkey.set_value("nothing", &Data::None).unwrap();
        regkey
            .set_value("some binary", &Data::Binary(vec![1, 2, 3, 4, 255]))
            .unwrap();
        regkey.set_value("u32", &Data::U32(0x1234FEFE)).unwrap();
        regkey.set_value("u32be", &Data::U32BE(0x1234FEFE)).unwrap();
        regkey
            .set_value("u64", &Data::U64(0x1234FEFE_1234FEFE))
            .unwrap();

        let results = regkey.values().collect::<Result<Vec<_>, _>>().unwrap();
        println!("{:?}", &results);

        Hive::CurrentUser.delete("Test", true).unwrap();
    }
}
