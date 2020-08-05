#![cfg(windows)]
#![deny(rust_2018_idioms)]

//! # Registry
//!
//! A convenient crate for safely accessing and mutating the Windows Registry.

mod hive;
pub mod iter;
pub mod key;
mod sec;
mod util;
pub mod value;

pub use hive::Hive;
pub use key::RegKey;
pub use sec::Security;
pub use value::Data;

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
