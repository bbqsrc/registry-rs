use std::path::Path;

use registry::{Hive, RegKey, Security};

fn main() -> Result<(), std::io::Error> {
    let hive_key = Hive::load_file(
        Path::new(r"C:\Users\Default\NTUSER.DAT"),
        Security::Read | Security::Write,
    )
    .unwrap();

    walk_keys(hive_key, 0);
    Ok(())
}

fn walk_keys(key: RegKey, tabstop: i32) {
    for _ in 0..tabstop {
        print!("\t");
    }
    println!("{}", key.to_string());

    for subkey in key.keys() {
        let subkey = subkey.unwrap().open(Security::Read).unwrap();
        walk_keys(subkey, tabstop + 1);
    }
}
