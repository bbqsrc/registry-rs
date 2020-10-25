# Registry

[![Documentation](https://docs.rs/registry/badge.svg)](https://docs.rs/registry)
[![Actions Status](https://github.com/bbqsrc/registry-rs/workflows/CI/badge.svg)](https://github.com/bbqsrc/registry-rs/actions)

A convenient crate for safely accessing and mutating the Windows Registry.

This crate only supported versions of Windows 8.1 and newer. Usage on Windows 7 or 8 may work, subject to various Win32 API limitations. These limitations will not be documented in this crate, so if you are unfamiliar with the Win32 variants of these functions, stick to Windows 8.1 or newer.

## License

The `registry` crate is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.