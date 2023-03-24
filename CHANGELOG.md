## 1.2.3 - 2023-03-24

- Fix: panic with too short vec for MultiString (thanks @PyPylia)

## 1.2.2 - 2022-05-16

- Improvement: fix docs and code samples

## 1.2.1 - 2021-10-26

- Fix: reading integer values

## 1.2.0 - 2021-06-20

- Added high level `Error` type for convenience in implementing crates
- Improved debug output for `Data` type
- Fixed potential undefined behaviour in internal handling of byte arrays
- Fixed extra empty string in `MultiString` lists
- Fixed incorrect path for display value of `RegKey` paths when using `open` or `create`

## 1.1.1 - 2021-04-16

- Fixed `value::Error::BufferSize` occurring instead of `value::Error::NotFound`
- Deprecated `value::Error::BufferSize` and `value::Error::InvalidBufferSize` as they are not used.

## 1.1.0 — 2020-10-25

- Added `Hive::load_file` to load application hive files using `RegLoadAppKeyW`
- Added two examples of application hive usage (thanks @ZoeyR)

## 1.0.0

- First release
