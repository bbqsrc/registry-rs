## 1.1.1 - 2021-04-16

- Fixed `value::Error::BufferSize` occurring instead of `value::Error::NotFound`
- Deprecated `value::Error::BufferSize` and `value::Error::InvalidBufferSize` as they are not used.

## 1.1.0 — 2020-10-25

- Added `Hive::load_file` to load application hive files using `RegLoadAppKeyW`
- Added two examples of application hive usage (thanks @ZoeyR)

## 1.0.0

- First release