#![allow(non_upper_case_globals)]

bitflags::bitflags! {
    pub struct Security: u32 {
        const QueryValue = 0x1;
        const SetValue = 0x2;
        const CreateSubKey = 0x4;
        const EnumerateSubKeys = 0x8;
        const Notify = 0x10;
        const CreateLink = 0x20;
        const Wow6464Key = 0x100;
        const Wow6432Key = 0x200;
        const Write = 0x20006;
        const Read = 0x20019;
        const Execute = 0x20019;
        const AllAccess = 0xf003f;
    }
}

impl Default for Security {
    fn default() -> Self {
        Security::AllAccess
    }
}
