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

        // Safety: this is guaranteed to be aligned.
        #[allow(clippy::cast_ptr_alignment)]
        unsafe {
            Vec::from_raw_parts(ptr as *mut u16, len / 2, capacity / 2)
        }
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
