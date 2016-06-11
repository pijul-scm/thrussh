use std;
use libsodium_sys;
use super::libc::{ malloc, free, c_void };
#[derive(Debug)]
pub struct CryptoBuf {
    p:*mut u8,
    size:usize,
    capacity:usize,
    zero:u8,
}

impl std::ops::Index<usize> for CryptoBuf {
    type Output = u8;
    fn index<'a>(&'a self, index:usize) -> &'a u8 {
        assert!(index < self.size);
        unsafe {
            &* self.p.offset(index as isize)
        }
    }
}

impl CryptoBuf {
    pub fn new() -> CryptoBuf {
        let mut buf = CryptoBuf {
            p:std::ptr::null_mut(),
            size:0,
            capacity:0,
            zero:0
        };
        // This avoids potential problems in as_slice().
        buf.p = &mut buf.zero;
        //
        buf
    }
    pub fn len(&self) -> usize {
        self.size
    }
    pub fn resize(&mut self, size:usize) {
        if size <= self.capacity {
            self.size = size
        } else {
            // realloc ! and erase the previous memory.
            unsafe {
                let next_capacity = size.next_power_of_two();
                let old_ptr = self.p;
                self.p = malloc(next_capacity) as *mut u8;

                if self.capacity > 0 {
                    std::ptr::copy_nonoverlapping(old_ptr, self.p, self.size);
                    libsodium_sys::sodium_memzero(old_ptr, self.size);
                    free(old_ptr as *mut c_void);
                }

                if self.p.is_null() {
                    panic!("Realloc failed, pointer = {:?} {:?}", self, size)
                } else {
                    self.capacity = next_capacity;
                    self.size = size;
                }
            }
        }
    }
    pub fn clear(&mut self) {
        unsafe {
            if self.capacity > 0 {
                libsodium_sys::sodium_memzero(self.p, self.size);
            }
        }
        self.size = 0;
    }

    pub fn push(&mut self, s:u8) {
        let size = self.size;
        self.resize(size + 1);
        unsafe {
            *(self.p.offset(size as isize)) = s
        }
    }

    pub fn push_u32_be(&mut self, s:u32) {
        let size = self.size;
        self.resize(size + 4);
        unsafe {
            *(self.p.offset(size as isize) as *mut u32) = s.to_be()
        }
    }

    pub fn read_u32_be(&self, i:usize) -> u32 {
        assert!(i + 4 <= self.size);
        unsafe {
            u32::from_be(*(self.p.offset(i as isize) as *const u32))
        }
    }

    // append n_bytes bytes at the end of this cryptobuf.
    pub fn read<R:std::io::Read>(&mut self, n_bytes:usize, r:&mut R) -> Result<usize, std::io::Error> {
        let cur_size = self.size;
        self.resize(cur_size + n_bytes);
        unsafe {
            let s = std::slice::from_raw_parts_mut(self.p.offset(cur_size as isize), n_bytes);
            r.read(s)
        }
    }

    pub fn write_all_from<W:std::io::Write>(&self, offset:usize, w:&mut W) -> Result<usize, std::io::Error> {
        assert!(offset < self.size);
        // if we're past this point, self.p cannot be null.
        unsafe {
            let s = std::slice::from_raw_parts(self.p.offset(offset as isize), self.size - offset);
            w.write(s)
        }
    }

    
    pub fn extend(&mut self, s:&[u8]) {
        //println!("extend {:?}", s);
        let size = self.size;
        self.resize(size + s.len());
        //println!("{:?}", self);
        unsafe {
            std::ptr::copy_nonoverlapping(
                s.as_ptr(),
                self.p.offset(size as isize),
                s.len()
            );
        }
    }

    pub fn as_slice<'a>(&'a self) -> &'a[u8] {
        unsafe {
            std::slice::from_raw_parts(self.p, self.size)
        }
    }

    pub fn as_mut_slice<'a>(&'a mut self) -> &'a mut [u8] {
        unsafe {
            std::slice::from_raw_parts_mut(self.p, self.size)
        }
    }
}

impl Drop for CryptoBuf {
    fn drop(&mut self) {
        if self.capacity > 0 {
            unsafe {
                libsodium_sys::sodium_memzero(self.p, self.size);
                free(self.p as *mut c_void)
            }
        }
    }
}
