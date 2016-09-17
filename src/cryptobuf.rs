// Copyright 2016 Pierre-Étienne Meunier
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
use std;

use super::libc::{malloc, free, c_void};
use std::ops::{Index, IndexMut, Deref, DerefMut, Range, RangeFrom, RangeTo};
/// A buffer which zeroes its memory on `.clear()`, `.truncate()` and
/// reallocations, to avoid copying secrets around.
#[derive(Debug)]
pub struct CryptoBuf {
    p: *mut u8,
    size: usize,
    capacity: usize,
    zero: u8,
}

unsafe impl Send for CryptoBuf {}

impl Deref for CryptoBuf {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.p, self.size) }
    }
}
impl DerefMut for CryptoBuf {
    fn deref_mut(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.p, self.size) }
    }
}

impl Index<RangeFrom<usize>> for CryptoBuf {
    type Output = [u8];
    fn index(&self, index: RangeFrom<usize>) -> &[u8] {
        self.deref().index(index)
    }
}
impl Index<RangeTo<usize>> for CryptoBuf {
    type Output = [u8];
    fn index(&self, index: RangeTo<usize>) -> &[u8] {
        self.deref().index(index)
    }
}
impl Index<Range<usize>> for CryptoBuf {
    type Output = [u8];
    fn index(&self, index: Range<usize>) -> &[u8] {
        self.deref().index(index)
    }
}

impl IndexMut<RangeFrom<usize>> for CryptoBuf {
    fn index_mut(&mut self, index: RangeFrom<usize>) -> &mut [u8] {
        self.deref_mut().index_mut(index)
    }
}
impl IndexMut<RangeTo<usize>> for CryptoBuf {
    fn index_mut(&mut self, index: RangeTo<usize>) -> &mut [u8] {
        self.deref_mut().index_mut(index)
    }
}
impl IndexMut<Range<usize>> for CryptoBuf {
    fn index_mut(&mut self, index: Range<usize>) -> &mut [u8] {
        self.deref_mut().index_mut(index)
    }
}


impl Index<usize> for CryptoBuf {
    type Output = u8;
    fn index(&self, index: usize) -> &u8 {
        self.deref().index(index)
    }
}

impl std::io::Write for CryptoBuf {
    fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
        self.extend(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> Result<(), std::io::Error> {
        Ok(())
    }
}


impl Default for CryptoBuf {
    fn default() -> Self {
        let mut buf = CryptoBuf {
            p: std::ptr::null_mut(),
            size: 0,
            capacity: 0,
            zero: 0,
        };
        // This avoids potential problems in as_slice().
        buf.p = &mut buf.zero;
        //
        buf
    }
}


impl CryptoBuf {
    pub fn new() -> CryptoBuf {
        CryptoBuf::default()
    }

    pub fn len(&self) -> usize {
        self.size
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }


    pub fn resize(&mut self, size: usize) {
        if size <= self.capacity {
            self.size = size
        } else {
            // realloc ! and erase the previous memory.
            unsafe {
                let next_capacity = size.next_power_of_two();
                let old_ptr = self.p;
                self.p = malloc(next_capacity) as *mut u8;
                // TODO: mlock(self.p as *mut c_void, next_capacity);

                if self.capacity > 0 {
                    std::ptr::copy_nonoverlapping(old_ptr, self.p, self.size);
                    // TOOD: munlock(old_ptr as *mut c_void, self.size);
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
        self.truncate(0);
    }

    pub fn truncate(&mut self, len: usize) {
        unsafe {
            if self.capacity > 0 {
                let mut i = len;
                while i < self.size {
                    *(self.p).offset(i as isize) = 0;
                    i += 1
                }
            }
        }
        self.size = len;
    }

    pub fn push(&mut self, s: u8) {
        let size = self.size;
        self.resize(size + 1);
        unsafe { *(self.p.offset(size as isize)) = s }
    }

    pub fn push_u32_be(&mut self, s: u32) {
        let size = self.size;
        self.resize(size + 4);
        unsafe { *(self.p.offset(size as isize) as *mut u32) = s.to_be() }
    }

    pub fn read_u32_be(&self, i: usize) -> u32 {
        assert!(i + 4 <= self.size);
        unsafe { u32::from_be(*(self.p.offset(i as isize) as *const u32)) }
    }

    // append n_bytes bytes at the end of this cryptobuf.
    pub fn read<R: std::io::Read>(&mut self,
                                  n_bytes: usize,
                                  r: &mut R)
                                  -> Result<usize, std::io::Error> {
        let cur_size = self.size;
        self.resize(cur_size + n_bytes);
        unsafe {
            let s = std::slice::from_raw_parts_mut(self.p.offset(cur_size as isize), n_bytes);
            r.read(s)
        }
    }

    pub fn write_all_from<W: std::io::Write>(&self,
                                             offset: usize,
                                             w: &mut W)
                                             -> Result<usize, std::io::Error> {
        assert!(offset < self.size);
        // if we're past this point, self.p cannot be null.
        unsafe {
            let s = std::slice::from_raw_parts(self.p.offset(offset as isize), self.size - offset);
            w.write(s)
        }
    }

    pub fn reserve(&mut self, n: usize) -> &mut [u8] {
        let size = self.size;
        self.resize(size + n);
        unsafe { std::slice::from_raw_parts_mut(self.p.offset(size as isize), n) }
    }

    pub fn extend(&mut self, s: &[u8]) {
        // println!("extend {:?}", s);
        let size = self.size;
        self.resize(size + s.len());
        // println!("{:?}", self);
        unsafe {
            std::ptr::copy_nonoverlapping(s.as_ptr(), self.p.offset(size as isize), s.len());
        }
    }

    pub fn hexdump(&self) {
        let mut buf = Vec::new();
        let mut i = 0;
        while i < self.len() {
            if i % 16 == 0 {
                print!("{:04}: ", i)
            }
            print!("{:02x} ", self[i]);
            if self[i] >= 0x20 && self[i] <= 0x7e {
                buf.push(self[i]);
            } else {
                buf.push(b'.');
            }
            if i % 16 == 15 || i == self.len() - 1 {
                while i % 16 != 15 {
                    print!("   ");
                    i += 1
                }
                println!(" {:?}", std::str::from_utf8(&buf));
                buf.clear();
            }
            i += 1
        }
    }
}

impl Drop for CryptoBuf {
    fn drop(&mut self) {
        if self.capacity > 0 {
            unsafe {
                // TODO: munlock(self.p as *mut c_void, self.size);
                free(self.p as *mut c_void)
            }
        }
    }
}
