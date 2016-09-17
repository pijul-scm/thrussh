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

// Some parts of this module come from sodiumoxide, (c) 2013 Daniel Ashhami, under an MIT licence.

use super::libsodium_sys;
pub fn init() -> bool {
    unsafe { libsodium_sys::sodium_init() != -1 }
}

use super::libc::{size_t, c_void};

extern "C" {
    pub fn sodium_mlock(p: *mut c_void, len: size_t);
    pub fn sodium_munlock(p: *mut c_void, len: size_t);
}
