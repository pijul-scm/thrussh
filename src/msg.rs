// https://tools.ietf.org/html/rfc4253#section-12
pub const DISCONNECT:u8 = 1;
pub const UNIMPLEMENTED:u8 = 2;
pub const DEBUG:u8 = 3;
pub const SERVICE_REQUEST:u8 = 4;
pub const SERVICE_ACCEPT:u8 = 5;
pub const KEXINIT:u8 = 20;
pub const NEWKEYS:u8 = 21;


// http://tools.ietf.org/html/rfc5656#section-7.1
pub const KEX_ECDH_INIT:u8 = 30;
pub const KEX_ECDH_REPLY:u8 = 31;
