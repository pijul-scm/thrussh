// https://tools.ietf.org/html/rfc4253#section-12
#[allow(dead_code)]
pub const DISCONNECT:u8 = 1;
#[allow(dead_code)]
pub const IGNORE:u8 = 2;
#[allow(dead_code)]
pub const UNIMPLEMENTED:u8 = 3;
#[allow(dead_code)]
pub const DEBUG:u8 = 4;

pub const SERVICE_REQUEST:u8 = 5;
pub const SERVICE_ACCEPT:u8 = 6;
pub const KEXINIT:u8 = 20;
pub const NEWKEYS:u8 = 21;


// http://tools.ietf.org/html/rfc5656#section-7.1
#[allow(dead_code)]
pub const KEX_ECDH_INIT:u8 = 30;
#[allow(dead_code)]
pub const KEX_ECDH_REPLY:u8 = 31;


// https://tools.ietf.org/html/rfc4250#section-4.1.2
#[allow(dead_code)]
pub const USERAUTH_REQUEST:u8 = 50;
#[allow(dead_code)]
pub const USERAUTH_FAILURE:u8 = 51;
#[allow(dead_code)]
pub const USERAUTH_SUCCESS:u8 = 52;
#[allow(dead_code)]
pub const USERAUTH_BANNER:u8 = 53;
#[allow(dead_code)]
pub const USERAUTH_PK_OK:u8 = 60;

// https://tools.ietf.org/html/rfc4254#section-9
#[allow(dead_code)]
pub const GLOBAL_REQUEST:u8 = 80;
#[allow(dead_code)]
pub const REQUEST_SUCCESS:u8 = 81;
#[allow(dead_code)]
pub const REQUEST_FAILURE:u8 = 82;

#[allow(dead_code)]
pub const CHANNEL_OPEN:u8 = 90;
#[allow(dead_code)]
pub const CHANNEL_OPEN_CONFIRMATION:u8 = 91;
#[allow(dead_code)]
pub const CHANNEL_OPEN_FAILURE:u8 = 92;
#[allow(dead_code)]
pub const CHANNEL_WINDOW_ADJUST:u8 = 93;
#[allow(dead_code)]
pub const CHANNEL_DATA:u8 = 94;
#[allow(dead_code)]
pub const CHANNEL_EXTENDED_DATA:u8 = 95;
#[allow(dead_code)]
pub const CHANNEL_EOF:u8 = 96;
#[allow(dead_code)]
pub const CHANNEL_CLOSE:u8 = 97;
#[allow(dead_code)]
pub const CHANNEL_REQUEST:u8 = 98;
#[allow(dead_code)]
pub const CHANNEL_SUCCESS:u8 = 99;
#[allow(dead_code)]
pub const CHANNEL_FAILURE:u8 = 100;
