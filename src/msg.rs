// https://tools.ietf.org/html/rfc4253#section-12
pub const DISCONNECT:u8 = 1;
pub const IGNORE:u8 = 2;
pub const UNIMPLEMENTED:u8 = 3;
pub const DEBUG:u8 = 4;
pub const SERVICE_REQUEST:u8 = 5;
pub const SERVICE_ACCEPT:u8 = 6;
pub const KEXINIT:u8 = 20;
pub const NEWKEYS:u8 = 21;


// http://tools.ietf.org/html/rfc5656#section-7.1
pub const KEX_ECDH_INIT:u8 = 30;
pub const KEX_ECDH_REPLY:u8 = 31;


pub const USERAUTH_REQUEST:u8 = 50;
pub const USERAUTH_FAILURE:u8 = 51;
pub const USERAUTH_SUCCESS:u8 = 52;
pub const USERAUTH_BANNER:u8 = 53;



// https://tools.ietf.org/html/rfc4250#section-4.1.2
/*
         SSH_MSG_DISCONNECT                       1     [SSH-TRANS]
         SSH_MSG_IGNORE                           2     [SSH-TRANS]
         SSH_MSG_UNIMPLEMENTED                    3     [SSH-TRANS]
         SSH_MSG_DEBUG                            4     [SSH-TRANS]
         SSH_MSG_SERVICE_REQUEST                  5     [SSH-TRANS]
         SSH_MSG_SERVICE_ACCEPT                   6     [SSH-TRANS]
         SSH_MSG_KEXINIT                         20     [SSH-TRANS]
         SSH_MSG_NEWKEYS                         21     [SSH-TRANS]

         SSH_MSG_USERAUTH_REQUEST                50     [SSH-USERAUTH]
         SSH_MSG_USERAUTH_FAILURE                51     [SSH-USERAUTH]
         SSH_MSG_USERAUTH_SUCCESS                52     [SSH-USERAUTH]
         SSH_MSG_USERAUTH_BANNER                 53     [SSH-USERAUTH]

         SSH_MSG_GLOBAL_REQUEST                  80     [SSH-CONNECT]
         SSH_MSG_REQUEST_SUCCESS                 81     [SSH-CONNECT]
         SSH_MSG_REQUEST_FAILURE                 82     [SSH-CONNECT]
         SSH_MSG_CHANNEL_OPEN                    90     [SSH-CONNECT]
         SSH_MSG_CHANNEL_OPEN_CONFIRMATION       91     [SSH-CONNECT]
         SSH_MSG_CHANNEL_OPEN_FAILURE            92     [SSH-CONNECT]
         SSH_MSG_CHANNEL_WINDOW_ADJUST           93     [SSH-CONNECT]
         SSH_MSG_CHANNEL_DATA                    94     [SSH-CONNECT]
         SSH_MSG_CHANNEL_EXTENDED_DATA           95     [SSH-CONNECT]
         SSH_MSG_CHANNEL_EOF                     96     [SSH-CONNECT]
         SSH_MSG_CHANNEL_CLOSE                   97     [SSH-CONNECT]
         SSH_MSG_CHANNEL_REQUEST                 98     [SSH-CONNECT]
         SSH_MSG_CHANNEL_SUCCESS                 99     [SSH-CONNECT]
         SSH_MSG_CHANNEL_FAILURE                100     [SSH-CONNECT]
*/
