use cryptobuf::CryptoBuf;
use msg;

pub struct TcpipForward<'a> {
    want_reply: bool,
    address_to_bind: &'a str,
    port_to_bind: u32,
}

impl<'a> TcpipForward<'a> {
    pub fn req(&mut self, buffer: &mut CryptoBuf) {
        buffer.clear();
        buffer.push(msg::GLOBAL_REQUEST);

        buffer.extend_ssh_string(b"tcpip-forward");
        buffer.push(if self.want_reply {
            1
        } else {
            0
        });
        buffer.extend_ssh_string(self.address_to_bind.as_bytes());
        buffer.push_u32_be(self.port_to_bind);
    }
}

pub struct CancelTcpipForward<'a> {
    want_reply: bool,
    address_to_bind: &'a str,
    port_to_bind: u32,
}

impl<'a> CancelTcpipForward<'a> {
    pub fn req(&mut self, buffer: &mut CryptoBuf) {
        buffer.clear();
        buffer.push(msg::GLOBAL_REQUEST);

        buffer.extend_ssh_string(b"cancel-tcpip-forward");
        buffer.push(if self.want_reply {
            1
        } else {
            0
        });
        buffer.extend_ssh_string(self.address_to_bind.as_bytes());
        buffer.push_u32_be(self.port_to_bind);
    }
}
