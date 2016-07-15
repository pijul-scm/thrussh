use pty;
use super::ChannelParameters;
use cryptobuf::CryptoBuf;
use msg;

pub trait Req {
    fn req(&self, channel:&ChannelParameters, buffer:&mut CryptoBuf);
}

pub struct Pty<'a> {
    pub want_reply: bool,
    pub term: &'a str,
    pub col_width: u32,
    pub row_height: u32,
    pub pix_width: u32,
    pub pix_height: u32,
    pub terminal_modes: &'a [(pty::Option, u32)]
}

impl<'a> Req for Pty<'a> {
    fn req(&self, channel:&ChannelParameters, buffer:&mut CryptoBuf) {

        push_packet!(buffer,{
            buffer.push(msg::CHANNEL_REQUEST);

            buffer.push_u32_be(channel.recipient_channel);
            buffer.extend_ssh_string(b"pty-req");
            buffer.push(if self.want_reply { 1 } else { 0 });
            buffer.extend_ssh_string(self.term.as_bytes());
            buffer.push_u32_be(self.col_width);
            buffer.push_u32_be(self.row_height);
            buffer.push_u32_be(self.pix_width);
            buffer.push_u32_be(self.pix_height);

            buffer.push_u32_be((5 * self.terminal_modes.len()) as u32);
            for &(pty::Option(code), value) in self.terminal_modes {
                buffer.push(code);
                buffer.push_u32_be(value)
            }
            buffer.push(0);
            buffer.push_u32_be(0);
        })
    }
}

pub struct X11<'a> {
    pub want_reply: bool,
    pub single_connection: bool,
    pub x11_authentication_protocol: &'a str,
    pub x11_authentication_cookie: &'a str,
    pub x11_screen_number: u32
}


impl<'a> Req for X11<'a> {
    fn req(&self, channel:&ChannelParameters, buffer:&mut CryptoBuf) {
        push_packet!(buffer, {
            buffer.push(msg::CHANNEL_REQUEST);

            buffer.push_u32_be(channel.recipient_channel);
            buffer.extend_ssh_string(b"x11-req");
            buffer.push(if self.want_reply { 1 } else { 0 });
            buffer.push(if self.single_connection { 1 } else { 0 });
            buffer.extend_ssh_string(self.x11_authentication_protocol.as_bytes());
            buffer.extend_ssh_string(self.x11_authentication_cookie.as_bytes());
            buffer.push_u32_be(self.x11_screen_number);
        })
    }
}



pub struct Env<'a> {
    pub want_reply: bool,
    pub variable_name: &'a str,
    pub variable_value: &'a str,
}

impl<'a> Req for Env<'a> {
    fn req(&self, channel:&ChannelParameters, buffer:&mut CryptoBuf) {
        push_packet!(buffer, {
            buffer.push(msg::CHANNEL_REQUEST);

            buffer.push_u32_be(channel.recipient_channel);
            buffer.extend_ssh_string(b"env");
            buffer.push(if self.want_reply { 1 } else { 0 });
            buffer.extend_ssh_string(self.variable_name.as_bytes());
            buffer.extend_ssh_string(self.variable_value.as_bytes());
        })
    }
}

pub struct Shell {
    pub want_reply: bool,
}

impl Req for Shell {
    fn req(&self, channel:&ChannelParameters, buffer:&mut CryptoBuf) {

        push_packet!(buffer, {
            buffer.push(msg::CHANNEL_REQUEST);

            buffer.push_u32_be(channel.recipient_channel);
            buffer.extend_ssh_string(b"shell");
            buffer.push(if self.want_reply { 1 } else { 0 });
        })
    }
}

pub struct Exec<'a> {
    pub want_reply: bool,
    pub command:&'a str
}
impl<'a> Req for Exec<'a> {
    fn req(&self, channel:&ChannelParameters, buffer:&mut CryptoBuf) {

        push_packet!(buffer, {
            buffer.push(msg::CHANNEL_REQUEST);

            buffer.push_u32_be(channel.recipient_channel);
            buffer.extend_ssh_string(b"exec");
            buffer.push(if self.want_reply { 1 } else { 0 });
            buffer.extend_ssh_string(self.command.as_bytes());
        })
    }
}

pub struct Subsystem<'a> {
    pub want_reply: bool,
    pub name:&'a str
}
impl<'a> Req for Subsystem<'a> {
    fn req(&self, channel:&ChannelParameters, buffer:&mut CryptoBuf) {
        push_packet!(buffer, {
            buffer.push(msg::CHANNEL_REQUEST);

            buffer.push_u32_be(channel.recipient_channel);
            buffer.extend_ssh_string(b"subsystem");
            buffer.push(if self.want_reply { 1 } else { 0 });
            buffer.extend_ssh_string(self.name.as_bytes());
        })
    }
}


pub struct WindowChange {
    col_width: u32,
    row_height: u32,
    pix_width: u32,
    pix_height: u32
}
impl Req for WindowChange {
    fn req(&self, channel:&ChannelParameters, buffer:&mut CryptoBuf) {
        push_packet!(buffer, {
            buffer.push(msg::CHANNEL_REQUEST);

            buffer.push_u32_be(channel.recipient_channel);
            buffer.extend_ssh_string(b"window-change");
            buffer.push(0);
            buffer.push_u32_be(self.col_width);
            buffer.push_u32_be(self.row_height);
            buffer.push_u32_be(self.pix_width);
            buffer.push_u32_be(self.pix_height);
        })
    }
}

pub struct XonXoff {
    client_can_do: bool
}
impl Req for XonXoff {
    fn req(&self, channel:&ChannelParameters, buffer:&mut CryptoBuf) {
        push_packet!(buffer, {
            buffer.push(msg::CHANNEL_REQUEST);

            buffer.push_u32_be(channel.recipient_channel);
            buffer.extend_ssh_string(b"xon-xoff");
            buffer.push(0);
            buffer.push(if self.client_can_do { 1 } else { 0 });
        })
    }
}

pub struct ExitStatus {
    exit_status: u32
}
impl Req for ExitStatus {
    fn req(&self, channel:&ChannelParameters, buffer:&mut CryptoBuf) {
        push_packet!(buffer, {
            buffer.push(msg::CHANNEL_REQUEST);

            buffer.push_u32_be(channel.recipient_channel);
            buffer.extend_ssh_string(b"exit-status");
            buffer.push(0);
            buffer.push_u32_be(self.exit_status)
        })
    }
}


pub struct SignalName<'a>(&'a str);

pub const SIGABRT: SignalName<'static> = SignalName("ABRT");
pub const SIGALRM: SignalName<'static> = SignalName("ALRM");
pub const SIGFPE: SignalName<'static> = SignalName("FPE");
pub const SIGHUP: SignalName<'static> = SignalName("HUP");
pub const SIGILL: SignalName<'static> = SignalName("ILL");
pub const SIGINT: SignalName<'static> = SignalName("INT");
pub const SIGKILL: SignalName<'static> = SignalName("KILL");
pub const SIGPIPE: SignalName<'static> = SignalName("PIPE");
pub const SIGQUIT: SignalName<'static> = SignalName("QUIT");
pub const SIGSEGV: SignalName<'static> = SignalName("SEGV");
pub const SIGTERM: SignalName<'static> = SignalName("TERM");
pub const SIGUSR1: SignalName<'static> = SignalName("USR1");

impl<'a> SignalName<'a> {
    fn other(name: &'a str) -> SignalName<'a> {
        SignalName(name)
    }
}

pub struct ExitSignal<'a> {
    signal_name: SignalName<'a>,
    core_dumped: bool,
    error_message: &'a str,
    language_tag: &'a str
}

impl<'a> ExitSignal<'a> {
    fn req(&self, channel:&ChannelParameters, buffer:&mut CryptoBuf) {
        push_packet!(buffer, {
            buffer.push(msg::CHANNEL_REQUEST);

            buffer.push_u32_be(channel.recipient_channel);
            buffer.extend_ssh_string(b"exit-signal");
            buffer.push(0);
            buffer.extend_ssh_string(self.signal_name.0.as_bytes());
            buffer.push(if self.core_dumped { 1 } else { 0 });
            buffer.extend_ssh_string(self.error_message.as_bytes());
            buffer.extend_ssh_string(self.language_tag.as_bytes());
        })
    }
}
