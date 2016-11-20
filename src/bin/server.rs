extern crate thrussh;
extern crate env_logger;
extern crate futures;
use std::sync::{Arc, Mutex};
use thrussh::*;
use thrussh::server::*;
#[derive(Debug, Clone, Default)]
struct H(Arc<Mutex<HH>>);
#[derive(Debug, Default)]
struct HH {
    user: String,
    password: String,
}
x
impl thrussh::server::Handler for H {
    type FutureAuth = futures::Finished<Auth, Error>;
    type FutureUnit = futures::Finished<(), Error>;
    type FutureBool = futures::Finished<bool, Error>;

    fn auth_password(&mut self, user: &str, password: &str) -> Self::FutureBool {
        let mut h = self.0.lock().unwrap();
        h.user.push_str(user);
        h.password.clear();
        h.password.push_str(password);
        futures::finished(true)
    }
    fn auth_keyboard_interactive(&mut self, user: &str, submethods: &str, response: Option<thrussh::server::Response>) -> Self::FutureAuth {
        println!("\n\n======================\n\nuser {:?} {:?}\n\n", user, response);
        if let Some(mut resp) = response {

            for resp in resp {
                println!("resp: {:?}", resp)
            }
            futures::finished(Auth::Accept)

        } else {

            futures::finished(Auth::Partial {
                name: "name".to_string(),
                instructions: "type your password".to_string(),
                prompts: vec![("Password: ".to_string(), false)]
            })
        }
    }

    fn auth_none(&mut self, user: &str) -> Self::FutureBool {
        futures::finished(false)
    }

    fn auth_publickey(&mut self, user: &str, public_key: &key::PublicKey) -> Self::FutureBool {
        futures::finished(false)
    }

    fn channel_close(&mut self, channel: u32, session: &mut Session) -> Self::FutureUnit {
        futures::finished(())
    }

    fn channel_eof(&mut self, channel: u32, session: &mut Session) -> Self::FutureUnit {
        futures::finished(())
    }

    fn channel_open_session(&mut self, channel: u32, session: &mut Session) -> Self::FutureUnit {
        futures::finished(())
    }
    fn channel_open_x11(&mut self,
                        channel: u32,
                        originator_address: &str,
                        originator_port: u32,
                        session: &mut Session)
                        -> Self::FutureUnit {
        futures::finished(())
    }

    fn channel_open_direct_tcpip(&mut self,
                                 channel: u32,
                                 host_to_connect: &str,
                                 port_to_connect: u32,
                                 originator_address: &str,
                                 originator_port: u32,
                                 session: &mut Session)
                                 -> Self::FutureUnit {
        futures::finished(())
    }

    fn data(&mut self, channel: u32, data: &[u8], session: &mut Session) -> Self::FutureUnit {
        futures::finished(())
    }

    fn extended_data(&mut self, channel: u32, code: u32, data: &[u8], session: &mut Session) -> Self::FutureUnit {
        futures::finished(())
    }

    fn window_adjusted(&mut self, channel: u32, session: &mut Session) -> Self::FutureUnit {
        futures::finished(())
    }

    fn pty_request(&mut self,
                   channel: u32,
                   term: &str,
                   col_width: u32,
                   row_height: u32,
                   pix_width: u32,
                   pix_height: u32,
                   modes: &[(Pty, u32)],
                   session: &mut Session)
                   -> Self::FutureUnit {
        futures::finished(())
    }

    fn x11_request(&mut self,
                   channel: u32,
                   single_connection: bool,
                   x11_auth_protocol: &str,
                   x11_auth_cookie: &str,
                   x11_screen_number: u32,
                   session: &mut Session)
                   -> Self::FutureUnit {
        futures::finished(())
    }

    fn env_request(&mut self,
                   channel: u32,
                   variable_name: &str,
                   variable_value: &str,
                   session: &mut Session)
                   -> Self::FutureUnit {
        futures::finished(())
    }

    fn shell_request(&mut self, channel: u32, session: &mut Session) -> Self::FutureUnit {
        futures::finished(())
    }

    fn exec_request(&mut self, channel: u32, data: &[u8], session: &mut Session) -> Self::FutureUnit {
        futures::finished(())
    }

    fn subsystem_request(&mut self, channel: u32, name: &str, session: &mut Session) -> Self::FutureUnit {
        futures::finished(())
    }

    fn window_change_request(&mut self,
                             channel: u32,
                             col_width: u32,
                             row_height: u32,
                             pix_width: u32,
                             pix_height: u32,
                             session: &mut Session)
                             -> Self::FutureUnit {
        futures::finished(())
    }

    fn signal(&mut self, channel: u32, signal_name: Sig, session: &mut Session) -> Self::FutureUnit {
        futures::finished(())
    }

    fn tcpip_forward(&mut self, address: &str, port: u32, session: &mut Session) -> Self::FutureBool {
        futures::finished(true)
    }

    fn cancel_tcpip_forward(&mut self, address: &str, port: u32, session: &mut Session) -> Self::FutureBool {
        futures::finished(true)
    }
}


fn main() {
    env_logger::init().unwrap();
    let mut config = thrussh::server::Config::default();
    config.connection_timeout = Some(std::time::Duration::from_secs(600));
    config.keys.push(thrussh::load_secret_key("ssh_host_ed25519_key").unwrap());
    let config = Arc::new(config);
    let sh = H::default();
    thrussh::server::run(config, "0.0.0.0:2222", sh);
}
