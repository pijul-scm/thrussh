extern crate thrussh;
extern crate env_logger;
extern crate futures;
#[macro_use]
extern crate log;
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
    fn auth_keyboard_interactive(&mut self, user: &str, _: &str, response: Option<thrussh::server::Response>) -> Self::FutureAuth {
        println!("Keyboard interactive, user {:?}", user);
        if let Some(resp) = response {

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

    fn auth_publickey(&mut self, user: &str, public_key: &key::PublicKey) -> Self::FutureBool {
        debug!("publickey request by user {:?}, pub {:?}", user, public_key);
        futures::finished(true)
    }

    fn data(&mut self, channel: ChannelId, data: &[u8], session: &mut Session) -> Self::FutureUnit {
        println!("data on channel {:?}: {:?}", channel, std::str::from_utf8(data));
        session.data(channel, None, data).unwrap();
        futures::finished(())
    }
}


fn main() {
    env_logger::init().unwrap();
    let mut config = thrussh::server::Config::default();
    config.connection_timeout = Some(std::time::Duration::from_secs(600));
    config.auth_rejection_time = std::time::Duration::from_secs(3);
    config.keys.push(thrussh::load_secret_key("ssh_host_ed25519_key").unwrap());
    let config = Arc::new(config);
    let sh = H::default();
    thrussh::server::run(config, "0.0.0.0:2222", sh);
}
