extern crate thrussh;
extern crate env_logger;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Default)]
struct H(Arc<Mutex<HH>>);
#[derive(Debug, Default)]
struct HH {
    user: String,
    password: String,
}

impl thrussh::server::Handler for H {
    fn auth_password(&mut self, user: &str, password: &str) -> bool {
        let mut h = self.0.lock().unwrap();
        h.user.push_str(user);
        h.password.clear();
        h.password.push_str(password);
        true
    }
    fn auth_keyboard_interactive(&mut self, user: &str, submethods: &str, ki: &mut thrussh::server::KeyboardInteractive, response: Option<thrussh::server::Response>) -> bool {

        if let Some(mut resp) = response {

            for resp in resp {
                println!("resp: {:?}", resp)
            }
            true

        } else {

            ki.prompt("Password: ", false);
            false

        }
    }
}
impl thrussh::client::Handler for H {
    fn check_server_key(&mut self, server_public_key: &thrussh::key::PublicKey) -> Result<bool, thrussh::Error> {
        // This function returns false by default.
        Ok(true)
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
