extern crate thrussh;
extern crate futures;
extern crate tokio_core;
extern crate env_logger;
#[macro_use]
extern crate log;
use std::sync::Arc;
use thrussh::*;

#[derive(Clone)]
struct H {}

impl server::Handler for H {
    type Error = ();
    type FutureAuth = futures::Finished<(Self, server::Auth), ()>;
    type FutureUnit = futures::Finished<(Self, server::Session), ()>;
    type FutureBool = futures::Finished<(Self, server::Session, bool), ()>;

    fn auth_publickey(self, _: &str, _: &key::PublicKey) -> Self::FutureAuth {
        futures::finished((self, server::Auth::Accept))
    }
    fn data(self,
            channel: ChannelId,
            data: &[u8],
            mut session: server::Session)
            -> Self::FutureUnit {
        println!("data on channel {:?}: {:?}",
                 channel,
                 std::str::from_utf8(data));
        session.data(channel, None, data).unwrap();
        futures::finished((self, session))
    }
}


use std::net::ToSocketAddrs;
use futures::Future;
use tokio_core::net::TcpStream;
use tokio_core::reactor::Core;


struct Client { }
impl client::Handler for Client {
    type Error = ();
    type FutureBool = futures::Finished<(Self, bool), ()>;
    type FutureUnit = futures::Finished<Self, ()>;
    type SessionUnit = futures::Finished<(Self, client::Session), ()>;
    fn check_server_key(self, server_public_key: &key::PublicKey) -> Self::FutureBool {
        debug!("check_server_key: {:?}", server_public_key);
        futures::finished((self, true))
    }
    fn channel_open_confirmation(self,
                                 channel: ChannelId,
                                 session: client::Session)
                                 -> Self::SessionUnit {
        debug!("channel_open_confirmation: {:?}", channel);
        futures::finished((self, session))
    }
    fn data(self,
            channel: ChannelId,
            ext: Option<u32>,
            data: &[u8],
            session: client::Session)
            -> Self::SessionUnit {
        println!("data on channel {:?} {:?}: {:?}",
                 ext,
                 channel,
                 std::str::from_utf8(data));
        futures::finished((self, session))
    }
}

impl Client {
    fn run(self, config: Arc<client::Config>, addr: &str) {

        let addr = addr.to_socket_addrs().unwrap().next().unwrap();
        let mut l = Core::new().unwrap();
        let handle = l.handle();
        let done = TcpStream::connect(&addr, &handle)
            .map_err(|err| thrussh::HandlerError::Error(thrussh::Error::IO(err)))
            .and_then(|socket| {

                println!("connected");
                let connection = client::Connection::new(config.clone(), socket, self, None)
                    .unwrap();

                let key = thrussh::load_secret_key("/home/pe/.ssh/id_ed25519").unwrap();

                connection.authenticate_key("pe", key).and_then(|connection| {

                    connection.channel_open_session().and_then(|(mut connection, chan)| {
                        if let Some(ref mut s) = connection.session {
                            s.data(chan, None, b"First test").unwrap();
                            s.data(chan, None, b"Second test").unwrap();
                            s.disconnect(Disconnect::ByApplication, "Ciao", "");
                        }
                        connection
                    })
                })
            });
        l.run(done).unwrap();
    }
}

fn main() {
    env_logger::init().unwrap();
    // Starting the server thread.
    let t = std::thread::spawn(|| {
        let mut config = thrussh::server::Config::default();
        config.connection_timeout = Some(std::time::Duration::from_secs(600));
        config.auth_rejection_time = std::time::Duration::from_secs(3);
        config.keys.push(thrussh::key::Algorithm::generate_keypair(thrussh::key::ED25519).unwrap());
        let config = Arc::new(config);
        let h = H {};
        thrussh::server::run::<H>(config, "0.0.0.0:2222", h);
    });

    std::thread::sleep(std::time::Duration::from_secs(1));
    let mut config = thrussh::client::Config::default();
    config.connection_timeout = Some(std::time::Duration::from_secs(600));
    let config = Arc::new(config);
    let sh = Client {};
    sh.run(config, "127.0.0.1:2222");

    // Kill the server thread after the client has ended.
    std::mem::forget(t)
}
