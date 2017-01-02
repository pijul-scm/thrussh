extern crate futures;
extern crate env_logger;
extern crate tokio_core;
extern crate thrussh;
#[macro_use]
extern crate log;
use thrussh::*;
use thrussh::client::*;
use std::sync::Arc;
use std::net::ToSocketAddrs;
use futures::Future;
use tokio_core::net::TcpStream;
use tokio_core::reactor::Core;

fn run<H: Handler + 'static>(config: Arc<Config>, addr: &str, handler: H) {

    let addr = addr.to_socket_addrs().unwrap().next().unwrap();
    let mut l = Core::new().unwrap();
    let handle = l.handle();
    let done =
        TcpStream::connect(&addr, &handle)
            .map_err(|err| thrussh::HandlerError::Error(thrussh::Error::IO(err)))
            .and_then(|socket| {

                println!("connected");
                let connection = Connection::new(config.clone(), socket, handler, None)
                    .unwrap();

                let key = thrussh::load_secret_key("/home/pe/.ssh/id_ed25519").unwrap();
                connection.authenticate_key("pe", key).and_then(|connection| {

                    connection.channel_open_session().and_then(|(mut connection, chan)| {

                        if let Some(ref mut session) = connection.session {
                            session.data(chan, None, b"AAAAAA").unwrap();
                            session.data(chan, None, b"BBBBBB").unwrap();
                        }
                        connection

                    })
                })
            });
    l.run(done).unwrap();
}

struct H { }

impl Handler for H {
    type Error = ();
    type FutureBool = futures::Finished<(Self, bool), ()>;
    type FutureUnit = futures::Finished<Self, ()>;
    type SessionUnit = futures::Finished<(Self, Session), ()>;
    fn check_server_key(self, server_public_key: &key::PublicKey) -> Self::FutureBool {
        debug!("check_server_key: {:?}", server_public_key);
        futures::finished((self, true))
    }
    fn channel_open_confirmation(self,
                                 channel: ChannelId,
                                 session: Session)
                                 -> Self::SessionUnit {
        debug!("channel_open_confirmation: {:?}", channel);
        futures::finished((self, session))
    }
    fn data(self,
            channel: ChannelId,
            ext: Option<u32>,
            data: &[u8],
            session: Session)
            -> Self::SessionUnit {
        println!("data on channel {:?} {:?}: {:?}",
                 ext,
                 channel,
                 std::str::from_utf8(data));
        futures::finished((self, session))
    }
}

fn main() {
    env_logger::init().unwrap();
    let mut config = thrussh::client::Config::default();
    config.connection_timeout = Some(std::time::Duration::from_secs(600));
    let config = Arc::new(config);
    let sh = H {};
    run(config, "127.0.0.1:2222", sh);
}
