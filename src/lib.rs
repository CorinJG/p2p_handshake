//! Types and methods for establishing handshakes with connected peers.

pub mod protocol;
pub(crate) mod util;

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::anyhow;
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::protocol::NetworkMessage;
use crate::util::{
    construct_verack_msg, construct_version_msg, read_network_msg, send_network_msg,
};

/// A connected peer.
pub struct Peer {
    stream: TcpStream,
    addr: SocketAddr,
    handshake: Handshake,
}

/// Represents the progress of the handshake.
/// We send our version as soon as the tcp connection is established.
/// Handles both cases where peer sends Version-Verack as well as Verack-Version.
enum Handshake {
    /// Before we have received a peer's Version or Verack.
    Init,
    /// Have received peer's Version, awaiting Verack.
    ReceivedVersion,
    /// Received peer's Verack, awaiting Version.
    ReceivedVerack,
    /// Both version messages exchanged, we have received peer's Verack. Handshake complete.
    Complete,
}
use Handshake::*;

impl Peer {
    pub fn new(stream: TcpStream, addr: SocketAddr) -> Self {
        Self {
            stream,
            addr,
            handshake: Handshake::Init,
        }
    }

    /// Attempt to establish a handshake.
    /// If the `relax` flag is set to true, accept partial handshakes as success (peer neglects to
    /// send Verack in response to our Version message).
    ///
    /// Whether we or the peer initiated the connection, begin by sending our Version message.
    ///
    /// Await peer's Version message, responding with Verack. Also intercept Verack of our Version
    /// message.
    ///  
    /// Discard other message types received during handshake.
    ///
    /// ## Errors
    /// Error if error sending network messages to peer.
    /// Error if reading next network message fails (error deserializing etc).
    /// Timeout error awaiting a Verack in response to our Version message.
    pub async fn establish_handshake(&mut self, relax: bool) -> anyhow::Result<()> {
        send_network_msg(&mut self.stream, construct_version_msg(self.addr)).await?;
        timeout(Duration::from_secs(3), self._handshake_inner(relax))
            .await
            .map_err(|_| anyhow!("timeout awaiting verack"))?
    }

    /// To neaten up the timeout logic, place the inner block of establish_timeout in a separate fn.
    async fn _handshake_inner(&mut self, relax: bool) -> anyhow::Result<()> {
        loop {
            match read_network_msg(&mut self.stream).await? {
                NetworkMessage::Version(_version_msg) => {
                    println!("received `version` ({}): {_version_msg:?}", self.addr);
                    // respond with verack
                    send_network_msg(&mut self.stream, construct_verack_msg()).await?;
                    match self.handshake {
                        Init => {
                            if relax {
                                self.handshake = Complete;
                                return Ok(());
                            } else {
                                self.handshake = ReceivedVersion;
                            }
                        }
                        ReceivedVerack => {
                            self.handshake = Complete;
                            return Ok(());
                        }
                        _ => (),
                    }
                }
                NetworkMessage::Verack(_) => match self.handshake {
                    Init => {
                        self.handshake = ReceivedVerack;
                    }
                    ReceivedVersion => {
                        self.handshake = Complete;
                        return Ok(());
                    }
                    _ => (),
                },
                _other => {
                    // unexpected message type
                    // println!("unexpected msg type ({}): `{other:?}`", self.addr);
                }
            }
        }
    }
}
