//! Listens for incoming connections and attempts to establish handshake ad infinitum,
//! dropping connections which complete handshake successfully.

use std::time::Duration;

use futures::stream::FuturesUnordered;
use futures::StreamExt;
use tokio::net::TcpListener;
use tokio::time::timeout;

use bitcoin_handshake::Peer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let relax = match std::env::args().skip(1).next() {
        Some(arg2) => {
            if arg2 == "relax" {
                true
            } else {
                panic!("the second cli arg is optional and may only be `relax`")
            }
        }
        None => false,
    };
    let listener = TcpListener::bind("0.0.0.0:8333").await?;
    let mut peers = FuturesUnordered::new();
    loop {
        tokio::select! {
            listen_result = listener.accept() => {
                match listen_result {
                    Ok((stream, addr)) => {
                        println!("new tcp connection from: {addr:?}");
                        let mut peer = Peer::new(stream, addr);
                        peers.push(async move {
                            if timeout(
                                Duration::from_secs(2),
                                peer.establish_handshake(relax)
                            ).await.is_err() {
                                println!("peer timed out before handshake complete: {addr:?}");
                            }
                        });
                   },
                   Err(e) => eprintln!("error accepting tcp connection: {e}"),
                }
            },
            _ = peers.next() => (),
        }
    }
}
