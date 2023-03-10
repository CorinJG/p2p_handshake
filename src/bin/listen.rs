//! Listens for incoming connections and attempts to establish handshake on each,
//! dropping connections when they complete handshake or fail.

use tokio::net::TcpListener;

use p2p_handshake::Peer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let relax = match std::env::args().nth(1) {
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
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                println!("new tcp connection from: {addr:?}");
                let mut peer = Peer::new(stream, addr);
                tokio::spawn(async move { peer.establish_handshake(relax).await });
            }
            Err(e) => eprintln!("error accepting tcp connection: {e}"),
        }
    }
}
