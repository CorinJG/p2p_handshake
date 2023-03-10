//! Attempt to establish handshake with the provided peer and exit.

use tokio::net::TcpStream;

use p2p_handshake::Peer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let peer_addr = args.next().expect("provide peer addr as first cli arg");
    let relax = match args.next() {
        Some(arg2) => {
            if arg2 == "relax" {
                true
            } else {
                panic!("the second cli arg is optional and may only be `relax`")
            }
        }
        None => false,
    };
    let stream = TcpStream::connect(&peer_addr).await?;
    let mut peer = Peer::new(stream, peer_addr.parse()?);
    match peer.establish_handshake(relax).await {
        Ok(_) => println!("success"),
        Err(e) => println!("error: {e}"),
    }
    Ok(())
}
