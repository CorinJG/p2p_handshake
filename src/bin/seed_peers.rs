//! Attempt to establish handshake with every peer in the list of nodes returned in a
//! DNS seed loopkup, printing results to stdout in series.
//!
//! Without the `relax` CLI arg, the majority of targets will timeout waiting for Verack.
//!  
//! (Note that if all IPv6 peers fail, it could suggest incorrect device configuration
//! e.g. no default gateway.)

use tokio::net::{lookup_host, TcpStream};

use p2p_handshake::Peer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
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
    let resolved_addrs = lookup_host("seed.bitcoin.sipa.be:8333").await?;
    for addr in resolved_addrs {
        let stream = match TcpStream::connect(&addr).await {
            Ok(stream) => stream,
            Err(e) => {
                println!("{addr}: error connecting (tcp rejected) {e}");
                continue;
            }
        };
        let mut peer = Peer::new(stream, addr);
        match peer.establish_handshake(relax).await {
            Ok(_) => {
                println!("{addr}: success")
            }
            Err(e) => {
                println!("{addr}: error - {e}")
            }
        }
    }
    Ok(())
}
