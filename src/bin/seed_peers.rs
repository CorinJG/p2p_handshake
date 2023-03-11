//! Attempt to establish handshake with every peer in a DNS seed loopkup, printing results
//! to stdout.
//!
//! Without the `relax` CLI arg, the majority of targets will timeout waiting for Verack.
//!  
//! (Note that if all IPv6 peers fail, it could suggest incorrect device configuration
//! e.g. no default gateway.)

use std::net::SocketAddr;

use anyhow::bail;
use futures::future::join_all;
use tokio::net::{lookup_host, TcpStream};

use p2p_handshake::Peer;

async fn attempt_handshake(peer_addr: &SocketAddr, relax: bool) -> anyhow::Result<()> {
    let stream = match TcpStream::connect(&peer_addr).await {
        Ok(stream) => stream,
        Err(e) => {
            bail!("error connecting to {peer_addr} - tcp failure - {e}");
        }
    };
    let mut peer = Peer::new(stream, *peer_addr);
    peer.establish_handshake(relax)
        .await
        .map(|v| {
            println!("{peer_addr}: success!\n");
            v
        })
        .map_err(|e| {
            println!("{peer_addr}: failure - {e}\n");
            e
        })
}

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
    let peer_addrs = lookup_host("seed.bitcoin.sipa.be:8333")
        .await?
        .collect::<Vec<_>>();
    let results = join_all(
        peer_addrs
            .iter()
            .map(|peer_addr| attempt_handshake(peer_addr, relax)),
    )
    .await;
    let successes = results.iter().filter(|r| r.is_ok()).count();
    let failures = results.iter().filter(|r| r.is_err()).count();
    let total = successes + failures;
    println!("\nResults:\nsuccesses: {successes}\nfailures: {failures}\ntotal: {total}");
    Ok(())
}
