//! A handful of convenience functions for serializing and deserializing protocol messages
//! from the network, and the checksum function.

use std::net::SocketAddr;

use anyhow::bail;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::protocol::{Command, NetworkMessage, Payload, ProtocolMessage, VersionData, MAGIC};

/// Construct a Version message, containing the peer address in the `receiver` field.
pub fn construct_version_msg(receiver_addr: SocketAddr) -> NetworkMessage {
    NetworkMessage::Version(ProtocolMessage::new(
        MAGIC,
        Command::Version,
        Payload::Version(VersionData::default_from_addr_recv(receiver_addr)),
    ))
}

/// Construct a Verack message.
pub fn construct_verack_msg() -> NetworkMessage {
    NetworkMessage::Verack(ProtocolMessage::new(MAGIC, Command::Verack, Payload::Empty))
}

/// Send a NetworkMessage to the peer.
pub async fn send_network_msg(stream: &mut TcpStream, msg: NetworkMessage) -> anyhow::Result<()> {
    stream.write_all(&msg.to_bytes()?).await?;
    Ok(())
}

/// Read the next [NetworkMessage] from the stream.
pub async fn read_network_msg(stream: &mut TcpStream) -> anyhow::Result<NetworkMessage> {
    let mut buf = [0u8; 1024];
    let bytes_read = stream.read(&mut buf).await?;
    if bytes_read < 24 {
        bail!("insufficient bytes for protocol messages: {bytes_read}");
    }
    NetworkMessage::from_bytes(&buf)
}

/// Sha256 applied twice, then first 4 bytes taken as checksum:
/// https://developer.bitcoin.org/reference/p2p_networking.html#message-headers
pub(crate) fn checksum(payload: &[u8]) -> [u8; 4] {
    let mut hasher = Sha256::new();
    hasher.update(payload);
    let hash = hasher.finalize();

    let mut hasher = Sha256::new();
    hasher.update(hash);
    let hash = hasher.finalize();

    let mut buf = [0u8; 4];
    buf.copy_from_slice(&hash[..4]);

    buf
}
