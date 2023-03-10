//! Types for (de)serializing Bitcoin messages for the wire.
//! All fields are little-endian apart from addresses and ports.
//!
//! The standard format for all message types is outlined here: [`Bitcoin Protocol: Message Headers`]
//!
//! [`Bitcoin Protocol: Message Headers`]: https://developer.bitcoin.org/reference/p2p_networking.html#message-headers

use std::io::{Cursor, Read};
use std::net::{IpAddr::*, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::bail;
use byteorder::{BigEndian, LittleEndian, ReadBytesExt, WriteBytesExt};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Magic identifies the network. We'll use the Mainnet.
pub const MAGIC: [u8; 4] = [0xF9, 0xBE, 0xB4, 0xD9];
/// version of the protocol.
pub const VERSION: i32 = 70015;

/// Internal data type for a wire message payload. We are only concerned with Version here.
#[derive(Debug)]
enum Payload {
    /// Version message.
    Version(VersionData),
    Empty,
}

impl Payload {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        Ok(match self {
            Payload::Version(data) => data.to_bytes()?,
            Payload::Empty => vec![],
        })
    }

    fn from_bytes(bytes: impl Read, command: &Command) -> anyhow::Result<Self> {
        match command {
            Command::Version => Ok(Payload::Version(VersionData::from_bytes(bytes)?)),
            _ => Ok(Payload::Empty),
        }
    }
}

/// The payload data fields of a Version message.
#[derive(Debug)]
pub struct VersionData {
    version: i32,
    services: u64,
    timestamp: i64,
    addr_recv: VersionNetworkAddress,
    addr_from: VersionNetworkAddress,
    nonce: u64,
    user_agent: String,
    start_height: i32,
    relay: bool,
}

impl VersionData {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        // since Version messages omit the timestamp field of `addr_recv` and `addr_from`, the
        // only unknown field size is `user_agent` - other fields sum to 77
        let mut buf = Vec::with_capacity(77 + self.user_agent.len());
        WriteBytesExt::write_i32::<LittleEndian>(&mut buf, self.version)?;
        WriteBytesExt::write_u64::<LittleEndian>(&mut buf, self.services)?;
        WriteBytesExt::write_i64::<LittleEndian>(&mut buf, self.timestamp)?;
        self.addr_recv.write_to_buffer(&mut buf)?;
        self.addr_from.write_to_buffer(&mut buf)?;
        WriteBytesExt::write_u64::<LittleEndian>(&mut buf, self.nonce)?;
        WriteBytesExt::write_u8(&mut buf, self.user_agent.len() as u8)?;
        buf.extend(self.user_agent.as_bytes());
        WriteBytesExt::write_i32::<LittleEndian>(&mut buf, self.start_height)?;
        WriteBytesExt::write_u8(&mut buf, self.relay.into())?;
        Ok(buf)
    }

    fn from_bytes(mut bytes: impl Read) -> anyhow::Result<Self> {
        let version = bytes.read_i32::<LittleEndian>()?;
        let services = bytes.read_u64::<LittleEndian>()?;
        let timestamp = bytes.read_i64::<LittleEndian>()?;
        let addr_recv = VersionNetworkAddress::read_from_buffer(&mut bytes)?;
        let addr_from = VersionNetworkAddress::read_from_buffer(&mut bytes)?;
        let nonce = bytes.read_u64::<LittleEndian>()?;
        let user_agent_len = bytes.read_u8()?;
        let mut user_agent_bytes = vec![0u8; user_agent_len as usize];
        bytes.read_exact(&mut user_agent_bytes)?;
        let user_agent = String::from_utf8(user_agent_bytes)?;
        let start_height = bytes.read_i32::<LittleEndian>()?;
        let relay = bytes.read_u8()? != 0;

        Ok(Self {
            version,
            services,
            timestamp,
            addr_recv,
            addr_from,
            nonce,
            user_agent,
            start_height,
            relay,
        })
    }
}

/// The `net_addr` data is not prefixed with a timestamp in the case of a Version message.
#[derive(Debug)]
struct VersionNetworkAddress {
    services: u64,
    ipv6_4: SocketAddr,
}

impl VersionNetworkAddress {
    fn new(services: u64, addr: SocketAddr) -> Self {
        Self {
            services,
            ipv6_4: addr,
        }
    }
    /// For writing network addresses to a provided buffer.
    fn write_to_buffer(&self, mut buf: &mut Vec<u8>) -> anyhow::Result<()> {
        WriteBytesExt::write_u64::<LittleEndian>(&mut buf, self.services)?;
        WriteBytesExt::write_u128::<BigEndian>(
            &mut buf,
            u128::from_ne_bytes(
                match self.ipv6_4.ip() {
                    V4(addr) => addr.to_ipv6_mapped(),
                    V6(addr) => addr,
                }
                .octets(),
            ),
        )?;
        WriteBytesExt::write_u16::<BigEndian>(&mut buf, self.ipv6_4.port())?;
        Ok(())
    }

    fn read_from_buffer(buf: &mut impl Read) -> anyhow::Result<Self> {
        let services = buf.read_u64::<LittleEndian>()?;
        let ip: Ipv6Addr = buf.read_u128::<BigEndian>()?.into();
        let port = buf.read_u16::<BigEndian>()?;
        Ok(Self {
            services,
            ipv6_4: (ip, port).into(),
        })
    }
}

/// Stub network message enum.
pub enum NetworkMessage {
    Version(ProtocolMessage),
    Verack(ProtocolMessage),
    Other(ProtocolMessage),
}

impl NetworkMessage {
    fn serialize(&self) -> anyhow::Result<Vec<u8>> {
        match self {
            NetworkMessage::Version(protocol_message) => protocol_message.serialize(),
            NetworkMessage::Verack(protocol_message) => protocol_message.serialize(),
            NetworkMessage::Other(_) => {
                unreachable!("we're not serializing other types here")
            }
        }
    }
}

#[derive(Debug)]
pub struct ProtocolMessage {
    /// Magic used to identify the network.
    magic: [u8; 4],
    /// Null padded command bytes.
    command: Command,
    /// Message payload, may be empty.
    payload: Payload,
}

impl ProtocolMessage {
    fn new(magic: [u8; 4], command: Command, payload: Payload) -> Self {
        Self {
            magic,
            command,
            payload,
        }
    }

    /// https://en.bitcoin.it/wiki/Protocol_documentation#Message_structure
    fn serialize(&self) -> anyhow::Result<Vec<u8>> {
        let mut payload = self.payload.to_bytes()?;
        let mut buf = Vec::with_capacity(24 + payload.len());
        buf.extend(&self.magic);
        let checksum = checksum(&payload);
        let command_bytes: [u8; 12] = self.command.to_bytes();
        buf.extend(command_bytes.iter().cloned());
        WriteBytesExt::write_u32::<LittleEndian>(&mut buf, payload.len() as u32)?;
        buf.extend(&checksum);
        buf.append(&mut payload);
        Ok(buf)
    }

    fn from_bytes(mut bytes: impl Read) -> anyhow::Result<Self> {
        let mut magic = [0u8; 4];
        bytes.read_exact(&mut magic)?;
        let mut command = [0u8; 12];
        bytes.read_exact(&mut command)?;
        let command = Command::from_bytes(command);
        let payload_len = bytes.read_u32::<LittleEndian>()? as usize;
        let mut checksum_bytes = [0u8; 4];
        bytes.read_exact(&mut checksum_bytes)?;
        let mut payload_bytes = vec![0u8; payload_len];
        bytes.read_exact(&mut payload_bytes)?;
        let payload_checksum = checksum(&payload_bytes);
        if payload_checksum != checksum_bytes {
            bail!("invalid checksum - expected {checksum_bytes:?}; received {payload_checksum:?}")
        };
        let payload = Payload::from_bytes(payload_bytes.as_slice(), &command)?;

        Ok(Self {
            magic,
            command,
            payload,
        })
    }
}

/// The `command` field of a network message.
#[derive(Debug)]
enum Command {
    Version,
    Verack,
    Other,
}

impl Command {
    /// NULL padded to length 12.
    pub fn to_bytes(&self) -> [u8; 12] {
        let mut buf = [0u8; 12];
        let command_bytes = match self {
            Command::Version => "version".as_bytes(),
            Command::Verack => "verack".as_bytes(),
            _ => unreachable!("we never serialize other message types"),
        };
        buf[..command_bytes.len()].copy_from_slice(command_bytes);
        buf
    }

    fn from_bytes(bytes: [u8; 12]) -> Self {
        match bytes[..7] {
            [0x76, 0x65, 0x72, 0x73, 0x69, 0x6F, 0x6E] => Command::Version,
            [0x76, 0x65, 0x72, 0x61, 0x63, 0x6b, ..] => Command::Verack,
            _ => Command::Other,
        }
    }
}

/// Construct a Version message, containing the peer address in the `receiver` field.
pub fn construct_version_msg(receiver_addr: SocketAddr) -> NetworkMessage {
    NetworkMessage::Version(ProtocolMessage::new(
        MAGIC,
        Command::Version,
        Payload::Version(VersionData {
            version: VERSION,
            services: 0,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            addr_recv: VersionNetworkAddress::new(0, receiver_addr),
            // field can be ignored
            addr_from: VersionNetworkAddress::new(
                0,
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0)),
            ),
            nonce: rand::random(),
            user_agent: "handshake_test".into(),
            start_height: 0,
            relay: false,
        }),
    ))
}

/// Construct a Verack message.
pub fn construct_verack_msg() -> NetworkMessage {
    NetworkMessage::Version(ProtocolMessage::new(MAGIC, Command::Verack, Payload::Empty))
}

/// Send a NetworkMessage to the peer.
pub async fn send_network_msg(stream: &mut TcpStream, msg: NetworkMessage) -> anyhow::Result<()> {
    stream.write_all(&msg.serialize()?).await?;
    Ok(())
}

/// Read the next ProtocolMessage from the stream.
pub async fn read_network_msg(stream: &mut TcpStream) -> anyhow::Result<NetworkMessage> {
    let mut buf = [0u8; 1024];
    let bytes_read = stream.read(&mut buf).await?;
    if bytes_read < 24 {
        println!("{buf:?}");
        bail!("insufficient bytes for protocol messages: {bytes_read}");
    }
    let message = ProtocolMessage::from_bytes(Cursor::new(buf))?;
    Ok(match message.command {
        Command::Version => NetworkMessage::Version(message),
        Command::Verack => NetworkMessage::Verack(message),
        Command::Other => NetworkMessage::Other(message),
    })
}

/// Sha256 applied twice, then first 4 bytes taken as checksum:
/// https://developer.bitcoin.org/reference/p2p_networking.html#message-headers
fn checksum(payload: &[u8]) -> [u8; 4] {
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
