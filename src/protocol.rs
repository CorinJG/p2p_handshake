//! Internal types to represent protocol messages and methods for (de)serialization.
//!
//! The standard format for all message types is outlined here: [`Bitcoin Protocol: Message Headers`]
//!
//! Fields are little-endian apart from addresses and ports which are big-endian.
//!
//! [`Bitcoin Protocol: Message Headers`]: https://developer.bitcoin.org/reference/p2p_networking.html#message-headers

use std::io::{Cursor, Read};
use std::net::{IpAddr::*, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::bail;
use byteorder::{BigEndian, LittleEndian, ReadBytesExt, WriteBytesExt};

use crate::util::checksum;

/// Magic identifies the network. We'll use the Mainnet.
pub const MAGIC: [u8; 4] = [0xF9, 0xBE, 0xB4, 0xD9];
/// Protocol version.
pub const VERSION: i32 = 70015;

/// Network message, majority of types not implemented. A wrapper around the
/// actual [ProtocolMessage] making it convenient to `match` on message type.
#[derive(Debug, PartialEq, Eq)]
pub enum NetworkMessage {
    Version(ProtocolMessage),
    Verack(ProtocolMessage),
    Other(ProtocolMessage),
}

impl NetworkMessage {
    pub(crate) fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        match self {
            NetworkMessage::Version(protocol_message) => protocol_message.to_bytes(),
            NetworkMessage::Verack(protocol_message) => protocol_message.to_bytes(),
            NetworkMessage::Other(_) => {
                unreachable!("we're not serializing other types")
            }
        }
    }

    pub(crate) fn from_bytes(buf: &[u8]) -> anyhow::Result<Self> {
        let message = ProtocolMessage::from_bytes(Cursor::new(buf))?;
        Ok(match message.command {
            Command::Version => NetworkMessage::Version(message),
            Command::Verack => NetworkMessage::Verack(message),
            Command::Other => NetworkMessage::Other(message),
        })
    }
}

/// The standard network message format: https://en.bitcoin.it/wiki/Protocol_documentation#Message_structure.
/// The `length` and `checksum` fields are computed as a function of the `payload` field.
#[derive(Debug, PartialEq, Eq)]
pub struct ProtocolMessage {
    /// Magic to identify the network.
    pub magic: [u8; 4],
    /// Null padded command bytes.
    pub command: Command,
    /// Message payload, may be empty.
    pub payload: Payload,
}

impl ProtocolMessage {
    pub(crate) fn new(magic: [u8; 4], command: Command, payload: Payload) -> Self {
        Self {
            magic,
            command,
            payload,
        }
    }

    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let mut payload = self.payload.to_bytes()?;
        // `magic` + `command` + `length` + `checksum` fields sum to 24 bytes
        let mut buf = Vec::with_capacity(24 + payload.len());
        buf.extend(&self.magic);
        let checksum = checksum(&payload);
        let command_bytes: [u8; 12] = self.command.to_bytes();
        buf.extend(command_bytes.iter());
        WriteBytesExt::write_u32::<LittleEndian>(&mut buf, payload.len() as u32)?;
        buf.extend(&checksum);
        buf.append(&mut payload);
        Ok(buf)
    }

    pub(crate) fn from_bytes(mut bytes: impl Read) -> anyhow::Result<Self> {
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

/// Internal data type for a message payload. We are only concerned with Version here.
#[derive(Debug, PartialEq, Eq)]
pub enum Payload {
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
#[derive(Debug, PartialEq, Eq)]
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
    /// Construct a new VersionData, providing a subset of the fields. Useful for testing.
    fn new(
        timestamp: i64,
        addr_recv: SocketAddr,
        addr_from: SocketAddr,
        nonce: u64,
        start_height: i32,
    ) -> Self {
        Self {
            version: VERSION,
            services: 0,
            timestamp,
            addr_recv: VersionNetworkAddress::new(0, addr_recv),
            addr_from: VersionNetworkAddress::new(0, addr_from),
            nonce,
            user_agent: "handshake_test".into(),
            start_height,
            relay: false,
        }
    }

    /// Defaults with a provided `addr_recv` field.
    pub(crate) fn default_from_addr_recv(receiver_addr: SocketAddr) -> Self {
        Self {
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
        }
    }

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

/// A special case of a network address field in a protocol message, for example the `addr_recv` and
/// `addr_from` fields of a Version message.
/// *The timestamp bytes are omitted in the case of a Version message.
/// See: https://en.bitcoin.it/wiki/Protocol_documentation#Network_address
#[derive(Debug, Eq)]
pub(crate) struct VersionNetworkAddress {
    services: u64,
    // may be either V4 or V6 form internally
    ipv4_6: SocketAddr,
}

impl PartialEq for VersionNetworkAddress {
    /// Custom comparison which returns true for the same address in ipv4/6 representations.
    fn eq(&self, other: &Self) -> bool {
        let self_ipv6_addr = match self.ipv4_6.ip() {
            V4(addr) => addr.to_ipv6_mapped(),
            V6(addr) => addr,
        };
        let other_ipv6_addr = match other.ipv4_6.ip() {
            V4(addr) => addr.to_ipv6_mapped(),
            V6(addr) => addr,
        };
        self_ipv6_addr == other_ipv6_addr
            && self.services == other.services
            && self.ipv4_6.port() == other.ipv4_6.port()
    }
}

impl VersionNetworkAddress {
    pub(crate) fn new(services: u64, addr: SocketAddr) -> Self {
        Self {
            services,
            ipv4_6: addr,
        }
    }
    /// For writing a serialised [VersionNetworkAddress] to a provided buffer.
    fn write_to_buffer(&self, mut buf: &mut Vec<u8>) -> anyhow::Result<()> {
        WriteBytesExt::write_u64::<LittleEndian>(&mut buf, self.services)?;
        WriteBytesExt::write_u128::<BigEndian>(
            &mut buf,
            // octets() returns "Big-endian" order of bytes in the array
            u128::from_be_bytes(
                match self.ipv4_6.ip() {
                    V4(addr) => addr.to_ipv6_mapped(),
                    V6(addr) => addr,
                }
                .octets(),
            ),
        )?;
        WriteBytesExt::write_u16::<BigEndian>(&mut buf, self.ipv4_6.port())?;
        Ok(())
    }

    /// Construct a [VersionNetworkAddress] from serialised bytes in a provided buffer.
    fn read_from_buffer(buf: &mut impl Read) -> anyhow::Result<Self> {
        let services = buf.read_u64::<LittleEndian>()?;
        let ip: Ipv6Addr = buf.read_u128::<BigEndian>()?.into();
        let port = buf.read_u16::<BigEndian>()?;
        Ok(Self {
            services,
            ipv4_6: (ip, port).into(),
        })
    }
}

/// The `command` field of a network message. Our stub only covers Version and Verack.
#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    Version,
    Verack,
    Other,
}

impl Command {
    pub fn to_bytes(&self) -> [u8; 12] {
        // NULL padded to length 12.
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
            [0x76, 0x65, 0x72, 0x61, 0x63, 0x6b, _] => Command::Verack,
            _ => Command::Other,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use crate::{
        protocol::{Command, ProtocolMessage},
        util::{checksum, construct_verack_msg},
    };

    use super::{NetworkMessage, Payload, VersionData, VersionNetworkAddress, MAGIC};

    // Serialization target verified from: https://en.bitcoin.it/wiki/Protocol_documentation#verack
    #[rustfmt::skip]
    #[test]
    fn serialize_verack() {
        let verack_msg = construct_verack_msg();
        let target = vec![
            0xf9, 0xbe, 0xb4, 0xd9,                                                 // magic
            0x76, 0x65, 0x72, 0x61, 0x63, 0x6B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // command
            0x00, 0x00, 0x00, 0x00,                                                 // payload length
            0x5d, 0xf6, 0xe0, 0xe2,                                                 // checksum
        ];
        assert_eq!(
            verack_msg.to_bytes().expect("error serializing verack msg"),
            target
        );
    }

    #[rustfmt::skip]
    #[test]
    fn deserialize_verack() {
        let verack = vec![
            0xf9, 0xbe, 0xb4, 0xd9,                                                 // magic
            0x76, 0x65, 0x72, 0x61, 0x63, 0x6B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // command
            0x00, 0x00, 0x00, 0x00,                                                 // payload length
            0x5d, 0xf6, 0xe0, 0xe2,                                                 // checksum
        ];
        let target = construct_verack_msg();
        assert_eq!(NetworkMessage::from_bytes(&verack).expect("error deserializing verack"), target);
    }

    #[rustfmt::skip]
    #[test]
    fn serialize_version() {
        let version_data = VersionData::new(
            1355854353, 
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8333),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8333),
            9833440827789222417,
            1198738,
        );
        
        let checksum_bytes = checksum(&version_data.to_bytes().expect("error serializing version data"));

        let target = vec![
            0xf9, 0xbe, 0xb4, 0xd9,                                                     // magic
            0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x00,     // command
            0x64, 0x00, 0x00, 0x00,                                                     // payload length
            checksum_bytes[0], checksum_bytes[1], checksum_bytes[2], checksum_bytes[3], // checksum
            // Version payload:-
            0x7f, 0x11, 0x01, 0x00,                                                     // 70015 protocol version 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,                             // network services (0)
            0x11, 0xb2, 0xd0, 0x50, 0x00, 0x00, 0x00, 0x00,                             // timestamp - 1355854353
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,                             // network services (0)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,                             // 2 lines of 128 bit IP (Big-endian)
            0x00, 0x00, 0xff, 0xff, 0x7f, 0x00, 0x00, 0x01,  
            0x20, 0x8d,                                                                 // port (8333) - u16 (Big-endian)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,                             // network services (0)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,                             // 2 lines of 128 bit IP (Big-endian)
            0x00, 0x00, 0xff, 0xff, 0x7f, 0x00, 0x00, 0x01,  
            0x20, 0x8d,                                                                 // port (8333) - u16 (Big-endian)
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,                             // nonce - u64
            0x0e, 0x68, 0x61, 0x6E, 0x64, 0x73, 0x68, 0x61,                             // 14 byte long user-agent (VarStr)
            0x6b, 0x65, 0x5f, 0x74, 0x65, 0x73, 0x74, 
            0x92, 0x4a, 0x12, 0x00,                                                     // start-height - 1198738
            0x00,                                                                       // relay (bool)
        ];
        let version_msg = NetworkMessage::Version(
            ProtocolMessage::new(MAGIC, Command::Version, Payload::Version(version_data))
        );
        assert_eq!(
            version_msg.to_bytes().expect("error serializing version msg"),
            target
        );
    }

    /// Encode and decode and check we get the same [NetworkMessage] back.
    #[test]
    fn version_encode_decode() {
        let version_data = VersionData::new(
            1555554333,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8333),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 8333),
            2578899354211868349,
            1384756,
        );

        let version_msg = NetworkMessage::Version(ProtocolMessage::new(
            MAGIC,
            Command::Version,
            Payload::Version(version_data),
        ));
        assert_eq!(
            version_msg,
            NetworkMessage::from_bytes(
                &version_msg
                    .to_bytes()
                    .expect("error serializing version msg")
            )
            .expect("error deserializing version msg")
        );
    }

    #[test]
    fn test_version_network_address_eq() {
        let ipv4_addr =
            VersionNetworkAddress::new(0, SocketAddr::V4("12.34.56.78:8080".parse().unwrap()));
        let ipv6_addr = VersionNetworkAddress::new(
            0,
            SocketAddr::V6("[::ffff:0c22:384e]:8080".parse().unwrap()),
        );
        let ipv6_addr2 = VersionNetworkAddress::new(
            0,
            SocketAddr::V6("[::ffff:0001:abcd]:8080".parse().unwrap()),
        );
        let ipv6_addr3 = VersionNetworkAddress::new(
            0,
            SocketAddr::V6("[::ffff:0001:abcd]:8081".parse().unwrap()),
        );
        assert_eq!(ipv4_addr, ipv6_addr);
        assert_eq!(ipv4_addr, ipv4_addr);
        assert_eq!(ipv6_addr, ipv6_addr);
        assert_ne!(ipv4_addr, ipv6_addr2);
        assert_ne!(ipv6_addr, ipv6_addr2);
        assert_ne!(ipv6_addr2, ipv6_addr3);
    }
}
