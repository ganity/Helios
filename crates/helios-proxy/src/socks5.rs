use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use helios_protocol::{Address, EncodeError, Target};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const VERSION: u8 = 5;
const NO_AUTH: u8 = 0;
const NO_ACCEPTABLE_METHOD: u8 = 0xff;
const CONNECT: u8 = 1;
const UDP_ASSOCIATE: u8 = 3;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpDatagram {
    pub target: Target,
    pub payload: Vec<u8>,
}

impl UdpDatagram {
    pub fn decode(input: &[u8]) -> Result<Self, Socks5Error> {
        if input.len() < 4 || input[..2] != [0, 0] || input[2] != 0 {
            return Err(Socks5Error::InvalidReserved);
        }
        let (address, consumed) = match input[3] {
            1 => {
                let value = input.get(4..8).ok_or(Socks5Error::InvalidReserved)?;
                (
                    Address::Ip(IpAddr::V4(Ipv4Addr::new(
                        value[0], value[1], value[2], value[3],
                    ))),
                    8,
                )
            }
            3 => {
                let length = *input.get(4).ok_or(Socks5Error::InvalidReserved)? as usize;
                let end = 5usize
                    .checked_add(length)
                    .ok_or(Socks5Error::InvalidReserved)?;
                let domain = input.get(5..end).ok_or(Socks5Error::InvalidReserved)?;
                (
                    Address::Domain(
                        String::from_utf8(domain.to_vec())
                            .map_err(|_| Socks5Error::InvalidTarget(EncodeError::InvalidDomain))?,
                    ),
                    end,
                )
            }
            4 => {
                let value = input.get(4..20).ok_or(Socks5Error::InvalidReserved)?;
                let octets: [u8; 16] = value.try_into().unwrap();
                (Address::Ip(IpAddr::V6(Ipv6Addr::from(octets))), 20)
            }
            other => return Err(Socks5Error::UnsupportedAddressType(other)),
        };
        let port_end = consumed
            .checked_add(2)
            .ok_or(Socks5Error::InvalidReserved)?;
        let port = u16::from_be_bytes(
            input
                .get(consumed..port_end)
                .ok_or(Socks5Error::InvalidReserved)?
                .try_into()
                .unwrap(),
        );
        let target = Target::new(address, port)?;
        Ok(Self {
            target,
            payload: input
                .get(port_end..)
                .ok_or(Socks5Error::InvalidReserved)?
                .to_vec(),
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, Socks5Error> {
        let mut output = vec![0, 0, 0];
        match &self.target.address {
            Address::Ip(IpAddr::V4(ip)) => {
                output.push(1);
                output.extend_from_slice(&ip.octets());
            }
            Address::Domain(domain) => {
                output.extend_from_slice(&[3, domain.len() as u8]);
                output.extend_from_slice(domain.as_bytes());
            }
            Address::Ip(IpAddr::V6(ip)) => {
                output.push(4);
                output.extend_from_slice(&ip.octets());
            }
        }
        output.extend_from_slice(&self.target.port.to_be_bytes());
        output.extend_from_slice(&self.payload);
        Ok(output)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Socks5Reply {
    Succeeded = 0,
    GeneralFailure = 1,
    NotAllowed = 2,
    NetworkUnreachable = 3,
    HostUnreachable = 4,
    ConnectionRefused = 5,
    TtlExpired = 6,
    CommandNotSupported = 7,
    AddressTypeNotSupported = 8,
}

#[derive(Debug, Error)]
pub enum Socks5Error {
    #[error("SOCKS5 I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("unsupported SOCKS version {0}")]
    UnsupportedVersion(u8),
    #[error("client does not offer no-authentication method")]
    NoAcceptableMethod,
    #[error("unsupported SOCKS command {0}")]
    UnsupportedCommand(u8),
    #[error("invalid reserved byte")]
    InvalidReserved,
    #[error("unsupported SOCKS address type {0}")]
    UnsupportedAddressType(u8),
    #[error("invalid SOCKS target: {0}")]
    InvalidTarget(#[from] EncodeError),
}

pub struct Socks5<S> {
    stream: S,
}

impl<S> Socks5<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub async fn negotiate(mut stream: S) -> Result<Self, Socks5Error> {
        let mut header = [0; 2];
        stream.read_exact(&mut header).await?;
        if header[0] != VERSION {
            return Err(Socks5Error::UnsupportedVersion(header[0]));
        }
        let mut methods = vec![0; header[1] as usize];
        stream.read_exact(&mut methods).await?;
        if !methods.contains(&NO_AUTH) {
            stream.write_all(&[VERSION, NO_ACCEPTABLE_METHOD]).await?;
            return Err(Socks5Error::NoAcceptableMethod);
        }
        stream.write_all(&[VERSION, NO_AUTH]).await?;
        Ok(Self { stream })
    }

    pub async fn read_connect(&mut self) -> Result<Target, Socks5Error> {
        let (command, target) = self.read_request().await?;
        if command != CONNECT {
            self.reply(Socks5Reply::CommandNotSupported).await?;
            return Err(Socks5Error::UnsupportedCommand(command));
        }
        target.ok_or(Socks5Error::InvalidTarget(EncodeError::ZeroPort))
    }

    pub async fn read_udp_associate(&mut self) -> Result<Option<Target>, Socks5Error> {
        let (command, target) = self.read_request().await?;
        if command != UDP_ASSOCIATE {
            self.reply(Socks5Reply::CommandNotSupported).await?;
            return Err(Socks5Error::UnsupportedCommand(command));
        }
        Ok(target)
    }

    pub async fn read_request(&mut self) -> Result<(u8, Option<Target>), Socks5Error> {
        let mut header = [0; 4];
        self.stream.read_exact(&mut header).await?;
        if header[0] != VERSION {
            return Err(Socks5Error::UnsupportedVersion(header[0]));
        }
        if header[2] != 0 {
            return Err(Socks5Error::InvalidReserved);
        }

        let address = match header[3] {
            1 => {
                let mut octets = [0; 4];
                self.stream.read_exact(&mut octets).await?;
                Address::Ip(IpAddr::V4(Ipv4Addr::from(octets)))
            }
            3 => {
                let length = self.stream.read_u8().await? as usize;
                let mut domain = vec![0; length];
                self.stream.read_exact(&mut domain).await?;
                Address::Domain(String::from_utf8(domain).map_err(|_| EncodeError::InvalidDomain)?)
            }
            4 => {
                let mut octets = [0; 16];
                self.stream.read_exact(&mut octets).await?;
                Address::Ip(IpAddr::V6(Ipv6Addr::from(octets)))
            }
            other => {
                self.reply(Socks5Reply::AddressTypeNotSupported).await?;
                return Err(Socks5Error::UnsupportedAddressType(other));
            }
        };
        let port = self.stream.read_u16().await?;
        if header[1] == UDP_ASSOCIATE && port == 0 {
            return Ok((header[1], None));
        }
        Ok((header[1], Some(Target::new(address, port)?)))
    }

    pub async fn reply(&mut self, reply: Socks5Reply) -> Result<(), Socks5Error> {
        self.stream
            .write_all(&[VERSION, reply as u8, 0, 1, 0, 0, 0, 0, 0, 0])
            .await?;
        self.stream.flush().await?;
        Ok(())
    }

    pub async fn reply_udp_bound(
        &mut self,
        reply: Socks5Reply,
        address: std::net::SocketAddr,
    ) -> Result<(), Socks5Error> {
        let mut response = vec![VERSION, reply as u8, 0];
        match address.ip() {
            IpAddr::V4(ip) => {
                response.push(1);
                response.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                response.push(4);
                response.extend_from_slice(&ip.octets());
            }
        }
        response.extend_from_slice(&address.port().to_be_bytes());
        self.stream.write_all(&response).await?;
        self.stream.flush().await?;
        Ok(())
    }

    pub fn into_inner(self) -> S {
        self.stream
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;

    #[tokio::test]
    async fn preserves_domain_without_resolving_it() {
        let (client, server) = duplex(256);
        let peer = tokio::spawn(async move {
            let mut client = client;
            client.write_all(&[5, 1, 0]).await.unwrap();
            let mut method = [0; 2];
            client.read_exact(&mut method).await.unwrap();
            assert_eq!(method, [5, 0]);
            client
                .write_all(&[
                    5, 1, 0, 3, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o',
                    b'm', 1, 187,
                ])
                .await
                .unwrap();
            let mut reply = [0; 10];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply[1], Socks5Reply::Succeeded as u8);
        });

        let mut socks = Socks5::negotiate(server).await.unwrap();
        let target = socks.read_connect().await.unwrap();
        assert_eq!(target.address, Address::Domain("example.com".into()));
        assert_eq!(target.port, 443);
        socks.reply(Socks5Reply::Succeeded).await.unwrap();
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn rejects_client_without_no_auth_method() {
        let (mut client, server) = duplex(16);
        let peer = tokio::spawn(async move {
            client.write_all(&[5, 1, 2]).await.unwrap();
            let mut reply = [0; 2];
            client.read_exact(&mut reply).await.unwrap();
            reply
        });

        assert!(matches!(
            Socks5::negotiate(server).await,
            Err(Socks5Error::NoAcceptableMethod)
        ));
        assert_eq!(peer.await.unwrap(), [5, 0xff]);
    }

    #[tokio::test]
    async fn rejects_unsupported_command_with_protocol_reply() {
        let (client, server) = duplex(32);
        let peer = tokio::spawn(async move {
            let mut client = client;
            client.write_all(&[5, 1, 0]).await.unwrap();
            let mut method = [0; 2];
            client.read_exact(&mut method).await.unwrap();
            client
                .write_all(&[5, 2, 0, 1, 127, 0, 0, 1, 0, 80])
                .await
                .unwrap();
            let mut reply = [0; 10];
            client.read_exact(&mut reply).await.unwrap();
            reply
        });

        let mut socks = Socks5::negotiate(server).await.unwrap();
        assert!(matches!(
            socks.read_connect().await,
            Err(Socks5Error::UnsupportedCommand(2))
        ));
        assert_eq!(
            peer.await.unwrap()[1],
            Socks5Reply::CommandNotSupported as u8
        );
    }

    #[test]
    fn udp_datagram_round_trips_and_rejects_fragmentation() {
        let packet = UdpDatagram {
            target: Target::new(Address::Domain("example.com".into()), 53).unwrap(),
            payload: b"query".to_vec(),
        };
        assert_eq!(
            UdpDatagram::decode(&packet.encode().unwrap()).unwrap(),
            packet
        );
        let mut fragmented = packet.encode().unwrap();
        fragmented[2] = 1;
        assert!(matches!(
            UdpDatagram::decode(&fragmented),
            Err(Socks5Error::InvalidReserved)
        ));
    }
}
