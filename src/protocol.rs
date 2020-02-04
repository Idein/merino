///! rfc1928 SOCKS Protocol Version 5
use std::fmt;
use std::io;
use std::convert::TryFrom;
use std::net::{SocketAddr, ToSocketAddrs, Ipv6Addr, Ipv4Addr, SocketAddrV4, SocketAddrV6};

/// Section 6. Replies > Reply field value
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ResponseCode {
    Success = 0x00,
    Failure = 0x01,
    RuleFailure = 0x02,
    NetworkUnreachable = 0x03,
    HostUnreachable = 0x04,
    ConnectionRefused = 0x05,
    TtlExpired = 0x06,
    CommandNotSupported = 0x07,
    AddrTypeNotSupported = 0x08,
}

impl ResponseCode {
    fn code(&self) -> u8 {
        *self as u8
    }
}

impl fmt::Display for ResponseCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use ResponseCode::*;
        match self {
            Success => write!(f, "succeeded"),
            Failure => write!(f, "general SOCKS server failure"),
            RuleFailure => write!(f, "connection now allowed by ruleset"),
            NetworkUnreachable => write!(f, "Network unreachable"),
            HostUnreachable => write!(f, "Host unreachable"),
            ConnectionRefused => write!(f, "Connection refused"),
            TtlExpired => write!(f, "TTL expired"),
            CommandNotSupported => write!(f, "Command not supported"),
            AddrTypeNotSupported => write!(f, "Address type not supported"),
        }
    }
}

/// Client Authentication Methods
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AuthMethods {
    /// No Authentication
    NoAuth,
    /// GSSAPI
    GssApi,
    /// Authenticate with a username / password
    UserPass,
    /// IANA assigned method
    IANAMethod(u8),
    /// Reserved for private method
    Private(u8),
    /// No acceptable method
    NoMethods,
}

impl AuthMethods {
    pub fn code(&self) -> u8 {
        use AuthMethods::*;
        match self {
            NoAuth => 0x00,
            GssApi => 0x01,
            UserPass => 0x02,
            IANAMethod(c) => *c,
            Private(c) => *c,
            NoMethods => 0xff,
        }
    }
}

impl From<u8> for AuthMethods {
    fn from(code: u8) -> Self {
        use AuthMethods::*;
        match code {
            0x00 => NoAuth,
            0x01 => GssApi,
            0x02 => UserPass,
            0x03..=0x7F => IANAMethod(code),
            0x80..=0xFE => Private(code),
            0xFF => NoAuth,
        }
    }
}

impl fmt::Display for AuthMethods {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use AuthMethods::*;
        match self {
            NoAuth => write!(f, "No Authentication Required"),
            GssApi => write!(f, "GSSAPI"),
            UserPass => write!(f, "Username/Password"),
            IANAMethod(c) =>write!(f, "IANA Assigned: {:#X}", c),
            Private(c) => write!(f, "Private Methods: {:#X}", c),
            NoMethods => write!(f, "No Acceptable Methods"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct TryFromU8Error {
    /// source value
    value: u8,
    /// target type
    to: String,
}

impl fmt::Display for TryFromU8Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "try from u8({:#X}) error to {}", self.value, self.to)
    }
}

impl std::error::Error for TryFromU8Error {
    fn description(&self) -> &str { "TryFromU8Error" }

    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}


/// ATYP
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AddrType {
    V4 = 0x01,
    Domain = 0x03,
    V6 = 0x04,
}

impl TryFrom<u8> for AddrType {
    type Error = TryFromU8Error;
    /// Parse Byte to Command
    fn try_from(n: u8) -> Result<AddrType, Self::Error> {
        match n {
            1 => Ok(AddrType::V4),
            3 => Ok(AddrType::Domain),
            4 => Ok(AddrType::V6),
            _ => Err(TryFromU8Error { value: n, to: "protocol::AddrType".to_owned() })
        }
    }
}

impl fmt::Display for AddrType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use AddrType::*;
        match self {
            V4 => write!(f, "Version4 IP Address"),
            Domain => write!(f, "Fully Qualified Domain Name"),
            V6 => write!(f, "Version6 IP Address"),
        }
    }
}


/// ATYP and (DST or BND)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Address<'a> {
    r#type: AddrType,
    data: &'a [u8],
    port: u16,
}

impl<'a> Address<'a> {
    pub fn new(r#type: AddrType, data: &'a [u8], port: u16) -> Self {
        Address {
            r#type,
            data,
            port,
        }
    }
}

impl<'a> fmt::Display for Address<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use AddrType::*;
        match self.r#type {
            V6 => {
                let addr: Vec<_> = self.data
                    .chunks_exact(2)
                    .map(|c| u16::from_ne_bytes([c[0], c[1]]))
                    .collect();
                let ipv6 = SocketAddrV6::new(
                    Ipv6Addr::new(
                        addr[0], addr[1],
                        addr[2], addr[3],
                        addr[4], addr[5],
                        addr[6], addr[7]
                    ),
                    self.port, 0, 0
                );
                write!(f, "{}", ipv6)
            },
            V4 => {
                let ipv4 = SocketAddrV4::new(
                    Ipv4Addr::new(
                        self.data[0],
                        self.data[1],
                        self.data[2],
                        self.data[3]
                    ),
                    self.port
                );
                write!(f, "{}", ipv4)
            },
            Domain =>
                if let Ok(ss) = String::from_utf8(self.data.to_vec()) {
                    write!(f, "{}:{}", ss, self.port)
                } else {
                    write!(f, "{:x?}:{}", self.data, self.port)
                }
            ,
        }
    }
}

impl<'a> ToSocketAddrs for Address<'a> {
    type Iter = std::vec::IntoIter<SocketAddr>;

    /// Convert an address and AddrType to a SocketAddr
    fn to_socket_addrs(&self) -> io::Result<Self::Iter> {
        match self.r#type {
            AddrType::V6 => {
                let addr: Vec<_> = self.data
                    .chunks_exact(2)
                    .map(|c| u16::from_ne_bytes([c[0], c[1]]))
                    .collect();

                Ok(vec![
                    SocketAddrV6::new(
                        Ipv6Addr::new(
                            addr[0], addr[1],
                            addr[2], addr[3],
                            addr[4], addr[5],
                            addr[6], addr[7]
                        ),
                        self.port, 0, 0
                    ).into()
                ].into_iter())
            },
            AddrType::V4 => {
                Ok(vec![
                   SocketAddrV4::new(
                       Ipv4Addr::new(
                           self.data[0],
                           self.data[1],
                           self.data[2],
                           self.data[3]
                        ),
                        self.port
                   ).into()
                ].into_iter())
            },
            AddrType::Domain => {
                let host = format!("{}:{}", String::from_utf8_lossy(&self.data[..]), self.port);
                Ok(host.to_socket_addrs()?)
            }
        }
    }
}

/// SOCK5 CMD Type
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SockCommand {
    Connect = 0x01,
    Bind = 0x02,
    UdpAssosiate = 0x3
}

impl TryFrom<u8> for SockCommand {
    type Error = TryFromU8Error;
    /// Parse Byte to Command
    fn try_from(n: u8) -> Result<SockCommand, Self::Error> {
        match n {
            1 => Ok(SockCommand::Connect),
            2 => Ok(SockCommand::Bind),
            3 => Ok(SockCommand::UdpAssosiate),
            _ => Err(TryFromU8Error { value: n, to: "protocol::SockCommand".to_owned() })
        }
    }
}

