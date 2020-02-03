///! rfc1928 SOCKS Protocol Version 5
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
/// Section 6. Replies > Reply field value
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
