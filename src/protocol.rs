///! rfc1928 SOCKS Protocol Version 5
use std::fmt;

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
