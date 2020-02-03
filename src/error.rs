use std::io;
use std::string;
use snafu::Snafu;

use crate::protocol;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Io Error: {}", source))]
    #[snafu(context(false))]
    Io { source: io::Error },
    #[snafu(display("Utf8Parse Error: {}", source))]
    #[snafu(context(false))]
    Utf8 {
        source: string::FromUtf8Error
    },
    #[snafu(display("SOCKS5 Server Error: {}", code))]
    Socks5 {
        code: protocol::ResponseCode,
    },
}

impl From<protocol::ResponseCode> for Error {
    fn from(error: protocol::ResponseCode) -> Self {
        Error::Socks5 { code: error }
    }
}

