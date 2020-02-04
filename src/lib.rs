#![forbid(unsafe_code)]
#[macro_use] extern crate serde_derive;
#[macro_use] extern crate log;

pub mod error;
pub mod protocol;

use error::*;
pub use protocol::{AuthMethods, ResponseCode};
use protocol::{AddrType, Address};

use std::convert::TryInto;
use std::io::prelude::*;
use std::io::copy;
use std::net::{Shutdown, TcpStream, TcpListener, ToSocketAddrs};
use std::{thread};


/// Version of socks
const SOCKS_VERSION: u8 = 0x05;

const RESERVED: u8 = 0x00;

#[derive(Clone,Debug, PartialEq, Deserialize)]
pub struct User {
    pub username: String,
    password: String
}


/// SOCK5 CMD Type
#[derive(Debug)]
enum SockCommand {
    Connect = 0x01,
    Bind = 0x02,
    UdpAssosiate = 0x3
}

impl SockCommand {
    /// Parse Byte to Command
    fn from(n: usize) -> Option<SockCommand> {
        match n {
            1 => Some(SockCommand::Connect),
            2 => Some(SockCommand::Bind),
            3 => Some(SockCommand::UdpAssosiate),
            _ => None
        }
    }
}


pub struct Merino {
    listener: TcpListener,
    users: Vec<User>,
    auth_methods: Vec<AuthMethods>
}

impl Merino {
    /// Create a new Merino instance
    pub fn new(port: u16,  ip: &str, auth_methods: Vec<AuthMethods>, users: Vec<User>) -> Result<Self, Error> {
        info!("Listening on {}:{}", ip, port);
        Ok(Merino {
            listener: TcpListener::bind((ip, port))?,
            auth_methods,
            users
        })
    }

    pub fn serve(&mut self) -> Result<(), Error> {
        info!("Serving Connections...");
        loop {
            if let Ok((stream, _remote)) = self.listener.accept() {
                // TODO Optimize this
                let mut client =
                    SOCKClient::new(stream, self.users.clone(), self.auth_methods.clone());
                thread::spawn(move || {
                    if let Err(error) = client.init() {
                        error!("Error! {}", error);
                        let error_text = format!("{}", error);

                        let response: ResponseCode;

                        if error_text.contains("Host") {
                            response = ResponseCode::HostUnreachable;
                        } else if error_text.contains("Network") {
                            response = ResponseCode::NetworkUnreachable;
                        } else if error_text.contains("ttl") {
                            response = ResponseCode::TtlExpired
                        } else {
                            response = ResponseCode::Failure
                        }

                        if client.error(response).is_err() {
                            warn!("Failed to send error code");
                        }
                        if let Err(err) = client.shutdown() {
                            warn!("Failed to shutdown TcpStream: {:?}", err);
                        }
                    }
                });
            }
        }
    }
}

struct SOCKClient {
    stream: TcpStream,
    auth_nmethods: u8,
    auth_methods: Vec<AuthMethods>,
    authed_users: Vec<User>,
    socks_version: u8
}

impl SOCKClient {
    /// Create a new SOCKClient
    pub fn new(stream: TcpStream, authed_users: Vec<User>, auth_methods: Vec<AuthMethods>) -> Self {
        SOCKClient {
            stream,
            auth_nmethods: 0,
            socks_version: 0,
            authed_users,
            auth_methods
        }
    }

    /// Check if username + password pair are valid
    fn authed(&self, user: &User) -> bool {
        self.authed_users.contains(user)
    }

    /// Send an error to the client
    pub fn error(&mut self, r: ResponseCode) -> Result<(), Error> {
        self.stream.write_all(&[5, r as u8])?;
        Ok(())
    }

    /// Shutdown a client
    pub fn shutdown(&mut self) -> Result<(), Error> {
        self.stream.shutdown(Shutdown::Both)?;
        Ok(())
    }

    fn init(&mut self) -> Result<(), Error> {
        debug!("New connection from: {}", self.stream.peer_addr()?.ip());
        let mut header = [0u8; 2];
        // Read a byte from the stream and determine the version being requested
        self.stream.read_exact(&mut header)?;

        self.socks_version = header[0];
        self.auth_nmethods = header[1];

        trace!("Version: {} Auth nmethods: {}", self.socks_version, self.auth_nmethods);

        // Handle SOCKS4 requests
        if header[0] != SOCKS_VERSION {
            warn!("Init: Unsupported version: SOCKS{}", self.socks_version);
            self.shutdown()?;
        }
        // Valid SOCKS5
        else {
            // Authenticate w/ client
            self.auth()?;
            // Handle requests
            self.handle_client()?;
        }

        Ok(())
    }

    fn auth(&mut self) -> Result<(), Error> {
        debug!("Authenticating w/ {}", self.stream.peer_addr()?.ip());
        // Get valid auth methods
        let methods = self.get_avalible_methods()?;
        trace!("methods: {:?}", methods);

        let mut response = [0u8; 2];

        // Set the version in the response
        response[0] = SOCKS_VERSION;
        
        if methods.contains(&AuthMethods::UserPass) {
            // Set the default auth method (NO AUTH)
            response[1] = AuthMethods::UserPass.code();

            debug!("Sending USER/PASS packet");
            self.stream.write_all(&response)?;

            let mut header = [0u8;2];

            // Read a byte from the stream and determine the version being requested
            self.stream.read_exact(&mut header)?;

            // debug!("Auth Header: [{}, {}]", header[0], header[1]);

            // Username parsing
            let ulen = header[1];

            let mut username = Vec::with_capacity(ulen as usize);

            // For some reason the vector needs to actually be full
            for _ in 0..ulen {
                username.push(0);
            }

            self.stream.read_exact(&mut username)?;

            // Password Parsing
            let mut plen = [0u8; 1];
            self.stream.read_exact(&mut plen)?;
            

            let mut password = Vec::with_capacity(plen[0] as usize);

            // For some reason the vector needs to actually be full
            for _ in 0..plen[0] {
                password.push(0);
            }

            self.stream.read_exact(&mut password)?;

            let username_str = String::from_utf8(username)?;
            let password_str = String::from_utf8(password)?;

           let user = User { 
                username: username_str,
                password: password_str 
            };

            // Authenticate passwords
            if self.authed(&user) {
                debug!("Access Granted. User: {}", user.username);
                let response = [1, ResponseCode::Success as u8];
                self.stream.write_all(&response)?;
            } 
            else {
                debug!("Access Denied. User: {}", user.username);
                let response = [1, ResponseCode::Failure as u8];
                self.stream.write_all(&response)?;

                // Shutdown 
                self.shutdown()?;

            }

            Ok(())
        }
        else if methods.contains(&AuthMethods::NoAuth) {
            // set the default auth method (no auth)
            response[1] = AuthMethods::NoAuth.code();
            debug!("Sending NOAUTH packet");
            self.stream.write_all(&response)?;
            Ok(())
        }
        else {
            warn!("Client has no suitable Auth methods!");
            response[1] = AuthMethods::NoMethods.code();
            self.stream.write_all(&response)?;
            self.shutdown()?;
            Err(ResponseCode::Failure.into())
        }

    }

    /// Handles a client
    pub fn handle_client(&mut self) -> Result<(), Error> {
        debug!("Handling requests for {}", self.stream.peer_addr()?.ip());
        // Read request
        // loop {
            // Parse Request
            let req = SOCKSReq::from_stream(&mut self.stream)?;
            
            // Log Request
            info!("New Request: Source: {}, Command: {:?} Addr: {}", 
                  self.stream.peer_addr()?.ip(),
                  req.command, 
                  req.address()
            );

            // Respond
            match req.command {
                // Use the Proxy to connect to the specified addr/port
                SockCommand::Connect => {
                    debug!("Handling CONNECT Command");

                    let sock_addr = req.address().to_socket_addrs()?;

                    trace!("Connecting to: {:?}", sock_addr);

                    let target = TcpStream::connect(sock_addr.as_slice())?;

                    trace!("Connected!");

                    self.stream.write_all(&[SOCKS_VERSION, ResponseCode::Success as u8, RESERVED, 1, 127, 0, 0, 1, 0, 0]).unwrap();

                    // Copy it all
                    let mut outbound_in = target.try_clone()?;
                    let mut outbound_out = target.try_clone()?;
                    let mut inbound_in = self.stream.try_clone()?;
                    let mut inbound_out = self.stream.try_clone()?;


                    // Download Thread
                    thread::spawn(move || {
                        copy(&mut outbound_in, &mut inbound_out).is_ok();
                        outbound_in.shutdown(Shutdown::Read).unwrap_or(());
                        inbound_out.shutdown(Shutdown::Write).unwrap_or(());
                    });

                    // Upload Thread
                    thread::spawn(move || {
                        copy(&mut inbound_in, &mut outbound_out).is_ok();
                        inbound_in.shutdown(Shutdown::Read).unwrap_or(());
                        outbound_out.shutdown(Shutdown::Write).unwrap_or(());
                    });


                },
                SockCommand::Bind => { },
                SockCommand::UdpAssosiate => { },
            }




            // connected = false;
        // }

        Ok(())
    }

    /// Return the avalible methods based on `self.auth_nmethods`
    fn get_avalible_methods(&mut self) -> Result<Vec<AuthMethods>, Error> {
        let mut methods: Vec<AuthMethods> = Vec::with_capacity(self.auth_nmethods as usize);
        for _ in 0..self.auth_nmethods {
            let mut method = [0u8; 1];
            self.stream.read_exact(&mut method)?;
            if self.auth_methods.contains(&(method[0].into())) {
                methods.push(method[0].into());
            }
        }
        Ok(methods)
    }
}

/// Proxy User Request
struct SOCKSReq {
    pub version: u8,
    pub command: SockCommand,
    pub addr_type: AddrType,
    pub addr: Vec<u8>,
    pub port: u16
}

impl SOCKSReq {
    fn address(&self) -> Address {
        Address::new(self.addr_type, &self.addr, self.port)
    }
}

impl SOCKSReq {
    /// Parse a SOCKS Req from a TcpStream
    fn from_stream(stream: &mut TcpStream) -> Result<Self, Error> {
        let mut packet = [0u8; 4];
        // Read a byte from the stream and determine the version being requested
        stream.read_exact(&mut packet)?;

        if packet[0] != SOCKS_VERSION {
            warn!("from_stream Unsupported version: SOCKS{}", packet[0]);
            stream.shutdown(Shutdown::Both)?;

        }

        // Get command
        let mut command: SockCommand = SockCommand::Connect;
        match SockCommand::from(packet[1] as usize) {
            Some(com) => {
                command = com;
                Ok(())
            },
            None => {
                warn!("Invalid Command");
                stream.shutdown(Shutdown::Both)?;
                Err(ResponseCode::CommandNotSupported)
            }
        }?;

        // DST.address
        let addr_type: AddrType = match packet[3].try_into() {
            Ok(addr) => addr,
            Err(err) => {
                error!("No Addr: {:?}", err);
                stream.shutdown(Shutdown::Both)?;
                return Err(ResponseCode::AddrTypeNotSupported.into())
            }
        };
        trace!("AddrType: {}", addr_type);

        trace!("Getting Addr");
        // Get Addr from addr_type and stream
        let addr: Result<Vec<u8>, Error> = match addr_type {
            AddrType::Domain => {
                let mut dlen = [0u8; 1];
                stream.read_exact(&mut dlen)?;

                let mut domain = vec![0u8; dlen[0] as usize];
                stream.read_exact(&mut domain)?;

                Ok(domain)
            },
            AddrType::V4 => {
                let mut addr = [0u8; 4];
                stream.read_exact(&mut addr)?;
                Ok(addr.to_vec())
            },
            AddrType::V6 => {
                let mut addr = [0u8; 16];
                stream.read_exact(&mut addr)?;
                Ok(addr.to_vec())
            }
        };

        let addr = addr?;

        // read DST.port
        let mut port = [0u8; 2];
        stream.read_exact(&mut port)?;

        // Merge two u8s into u16
        let port = (u16::from(port[0]) << 8) | u16::from(port[1]);

        // Return parsed request
        Ok(SOCKSReq {
            version: packet[0],
            command,
            addr_type,
            addr,
            port
        })
    }
}
