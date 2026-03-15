use clap::{Parser, Subcommand};
use std::net::Ipv4Addr;

#[derive(Parser, Debug)]
#[command(name = "tcp-raw-speedtest", about = "Network speed test using raw TCP sockets")]
pub struct Cli {
    #[command(subcommand)]
    pub mode: Mode,
}

#[derive(Subcommand, Debug)]
pub enum Mode {
    /// Run in server mode
    Server {
        /// Port to listen on
        #[arg(short, long, default_value_t = 5201)]
        port: u16,

        /// Bind address
        #[arg(short, long, default_value = "0.0.0.0")]
        bind: String,
    },
    /// Run in client mode
    Client {
        /// Server address (IP:PORT or IP, default port 5201)
        #[arg(short, long)]
        server: String,

        /// Payload size per packet in bytes
        #[arg(long, default_value_t = 1400)]
        payload_size: u16,

        /// Rate multiplier - converge to bandwidth * multiplier
        #[arg(short, long, default_value_t = 1.5)]
        multiplier: f64,

        /// Enable retransmission mode (re-send lost packets)
        #[arg(long, default_value_t = false)]
        retransmit: bool,

        /// Reverse direction: server sends data to client
        #[arg(long, default_value_t = false)]
        reverse: bool,

        /// Bidirectional: both sides send data
        #[arg(long, default_value_t = false)]
        bidirectional: bool,

        /// Stats reporting interval in seconds
        #[arg(short, long, default_value_t = 1.0)]
        interval: f64,

        /// Rate adjustment sensitivity base
        #[arg(long, default_value_t = 2.0)]
        base: f64,

        /// Source port (0 = random)
        #[arg(long, default_value_t = 0)]
        sport: u16,
    },
}

/// Parsed and validated configuration
#[derive(Debug, Clone)]
pub struct TestConfig {
    pub server_addr: Ipv4Addr,
    pub server_port: u16,
    pub payload_size: u16,
    pub multiplier: f64,
    pub retransmit: bool,
    pub reverse: bool,
    pub bidirectional: bool,
    pub interval_secs: f64,
    pub rate_base: f64,
}

/// Parameters sent from client to server during handshake
#[derive(Debug, Clone, Copy)]
pub struct TestParams {
    pub payload_size: u16,
    pub retransmit: bool,
    pub reverse: bool,
    pub bidirectional: bool,
}

impl TestParams {
    /// Encode test parameters into bytes for the SYN payload
    pub fn to_bytes(&self) -> [u8; 8] {
        let mut buf = [0u8; 8];
        buf[0..2].copy_from_slice(&self.payload_size.to_be_bytes());
        buf[2] = self.retransmit as u8;
        buf[3] = self.reverse as u8;
        buf[4] = self.bidirectional as u8;
        // 5-7 reserved
        buf
    }

    /// Decode test parameters from bytes
    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() < 8 {
            return None;
        }
        Some(TestParams {
            payload_size: u16::from_be_bytes([buf[0], buf[1]]),
            retransmit: buf[2] != 0,
            reverse: buf[3] != 0,
            bidirectional: buf[4] != 0,
        })
    }
}

pub fn parse_server_addr(s: &str) -> (Ipv4Addr, u16) {
    let (host, port) = if let Some((addr_str, port_str)) = s.rsplit_once(':') {
        let port: u16 = port_str.parse().expect("Invalid port number");
        (addr_str.to_string(), port)
    } else {
        (s.to_string(), 5201)
    };

    // Try parsing as IPv4 first, then fall back to DNS resolution
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return (ip, port);
    }

    use std::net::ToSocketAddrs;
    let addr_str = format!("{host}:0");
    for addr in addr_str
        .to_socket_addrs()
        .unwrap_or_else(|e| panic!("Failed to resolve '{host}': {e}"))
    {
        if let std::net::SocketAddr::V4(v4) = addr {
            eprintln!("Resolved {host} -> {}", v4.ip());
            return (*v4.ip(), port);
        }
    }
    panic!("No IPv4 address found for '{host}'");
}
