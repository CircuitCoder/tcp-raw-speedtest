mod client;
mod config;
mod congestion;
mod packet;
mod server;
mod socket;
mod stats;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use clap::Parser;
use log::info;

use config::{Cli, Mode, TestConfig, parse_server_addr};

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();

    let cli = Cli::parse();

    // Check we're running as root
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("Error: this tool requires root privileges for raw sockets.");
        eprintln!("Please run with: sudo {}", std::env::args().next().unwrap_or_default());
        std::process::exit(1);
    }

    // Set up Ctrl-C handler
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        eprintln!("\nCtrl-C received, shutting down...");
        shutdown_clone.store(true, Ordering::Relaxed);
    })
    .expect("Failed to set Ctrl-C handler");

    match cli.mode {
        Mode::Server { port, bind } => {
            let bind_addr: std::net::Ipv4Addr = bind.parse().expect("Invalid bind address");
            info!("Starting server on {bind_addr}:{port}");
            server::run_server(bind_addr, port, shutdown);
        }
        Mode::Client {
            server,
            payload_size,
            multiplier,
            retransmit,
            reverse,
            bidirectional,
            interval,
            base,
            sport,
        } => {
            let (server_addr, server_port) = parse_server_addr(&server);
            let config = TestConfig {
                server_addr,
                server_port,
                payload_size,
                multiplier,
                retransmit,
                reverse,
                bidirectional,
                interval_secs: interval,
                rate_base: base,
            };
            info!("Starting client connecting to {server_addr}:{server_port}");
            client::run_client(config, sport, shutdown);
        }
    }
}

