use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use log::{error, info, warn};
use rand::Rng;

use crate::config::TestParams;
use crate::packet::{TcpFlags, build_tcp_packet, parse_tcp_packet};
use crate::socket::create_raw_socket;

pub fn run_server(bind_addr: Ipv4Addr, port: u16, shutdown: Arc<AtomicBool>) {
    let (sender, receiver, _guard) = match create_raw_socket(bind_addr, port) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to create raw socket: {e}. Are you running as root?");
            return;
        }
    };

    eprintln!("Server listening on {bind_addr}:{port}");

    let mut buf = vec![0u8; 65535];

    while !shutdown.load(Ordering::Relaxed) {
        if let Some(n) = receiver.recv(&mut buf) {
            if let Some(pkt) = parse_tcp_packet(&buf[..n]) {
                if pkt.dst_port != port {
                    continue;
                }

                if pkt.flags.contains(TcpFlags::SYN) && !pkt.flags.contains(TcpFlags::ACK) {
                    eprintln!(
                        "Incoming connection from {}:{} (ISN={})",
                        pkt.src_ip, pkt.src_port, pkt.seq
                    );

                    let params = TestParams::from_bytes(&pkt.payload).unwrap_or(TestParams {
                        payload_size: 1400,
                        retransmit: false,
                        reverse: false,
                        bidirectional: false,
                    });

                    eprintln!(
                        "Test params: payload={}B, retransmit={}, reverse={}, bidir={}",
                        params.payload_size, params.retransmit, params.reverse, params.bidirectional
                    );

                    handle_connection(
                        &sender,
                        &receiver,
                        bind_addr,
                        port,
                        pkt.src_ip,
                        pkt.src_port,
                        pkt.seq,
                        params,
                        shutdown.clone(),
                    );

                    eprintln!("Connection ended, waiting for new connections...");
                }
            }
        }
    }

    eprintln!("Server shutting down");
}

fn handle_connection(
    sender: &crate::socket::RawSender,
    receiver: &crate::socket::RawReceiver,
    local_ip: Ipv4Addr,
    local_port: u16,
    remote_ip: Ipv4Addr,
    remote_port: u16,
    client_isn: u32,
    params: TestParams,
    shutdown: Arc<AtomicBool>,
) {
    // Resolve actual local IP if bound to 0.0.0.0, so that TCP checksums
    // in outgoing packets are computed with the real source IP.
    let local_ip = if local_ip.is_unspecified() {
        match crate::socket::get_local_ip_for(remote_ip) {
            Ok(ip) => {
                info!("Resolved local IP for {remote_ip}: {ip}");
                ip
            }
            Err(e) => {
                error!("Cannot determine local IP for {remote_ip}: {e}");
                return;
            }
        }
    } else {
        local_ip
    };

    let server_isn: u32 = rand::rng().random();
    let dst = SocketAddrV4::new(remote_ip, remote_port);

    // === SYN-ACK ===
    let syn_ack = build_tcp_packet(
        local_ip, remote_ip, local_port, remote_port,
        server_isn, client_isn.wrapping_add(1),
        TcpFlags::SYN_ACK, 65535, &[],
    );
    sender.send_to(&syn_ack, dst).expect("Failed to send SYN-ACK");
    info!("Sent SYN-ACK (ISN={server_isn})");

    // Wait for ACK
    let mut buf = vec![0u8; 65535];
    let handshake_start = Instant::now();

    loop {
        if shutdown.load(Ordering::Relaxed) {
            return;
        }
        if handshake_start.elapsed() > Duration::from_secs(10) {
            warn!("Handshake timeout");
            return;
        }

        if let Some(n) = receiver.recv(&mut buf) {
            if let Some(pkt) = parse_tcp_packet(&buf[..n]) {
                if pkt.src_ip != remote_ip || pkt.src_port != remote_port || pkt.dst_port != local_port {
                    continue;
                }

                // Retransmitted SYN
                if pkt.flags.contains(TcpFlags::SYN) && !pkt.flags.contains(TcpFlags::ACK) {
                    let _ = sender.send_to(&syn_ack, dst);
                    continue;
                }

                if pkt.flags.contains(TcpFlags::ACK) {
                    info!("Handshake complete");
                    break;
                }
            }
        }
    }

    // === DATA TRANSFER ===
    let mut next_seq = server_isn.wrapping_add(1);
    let mut highest_seq_seen = client_isn.wrapping_add(1);
    let mut next_ack = client_isn.wrapping_add(1);

    let payload = vec![0xBB; params.payload_size as usize];
    let is_sender = params.reverse || params.bidirectional;
    let is_receiver = !params.reverse || params.bidirectional;

    let start = Instant::now();
    let mut last_report = Instant::now();
    let mut total_recv_packets: u64 = 0;
    let mut total_recv_bytes: u64 = 0;
    let mut _total_sent_packets: u64 = 0;
    let mut _total_acked_packets: u64 = 0;
    let mut interval_recv_packets: u64 = 0;
    let mut interval_recv_bytes: u64 = 0;
    let mut _interval_sent_packets: u64 = 0;
    let mut _interval_acked_packets: u64 = 0;

    // Sequence tracking for diagnostic output
    let mut highest_recv_data_seq = client_isn.wrapping_add(1);
    let mut prev_highest_recv_data_seq = highest_recv_data_seq;
    let mut highest_sent_seq = next_seq;
    let mut prev_highest_sent_seq = highest_sent_seq;
    let mut highest_recv_ack = next_seq; // ACK for our sent data
    let mut prev_highest_recv_ack = highest_recv_ack;

    // For reverse mode: match client's probed rate
    let mut send_rate: f64 = 10.0;
    let mut last_send = Instant::now();

    eprintln!("Data transfer started");

    while !shutdown.load(Ordering::Relaxed) {
        // === SEND (reverse/bidir) ===
        if is_sender {
            let interval_ns = if send_rate > 0.0 {
                (1_000_000_000.0 / send_rate) as u64
            } else {
                100_000_000
            };

            if last_send.elapsed() >= Duration::from_nanos(interval_ns) {
                let data_pkt = build_tcp_packet(
                    local_ip, remote_ip, local_port, remote_port,
                    next_seq, next_ack, TcpFlags::ACK | TcpFlags::PSH, 65535, &payload,
                );

                if let Err(e) = sender.send_to(&data_pkt, dst) {
                    warn!("Send error: {e}");
                } else {
                    _total_sent_packets += 1;
                    _interval_sent_packets += 1;
                    next_seq = next_seq.wrapping_add(params.payload_size as u32);
                    highest_sent_seq = next_seq;
                }
                last_send = Instant::now();
            }
        }

        // === RECEIVE ===
        if let Some(n) = receiver.recv(&mut buf) {
            if let Some(pkt) = parse_tcp_packet(&buf[..n]) {
                if pkt.src_ip != remote_ip || pkt.src_port != remote_port || pkt.dst_port != local_port {
                    continue;
                }

                if pkt.flags.contains(TcpFlags::RST) {
                    eprintln!("Received RST, closing");
                    break;
                }

                if pkt.flags.contains(TcpFlags::FIN) {
                    info!("Received FIN");
                    let fin_ack = build_tcp_packet(
                        local_ip, remote_ip, local_port, remote_port,
                        next_seq, pkt.seq.wrapping_add(1),
                        TcpFlags::FIN | TcpFlags::ACK, 65535, &[],
                    );
                    let _ = sender.send_to(&fin_ack, dst);
                    eprintln!("Connection closed (FIN)");
                    break;
                }

                // Data received
                if !pkt.payload.is_empty() {
                    let plen = pkt.payload.len() as u64;
                    total_recv_packets += 1;
                    total_recv_bytes += plen;
                    interval_recv_packets += 1;
                    interval_recv_bytes += plen;

                    // Track highest received data seq
                    let pkt_end = pkt.seq.wrapping_add(pkt.payload.len() as u32);
                    if wrapping_gt(pkt_end, highest_recv_data_seq) {
                        highest_recv_data_seq = pkt_end;
                    }

                    // ACK handling: in no-retransmit mode, always advance ACK
                    if !params.retransmit {
                        if wrapping_gt(pkt_end, highest_seq_seen) {
                            highest_seq_seen = pkt_end;
                        }
                        next_ack = highest_seq_seen;
                    } else {
                        if pkt.seq == next_ack {
                            next_ack = pkt.seq.wrapping_add(pkt.payload.len() as u32);
                        }
                    }

                    // Send ACK
                    let ack_pkt = build_tcp_packet(
                        local_ip, remote_ip, local_port, remote_port,
                        next_seq, next_ack, TcpFlags::ACK, 65535, &[],
                    );
                    let _ = sender.send_to(&ack_pkt, dst);

                    // Adjust reverse send rate based on incoming rate
                    if is_sender && total_recv_packets > 10 {
                        let elapsed = start.elapsed().as_secs_f64();
                        send_rate = total_recv_packets as f64 / elapsed * 1.1;
                    }
                }

                // Track ACKs for our sent data (reverse/bidir) - from ANY packet with ACK flag
                if is_sender && pkt.flags.contains(TcpFlags::ACK) {
                    if wrapping_gt(pkt.ack, highest_recv_ack) {
                        highest_recv_ack = pkt.ack;
                    }
                    _total_acked_packets += 1;
                    _interval_acked_packets += 1;
                }
            }
        }

        // === STATS ===
        if last_report.elapsed().as_secs_f64() >= 1.0 {
            let elapsed = last_report.elapsed().as_secs_f64();
            let t = start.elapsed().as_secs_f64();

            // RECV stats (when receiving data from client)
            if is_receiver {
                let recv_bps = interval_recv_bytes as f64 * 8.0 / elapsed;

                // Receive window %: actual bytes received / seq window covered
                let recv_seq_delta = highest_recv_data_seq.wrapping_sub(prev_highest_recv_data_seq);
                let recv_pct = if recv_seq_delta > 0 {
                    interval_recv_bytes as f64 / recv_seq_delta as f64 * 100.0
                } else {
                    100.0
                };

                eprintln!(
                    "[{t:6.1}s] RECV: seq={highest_recv_data_seq} \
                     pkts={interval_recv_packets} recv={recv_pct:.1}% \
                     BW(actual)={}",
                    format_bps(recv_bps),
                );

                prev_highest_recv_data_seq = highest_recv_data_seq;
            }

            // SEND stats (when sending data in reverse/bidir)
            if is_sender {
                let ack_delta = highest_recv_ack.wrapping_sub(prev_highest_recv_ack);
                let seq_delta = highest_sent_seq.wrapping_sub(prev_highest_sent_seq);

                let ack_pct = if seq_delta > 0 {
                    ack_delta as f64 / seq_delta as f64 * 100.0
                } else {
                    100.0
                };

                // BW inferred from ACK advancement rate
                let inferred_bw = ack_delta as f64 * 8.0 / elapsed;

                eprintln!(
                    "[{t:6.1}s] SEND: seq={highest_sent_seq} ack={highest_recv_ack} \
                     delta_seq={seq_delta} delta_ack={ack_delta} \
                     ack_recv={ack_pct:.1}% BW(inferred)={}",
                    format_bps(inferred_bw),
                );

                prev_highest_sent_seq = highest_sent_seq;
                prev_highest_recv_ack = highest_recv_ack;
            }

            interval_recv_packets = 0;
            interval_recv_bytes = 0;
            _interval_sent_packets = 0;
            _interval_acked_packets = 0;
            last_report = Instant::now();
        }
    }

    // Shutdown: send FIN
    if shutdown.load(Ordering::Relaxed) {
        let fin = build_tcp_packet(
            local_ip, remote_ip, local_port, remote_port,
            next_seq, next_ack, TcpFlags::FIN | TcpFlags::ACK, 65535, &[],
        );
        let _ = sender.send_to(&fin, dst);
        eprintln!("Server sent FIN");
    }

    let elapsed = start.elapsed().as_secs_f64();

    eprintln!("\n--- Server Connection Summary ---");
    eprintln!("Duration:       {elapsed:.1}s");

    if is_receiver {
        let avg_recv_bps = if elapsed > 0.0 {
            total_recv_bytes as f64 * 8.0 / elapsed
        } else {
            0.0
        };
        eprintln!("--- Receiving ---");
        eprintln!("  Packets recv:   {total_recv_packets}");
        eprintln!("  BW(actual):     {}", format_bps(avg_recv_bps));
    }

    if is_sender {
        let send_base = server_isn.wrapping_add(1);
        let seq_span = highest_sent_seq.wrapping_sub(send_base);
        let ack_span = highest_recv_ack.wrapping_sub(send_base);
        let ack_pct = if seq_span > 0 {
            ack_span as f64 / seq_span as f64 * 100.0
        } else {
            100.0
        };
        let inferred_bw = if elapsed > 0.0 {
            ack_span as f64 * 8.0 / elapsed
        } else {
            0.0
        };
        eprintln!("--- Sending ---");
        eprintln!("  Seq span:       {seq_span}");
        eprintln!("  ACK span:       {ack_span}");
        eprintln!("  ACK recv:       {ack_pct:.2}%");
        eprintln!("  BW(inferred):   {}", format_bps(inferred_bw));
    }
}

fn wrapping_gt(a: u32, b: u32) -> bool {
    let diff = a.wrapping_sub(b);
    diff > 0 && diff < 0x80000000
}

fn format_bps(bps: f64) -> String {
    if bps >= 1_000_000_000.0 {
        format!("{:.2} Gbps", bps / 1_000_000_000.0)
    } else if bps >= 1_000_000.0 {
        format!("{:.2} Mbps", bps / 1_000_000.0)
    } else if bps >= 1_000.0 {
        format!("{:.2} Kbps", bps / 1_000.0)
    } else {
        format!("{:.0} bps", bps)
    }
}
