use std::net::SocketAddrV4;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use log::{error, info, warn};
use rand::Rng;

use crate::config::{TestConfig, TestParams};
use crate::congestion::RateController;
use crate::packet::{TcpFlags, build_tcp_packet, parse_tcp_packet};
use crate::socket::{create_raw_socket, get_local_ip_for};

/// Shared atomic counters between send and recv threads
#[allow(dead_code)]
struct SharedCounters {
    interval_sent: AtomicU64,
    interval_acked: AtomicU64,
    interval_bytes_sent: AtomicU64,
    interval_bytes_recv: AtomicU64,
    total_sent: AtomicU64,
    total_acked: AtomicU64,
    total_bytes_sent: AtomicU64,
    total_bytes_recv: AtomicU64,
    /// Current sending rate in packets/sec * 1000 (fixed point)
    rate_millipps: AtomicU64,
    /// Smoothed RTT in microseconds
    srtt_us: AtomicU64,
    min_rtt_us: AtomicU64,
    /// Connection state: 0=handshake, 1=data, 2=closing
    state: AtomicU32,
    /// Last ACK number received from peer (for retransmit tracking)
    last_ack_num: AtomicU32,
    /// Count of consecutive duplicate ACKs
    dup_ack_count: AtomicU32,
    /// Total retransmissions
    retransmit_count: AtomicU64,
    /// Total interval retransmissions
    interval_retransmits: AtomicU64,
    /// Highest sequence number sent (updated by send thread)
    highest_sent_seq: AtomicU32,
    /// Highest ACK number received (updated by recv thread, always tracked)
    highest_recv_ack: AtomicU32,
    /// Highest data sequence number received (for reverse/bidir)
    highest_recv_data_seq: AtomicU32,
    /// Interval received data packets (for receive window %)
    interval_recv_packets: AtomicU64,
}

impl SharedCounters {
    fn new() -> Self {
        SharedCounters {
            interval_sent: AtomicU64::new(0),
            interval_acked: AtomicU64::new(0),
            interval_bytes_sent: AtomicU64::new(0),
            interval_bytes_recv: AtomicU64::new(0),
            total_sent: AtomicU64::new(0),
            total_acked: AtomicU64::new(0),
            total_bytes_sent: AtomicU64::new(0),
            total_bytes_recv: AtomicU64::new(0),
            rate_millipps: AtomicU64::new(10_000), // 10 pps
            srtt_us: AtomicU64::new(0),
            min_rtt_us: AtomicU64::new(u64::MAX),
            state: AtomicU32::new(0),
            last_ack_num: AtomicU32::new(0),
            dup_ack_count: AtomicU32::new(0),
            retransmit_count: AtomicU64::new(0),
            interval_retransmits: AtomicU64::new(0),
            highest_sent_seq: AtomicU32::new(0),
            highest_recv_ack: AtomicU32::new(0),
            highest_recv_data_seq: AtomicU32::new(0),
            interval_recv_packets: AtomicU64::new(0),
        }
    }
}

pub fn run_client(config: TestConfig, src_port: u16, shutdown: Arc<AtomicBool>) {
    let local_ip = match get_local_ip_for(config.server_addr) {
        Ok(ip) => ip,
        Err(e) => {
            error!("Failed to determine local IP: {e}");
            return;
        }
    };

    let src_port = if src_port == 0 {
        rand::rng().random_range(10000..60000u16)
    } else {
        src_port
    };

    info!("Client: {local_ip}:{src_port} -> {}:{}", config.server_addr, config.server_port);

    let (sender, receiver, _guard) = match create_raw_socket(local_ip, src_port) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to create raw socket: {e}. Are you running as root?");
            return;
        }
    };

    let dst = SocketAddrV4::new(config.server_addr, config.server_port);
    let isn: u32 = rand::rng().random();

    // === HANDSHAKE ===
    let params = TestParams {
        payload_size: config.payload_size,
        retransmit: config.retransmit,
        reverse: config.reverse,
        bidirectional: config.bidirectional,
    };
    let syn_payload = params.to_bytes();

    info!("Sending SYN (ISN={isn})...");
    let syn = build_tcp_packet(
        local_ip, config.server_addr, src_port, config.server_port,
        isn, 0, TcpFlags::SYN, 65535, &syn_payload,
    );
    sender.send_to(&syn, dst).expect("Failed to send SYN");

    let mut buf = vec![0u8; 65535];
    let syn_start = Instant::now();
    let mut last_syn_send = Instant::now();
    let server_isn;

    loop {
        if shutdown.load(Ordering::Relaxed) {
            eprintln!("Interrupted during handshake");
            return;
        }
        if syn_start.elapsed() > Duration::from_secs(10) {
            error!("Handshake timeout");
            return;
        }

        if let Some(n) = receiver.recv(&mut buf) {
            if let Some(pkt) = parse_tcp_packet(&buf[..n]) {
                if pkt.src_port == config.server_port
                    && pkt.dst_port == src_port
                    && pkt.flags.contains(TcpFlags::SYN)
                    && pkt.flags.contains(TcpFlags::ACK)
                    && pkt.ack == isn.wrapping_add(1)
                {
                    server_isn = pkt.seq;
                    info!("Received SYN-ACK (server ISN={server_isn})");
                    break;
                }
            }
        }

        // Retransmit SYN every 500ms
        if last_syn_send.elapsed() > Duration::from_millis(500) {
            let _ = sender.send_to(&syn, dst);
            last_syn_send = Instant::now();
        }
    }

    // Send ACK to complete handshake
    let initial_seq = isn.wrapping_add(1);
    let initial_ack = server_isn.wrapping_add(1);
    let ack_pkt = build_tcp_packet(
        local_ip, config.server_addr, src_port, config.server_port,
        initial_seq, initial_ack, TcpFlags::ACK, 65535, &[],
    );
    sender.send_to(&ack_pkt, dst).expect("Failed to send ACK");
    info!("Handshake complete");

    // === DATA TRANSFER (threaded) ===
    let counters = Arc::new(SharedCounters::new());
    counters.state.store(1, Ordering::Relaxed);
    counters.last_ack_num.store(initial_seq, Ordering::Relaxed);
    counters.highest_sent_seq.store(initial_seq, Ordering::Relaxed);
    counters.highest_recv_ack.store(initial_seq, Ordering::Relaxed);
    counters.highest_recv_data_seq.store(initial_ack, Ordering::Relaxed);
    /// ACK number the send thread should use (updated by recv thread for piggybacking)
    struct OutgoingAck(AtomicU32);
    let outgoing_ack = Arc::new(OutgoingAck(AtomicU32::new(initial_ack)));

    let is_sender = !config.reverse;
    let is_receiver = config.reverse || config.bidirectional;
    let retransmit = config.retransmit;

    eprintln!(
        "Starting data transfer (mode: {}{})",
        if config.bidirectional { "bidirectional" }
        else if config.reverse { "reverse (server→client)" }
        else { "normal (client→server)" },
        if retransmit { ", retransmission ON" } else { "" }
    );

    // Send thread
    let send_shutdown = shutdown.clone();
    let send_counters = counters.clone();
    let payload_size = config.payload_size;
    let send_handle = if is_sender {
        let out_ack = outgoing_ack.clone();
        let handle = thread::spawn(move || {
            let payload = vec![0xAA; payload_size as usize];
            let mut seq = initial_seq;
            // RTO timer: retransmit if no ACK progress for this duration
            let mut last_ack_advance = Instant::now();
            let mut prev_ack = initial_seq;
            let rto = Duration::from_millis(500);

            while !send_shutdown.load(Ordering::Relaxed)
                && send_counters.state.load(Ordering::Relaxed) == 1
            {
                let rate_mpps = send_counters.rate_millipps.load(Ordering::Relaxed);
                let interval_ns = if rate_mpps > 0 {
                    1_000_000_000_000u64 / rate_mpps // ns per packet
                } else {
                    100_000_000 // 100ms default
                };

                // In retransmit mode, check if we need to retransmit
                if retransmit {
                    let current_ack = send_counters.last_ack_num.load(Ordering::Relaxed);
                    let dup_acks = send_counters.dup_ack_count.load(Ordering::Relaxed);

                    // Track ACK advancement for RTO
                    if current_ack != prev_ack {
                        last_ack_advance = Instant::now();
                        prev_ack = current_ack;
                    }

                    // Fast retransmit (3 dup ACKs) or RTO
                    let need_retransmit = dup_acks >= 3
                        || (wrapping_gt(seq, current_ack)
                            && last_ack_advance.elapsed() > rto);

                    if need_retransmit && wrapping_gt(seq, current_ack) {
                        // Retransmit from current_ack position
                        let retransmit_pkt = build_tcp_packet(
                            local_ip, config.server_addr, src_port, config.server_port,
                            current_ack, out_ack.0.load(Ordering::Relaxed),
                            TcpFlags::ACK | TcpFlags::PSH, 65535, &payload,
                        );
                        if let Ok(_) = sender.send_to(&retransmit_pkt, dst) {
                            send_counters.retransmit_count.fetch_add(1, Ordering::Relaxed);
                            send_counters.interval_retransmits.fetch_add(1, Ordering::Relaxed);
                        }
                        // Reset dup ack count after retransmit
                        send_counters.dup_ack_count.store(0, Ordering::Relaxed);
                        last_ack_advance = Instant::now();

                        // Rate-limit retransmissions
                        if interval_ns > 10_000 {
                            thread::sleep(Duration::from_nanos(interval_ns));
                        }
                        continue;
                    }
                }

                // Send new data
                let pkt = build_tcp_packet(
                    local_ip, config.server_addr, src_port, config.server_port,
                    seq, out_ack.0.load(Ordering::Relaxed), TcpFlags::ACK | TcpFlags::PSH, 65535, &payload,
                );

                if let Err(e) = sender.send_to(&pkt, dst) {
                    warn!("Send error: {e}");
                    thread::sleep(Duration::from_millis(1));
                    continue;
                }

                send_counters.interval_sent.fetch_add(1, Ordering::Relaxed);
                send_counters.total_sent.fetch_add(1, Ordering::Relaxed);
                send_counters.interval_bytes_sent.fetch_add(payload_size as u64, Ordering::Relaxed);
                send_counters.total_bytes_sent.fetch_add(payload_size as u64, Ordering::Relaxed);

                seq = seq.wrapping_add(payload_size as u32);
                send_counters.highest_sent_seq.store(seq, Ordering::Relaxed);

                if interval_ns > 10_000 {
                    thread::sleep(Duration::from_nanos(interval_ns));
                } else {
                    std::hint::spin_loop();
                }
            }

            // Send FIN on shutdown
            if send_counters.state.load(Ordering::Relaxed) == 1 {
                send_counters.state.store(2, Ordering::Relaxed);
            }
            let fin = build_tcp_packet(
                local_ip, config.server_addr, src_port, config.server_port,
                seq, out_ack.0.load(Ordering::Relaxed), TcpFlags::FIN | TcpFlags::ACK, 65535, &[],
            );
            let _ = sender.send_to(&fin, dst);
            info!("FIN sent");
            thread::sleep(Duration::from_millis(500));
        });
        Some(handle)
    } else {
        // If we're not sending data, we still need the sender for ACKs.
        // Move sender into recv thread via Arc. For simplicity, if reverse-only,
        // the recv thread handles ACK sending and FIN on shutdown.
        None
    };

    // Receive thread (runs on main thread if we have no send thread, or spawned)
    let recv_shutdown = shutdown.clone();
    let recv_counters = counters.clone();
    let recv_out_ack = outgoing_ack.clone();

    let recv_fn = move || {
        let mut buf = vec![0u8; 65535];
        let mut prev_ack_num = initial_seq;
        let mut highest_recv_seq = initial_ack;

        while !recv_shutdown.load(Ordering::Relaxed)
            && recv_counters.state.load(Ordering::Relaxed) <= 1
        {
            if let Some(n) = receiver.recv(&mut buf) {
                if let Some(pkt) = parse_tcp_packet(&buf[..n]) {
                    if pkt.src_port != config.server_port || pkt.dst_port != src_port {
                        continue;
                    }

                    if pkt.flags.contains(TcpFlags::RST) {
                        eprintln!("Received RST from server");
                        recv_counters.state.store(2, Ordering::Relaxed);
                        return;
                    }

                    if pkt.flags.contains(TcpFlags::FIN) {
                        info!("Received FIN from server");
                        recv_counters.state.store(2, Ordering::Relaxed);
                        return;
                    }

                    if pkt.flags.contains(TcpFlags::ACK) && is_sender {
                        let ack_num = pkt.ack;

                        // Always track highest ACK for diagnostic output
                        if wrapping_gt(ack_num, recv_counters.highest_recv_ack.load(Ordering::Relaxed)) {
                            recv_counters.highest_recv_ack.store(ack_num, Ordering::Relaxed);
                        }

                        // Track duplicate ACKs for fast retransmit
                        if retransmit {
                            if ack_num == prev_ack_num {
                                recv_counters.dup_ack_count.fetch_add(1, Ordering::Relaxed);
                            } else if wrapping_gt(ack_num, prev_ack_num) {
                                recv_counters.dup_ack_count.store(0, Ordering::Relaxed);
                                recv_counters.last_ack_num.store(ack_num, Ordering::Relaxed);
                                prev_ack_num = ack_num;
                            }
                        }

                        recv_counters.interval_acked.fetch_add(1, Ordering::Relaxed);
                        recv_counters.total_acked.fetch_add(1, Ordering::Relaxed);
                    }

                    if is_receiver && !pkt.payload.is_empty() {
                        let plen = pkt.payload.len() as u64;
                        recv_counters.interval_bytes_recv.fetch_add(plen, Ordering::Relaxed);
                        recv_counters.total_bytes_recv.fetch_add(plen, Ordering::Relaxed);
                        recv_counters.interval_recv_packets.fetch_add(1, Ordering::Relaxed);

                        // Track highest received data seq for window %
                        let pkt_end = pkt.seq.wrapping_add(pkt.payload.len() as u32);
                        if wrapping_gt(pkt_end, recv_counters.highest_recv_data_seq.load(Ordering::Relaxed)) {
                            recv_counters.highest_recv_data_seq.store(pkt_end, Ordering::Relaxed);
                        }

                        // Update outgoing ACK for piggybacking on data packets
                        if wrapping_gt(pkt_end, highest_recv_seq) {
                            highest_recv_seq = pkt_end;
                            recv_out_ack.0.store(highest_recv_seq, Ordering::Relaxed);
                        }
                    }
                }
            }
        }
    };

    if send_handle.is_some() {
        // Spawn recv on a separate thread
        let recv_handle = thread::spawn(recv_fn);

        // Main thread: stats reporting and congestion control
        let mut rate_ctrl = RateController::new(config.multiplier, config.rate_base);
        let start = Instant::now();
        let mut last_report = Instant::now();
        let mut prev_highest_sent_seq = initial_seq;
        let mut prev_highest_recv_ack = initial_seq;
        let mut prev_highest_recv_data_seq = initial_ack;

        while !shutdown.load(Ordering::Relaxed) && counters.state.load(Ordering::Relaxed) == 1 {
            thread::sleep(Duration::from_millis(50));

            if last_report.elapsed().as_secs_f64() >= config.interval_secs {
                let sent = counters.interval_sent.swap(0, Ordering::Relaxed);
                let acked = counters.interval_acked.swap(0, Ordering::Relaxed);
                let _bytes_sent = counters.interval_bytes_sent.swap(0, Ordering::Relaxed);
                let bytes_recv = counters.interval_bytes_recv.swap(0, Ordering::Relaxed);
                let retransmits = counters.interval_retransmits.swap(0, Ordering::Relaxed);
                let recv_packets = counters.interval_recv_packets.swap(0, Ordering::Relaxed);
                let elapsed = last_report.elapsed().as_secs_f64();

                // Sequence tracking
                let cur_highest_sent = counters.highest_sent_seq.load(Ordering::Relaxed);
                let cur_highest_ack = counters.highest_recv_ack.load(Ordering::Relaxed);
                let cur_highest_recv_data = counters.highest_recv_data_seq.load(Ordering::Relaxed);

                rate_ctrl.update(sent, acked);
                let t = start.elapsed().as_secs_f64();

                // === SEND stats ===
                if is_sender {
                    // ACK window %: % of sent seq space that has been acked
                    let seq_delta = cur_highest_sent.wrapping_sub(prev_highest_sent_seq);
                    let ack_delta = cur_highest_ack.wrapping_sub(prev_highest_recv_ack);

                    let ack_pct = if seq_delta > 0 {
                        ack_delta as f64 / seq_delta as f64 * 100.0
                    } else {
                        100.0
                    };

                    // BW inferred from ACK advancement rate
                    let inferred_bw = ack_delta as f64 * 8.0 / elapsed;

                    let retransmit_str = if retransmit {
                        format!(" retx={retransmits}")
                    } else {
                        String::new()
                    };

                    eprintln!(
                        "[{t:6.1}s] SEND: seq={cur_highest_sent} ack={cur_highest_ack} \
                         delta_seq={seq_delta} delta_ack={ack_delta} \
                         ack_recv={ack_pct:.1}%{retransmit_str} \
                         rate={:.0}pps BW(inferred)={}",
                        rate_ctrl.rate(),
                        format_bps(inferred_bw),
                    );

                    prev_highest_sent_seq = cur_highest_sent;
                    prev_highest_recv_ack = cur_highest_ack;
                }

                // === RECV stats ===
                if is_receiver {
                    // Receive window %: actual bytes received / seq window covered
                    let recv_seq_delta = cur_highest_recv_data.wrapping_sub(prev_highest_recv_data_seq);
                    let recv_pct = if recv_seq_delta > 0 {
                        bytes_recv as f64 / recv_seq_delta as f64 * 100.0
                    } else {
                        100.0
                    };

                    // Actual receive BW
                    let actual_recv_bw = bytes_recv as f64 * 8.0 / elapsed;

                    eprintln!(
                        "[{t:6.1}s] RECV: seq={cur_highest_recv_data} \
                         pkts={recv_packets} recv={recv_pct:.1}% \
                         BW(actual)={}",
                        format_bps(actual_recv_bw),
                    );

                    prev_highest_recv_data_seq = cur_highest_recv_data;
                }

                // Update rate for send thread
                counters.rate_millipps.store(
                    (rate_ctrl.rate() * 1000.0) as u64,
                    Ordering::Relaxed,
                );

                last_report = Instant::now();
            }
        }

        // Signal shutdown
        counters.state.store(2, Ordering::Relaxed);
        shutdown.store(true, Ordering::Relaxed);

        if let Some(h) = send_handle {
            let _ = h.join();
        }
        let _ = recv_handle.join();

        // Print summary
        print_summary(&counters, start.elapsed().as_secs_f64(), is_sender, is_receiver, payload_size, initial_seq, initial_ack);
    } else {
        // reverse-only mode: run recv on main thread
        recv_fn();
        // print summary
        print_summary(&counters, 0.0, is_sender, is_receiver, payload_size, initial_seq, initial_ack);
    }
}

fn print_summary(counters: &SharedCounters, elapsed: f64, is_sender: bool, is_receiver: bool, _payload_size: u16, initial_seq: u32, initial_ack: u32) {
    let total_bytes_sent = counters.total_bytes_sent.load(Ordering::Relaxed);
    let total_bytes_recv = counters.total_bytes_recv.load(Ordering::Relaxed);
    let total_retransmits = counters.retransmit_count.load(Ordering::Relaxed);
    let highest_sent = counters.highest_sent_seq.load(Ordering::Relaxed);
    let highest_ack = counters.highest_recv_ack.load(Ordering::Relaxed);

    eprintln!("\n--- Client Test Summary ---");
    eprintln!("Duration:        {elapsed:.1}s");

    if is_sender {
        let avg_send = if elapsed > 0.0 { total_bytes_sent as f64 * 8.0 / elapsed } else { 0.0 };

        let seq_span = highest_sent.wrapping_sub(initial_seq);
        let ack_span = highest_ack.wrapping_sub(initial_seq);
        let ack_pct = if seq_span > 0 {
            ack_span as f64 / seq_span as f64 * 100.0
        } else {
            100.0
        };
        let inferred_bw = if elapsed > 0.0 { ack_span as f64 * 8.0 / elapsed } else { 0.0 };

        eprintln!("--- Sending ---");
        eprintln!("  Seq span:        {seq_span}");
        eprintln!("  ACK span:        {ack_span}");
        eprintln!("  Retransmissions: {total_retransmits}");
        eprintln!("  ACK recv:        {ack_pct:.2}%");
        eprintln!("  Avg TX rate:     {}", format_bps(avg_send));
        eprintln!("  BW(inferred):    {}", format_bps(inferred_bw));
    }

    if is_receiver {
        let avg_recv = if elapsed > 0.0 { total_bytes_recv as f64 * 8.0 / elapsed } else { 0.0 };
        let highest_recv_data = counters.highest_recv_data_seq.load(Ordering::Relaxed);
        let recv_span = highest_recv_data.wrapping_sub(initial_ack);
        let recv_pct = if recv_span > 0 {
            total_bytes_recv as f64 / recv_span as f64 * 100.0
        } else {
            100.0
        };

        eprintln!("--- Receiving ---");
        eprintln!("  Bytes received:  {total_bytes_recv}");
        eprintln!("  Recv window:     {recv_pct:.2}%");
        eprintln!("  BW(actual):      {}", format_bps(avg_recv));
    }
}

/// Compare TCP sequence numbers with wrapping
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
