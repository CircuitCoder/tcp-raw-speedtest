use std::time::Instant;

/// Periodic statistics tracker for the speed test
#[allow(dead_code)]
pub struct Stats {
    /// Total packets sent since start
    pub total_sent: u64,
    /// Total packets acked since start
    pub total_acked: u64,
    /// Total bytes of payload sent
    pub total_bytes_sent: u64,
    /// Total bytes of payload received (for reverse/bidir)
    pub total_bytes_recv: u64,
    /// Packets sent in current interval
    pub interval_sent: u64,
    /// Packets acked in current interval
    pub interval_acked: u64,
    /// Bytes sent in current interval
    pub interval_bytes_sent: u64,
    /// Bytes received in current interval
    pub interval_bytes_recv: u64,
    /// When the test started
    pub start_time: Instant,
    /// When the current interval started
    pub interval_start: Instant,
    /// Reporting interval in seconds
    pub interval_secs: f64,
    /// Running min RTT in microseconds
    pub min_rtt_us: u64,
    /// Smoothed RTT in microseconds
    pub srtt_us: f64,
}

#[allow(dead_code)]
impl Stats {
    pub fn new(interval_secs: f64) -> Self {
        let now = Instant::now();
        Stats {
            total_sent: 0,
            total_acked: 0,
            total_bytes_sent: 0,
            total_bytes_recv: 0,
            interval_sent: 0,
            interval_acked: 0,
            interval_bytes_sent: 0,
            interval_bytes_recv: 0,
            start_time: now,
            interval_start: now,
            interval_secs,
            min_rtt_us: u64::MAX,
            srtt_us: 0.0,
        }
    }

    pub fn record_sent(&mut self, payload_bytes: u64) {
        self.total_sent += 1;
        self.interval_sent += 1;
        self.total_bytes_sent += payload_bytes;
        self.interval_bytes_sent += payload_bytes;
    }

    pub fn record_ack(&mut self) {
        self.total_acked += 1;
        self.interval_acked += 1;
    }

    pub fn record_recv(&mut self, payload_bytes: u64) {
        self.total_bytes_recv += payload_bytes;
        self.interval_bytes_recv += payload_bytes;
    }

    pub fn record_rtt(&mut self, rtt_us: u64) {
        if rtt_us < self.min_rtt_us {
            self.min_rtt_us = rtt_us;
        }
        if self.srtt_us == 0.0 {
            self.srtt_us = rtt_us as f64;
        } else {
            self.srtt_us = 0.875 * self.srtt_us + 0.125 * rtt_us as f64;
        }
    }

    /// Check if it's time to report, and if so, print and reset interval counters.
    /// Returns (interval_sent, interval_acked) if reported, for congestion update.
    pub fn maybe_report(&mut self, current_rate: f64, loss_rate: f64) -> Option<(u64, u64)> {
        let elapsed = self.interval_start.elapsed().as_secs_f64();
        if elapsed < self.interval_secs {
            return None;
        }

        let interval_loss = if self.interval_sent > 0 {
            1.0 - (self.interval_acked as f64 / self.interval_sent as f64)
        } else {
            0.0
        };

        let send_bps = self.interval_bytes_sent as f64 * 8.0 / elapsed;
        let recv_bps = self.interval_bytes_recv as f64 * 8.0 / elapsed;
        let total_elapsed = self.start_time.elapsed().as_secs_f64();

        let rtt_str = if self.srtt_us > 0.0 {
            format!("{:.1}ms", self.srtt_us / 1000.0)
        } else {
            "-".to_string()
        };

        eprintln!(
            "[{:6.1}s] TX: {} | ACK: {} | Loss: {:.1}% (smooth {:.1}%) | Rate: {:.0} pps | \
             Send: {} | Recv: {} | RTT: {}",
            total_elapsed,
            self.interval_sent,
            self.interval_acked,
            interval_loss * 100.0,
            loss_rate * 100.0,
            current_rate,
            format_bps(send_bps),
            format_bps(recv_bps),
            rtt_str,
        );

        let result = (self.interval_sent, self.interval_acked);

        // Reset interval counters
        self.interval_sent = 0;
        self.interval_acked = 0;
        self.interval_bytes_sent = 0;
        self.interval_bytes_recv = 0;
        self.interval_start = std::time::Instant::now();

        Some(result)
    }

    pub fn print_summary(&self) {
        let elapsed = self.start_time.elapsed().as_secs_f64();
        let total_loss = if self.total_sent > 0 {
            1.0 - (self.total_acked as f64 / self.total_sent as f64)
        } else {
            0.0
        };

        let avg_send_bps = self.total_bytes_sent as f64 * 8.0 / elapsed;
        let avg_recv_bps = self.total_bytes_recv as f64 * 8.0 / elapsed;

        eprintln!("\n--- Test Summary ---");
        eprintln!("Duration:      {elapsed:.1}s");
        eprintln!("Packets sent:  {}", self.total_sent);
        eprintln!("Packets acked: {}", self.total_acked);
        eprintln!("Packet loss:   {:.2}%", total_loss * 100.0);
        eprintln!("Avg TX:        {}", format_bps(avg_send_bps));
        eprintln!("Avg RX:        {}", format_bps(avg_recv_bps));
        if self.min_rtt_us < u64::MAX {
            eprintln!("Min RTT:       {:.1}ms", self.min_rtt_us as f64 / 1000.0);
            eprintln!("Smoothed RTT:  {:.1}ms", self.srtt_us / 1000.0);
        }

        // Inferred bandwidth: effective throughput / (1 - loss_rate) isn't quite right.
        // The throughput that got through IS the bandwidth. So:
        let inferred_bw = if self.total_acked > 0 && elapsed > 0.0 {
            // goodput = acked_packets * payload_size * 8 / time
            // but we track bytes sent, and loss is (sent - acked)/sent
            // so goodput = avg_send_bps * (1 - loss)
            avg_send_bps * (1.0 - total_loss)
        } else {
            0.0
        };
        eprintln!("Inferred BW:   {}", format_bps(inferred_bw));
    }
}

#[allow(dead_code)]
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
