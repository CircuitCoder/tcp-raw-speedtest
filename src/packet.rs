use std::net::Ipv4Addr;

/// Build a raw TCP packet (IP header + TCP header + payload).
/// Returns the full IP packet bytes ready to send.
pub fn build_tcp_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: TcpFlags,
    window: u16,
    payload: &[u8],
) -> Vec<u8> {
    let tcp_header_len = 20u8; // no options
    let ip_header_len = 20u16;
    let tcp_total_len = tcp_header_len as u16 + payload.len() as u16;
    let ip_total_len = ip_header_len + tcp_total_len;

    let mut pkt = vec![0u8; ip_total_len as usize];

    // === IP Header ===
    pkt[0] = 0x45; // version 4, IHL 5
    pkt[1] = 0x00; // DSCP/ECN
    pkt[2..4].copy_from_slice(&ip_total_len.to_be_bytes());
    pkt[4..6].copy_from_slice(&0u16.to_be_bytes()); // identification
    pkt[6] = 0x40; // Don't Fragment
    pkt[7] = 0x00;
    pkt[8] = 64; // TTL
    pkt[9] = 6; // protocol: TCP
    pkt[10..12].copy_from_slice(&0u16.to_be_bytes()); // checksum (kernel fills)
    pkt[12..16].copy_from_slice(&src_ip.octets());
    pkt[16..20].copy_from_slice(&dst_ip.octets());

    // === TCP Header ===
    let tcp = &mut pkt[20..];
    tcp[0..2].copy_from_slice(&src_port.to_be_bytes());
    tcp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    tcp[4..8].copy_from_slice(&seq.to_be_bytes());
    tcp[8..12].copy_from_slice(&ack.to_be_bytes());
    tcp[12] = (tcp_header_len / 4) << 4; // data offset
    tcp[13] = flags.bits();
    tcp[14..16].copy_from_slice(&window.to_be_bytes());
    tcp[16..18].copy_from_slice(&0u16.to_be_bytes()); // checksum placeholder
    tcp[18..20].copy_from_slice(&0u16.to_be_bytes()); // urgent pointer

    // Copy payload
    if !payload.is_empty() {
        tcp[20..20 + payload.len()].copy_from_slice(payload);
    }

    // Compute TCP checksum (pseudo-header + tcp segment)
    let checksum = tcp_checksum(src_ip, dst_ip, &pkt[20..]);
    pkt[36..38].copy_from_slice(&checksum.to_be_bytes());

    pkt
}

/// Parse an incoming IP packet into TCP fields
#[derive(Debug)]
#[allow(dead_code)]
pub struct ParsedPacket {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: TcpFlags,
    pub window: u16,
    pub payload: Vec<u8>,
}

pub fn parse_tcp_packet(data: &[u8]) -> Option<ParsedPacket> {
    if data.len() < 40 {
        return None; // minimum IP(20) + TCP(20)
    }

    let ip_version = (data[0] >> 4) & 0xF;
    if ip_version != 4 {
        return None;
    }

    let ip_ihl = (data[0] & 0xF) as usize * 4;
    if data.len() < ip_ihl + 20 {
        return None;
    }

    let protocol = data[9];
    if protocol != 6 {
        return None; // not TCP
    }

    let src_ip = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let dst_ip = Ipv4Addr::new(data[16], data[17], data[18], data[19]);

    let tcp = &data[ip_ihl..];
    if tcp.len() < 20 {
        return None;
    }

    let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
    let ack = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
    let data_offset = ((tcp[12] >> 4) & 0xF) as usize * 4;
    let flags = TcpFlags::from_bits(tcp[13]);
    let window = u16::from_be_bytes([tcp[14], tcp[15]]);

    let payload = if tcp.len() > data_offset {
        tcp[data_offset..].to_vec()
    } else {
        vec![]
    };

    Some(ParsedPacket {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        seq,
        ack,
        flags,
        window,
        payload,
    })
}

/// TCP flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpFlags(u8);

impl TcpFlags {
    pub const FIN: TcpFlags = TcpFlags(0x01);
    pub const SYN: TcpFlags = TcpFlags(0x02);
    pub const RST: TcpFlags = TcpFlags(0x04);
    pub const PSH: TcpFlags = TcpFlags(0x08);
    pub const ACK: TcpFlags = TcpFlags(0x10);
    pub const SYN_ACK: TcpFlags = TcpFlags(0x12);
    #[allow(dead_code)]
    pub const FIN_ACK: TcpFlags = TcpFlags(0x11);

    pub fn bits(self) -> u8 {
        self.0
    }

    pub fn from_bits(b: u8) -> Self {
        TcpFlags(b)
    }

    pub fn contains(self, other: TcpFlags) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl std::ops::BitOr for TcpFlags {
    type Output = TcpFlags;
    fn bitor(self, rhs: Self) -> Self::Output {
        TcpFlags(self.0 | rhs.0)
    }
}

impl std::fmt::Display for TcpFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut parts = vec![];
        if self.contains(TcpFlags::SYN) {
            parts.push("SYN");
        }
        if self.contains(TcpFlags::ACK) {
            parts.push("ACK");
        }
        if self.contains(TcpFlags::FIN) {
            parts.push("FIN");
        }
        if self.contains(TcpFlags::RST) {
            parts.push("RST");
        }
        if self.contains(TcpFlags::PSH) {
            parts.push("PSH");
        }
        if parts.is_empty() {
            write!(f, "NONE")
        } else {
            write!(f, "{}", parts.join("|"))
        }
    }
}

/// Compute TCP checksum over pseudo-header + TCP segment
fn tcp_checksum(src: Ipv4Addr, dst: Ipv4Addr, tcp_segment: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Pseudo header
    let src_octets = src.octets();
    let dst_octets = dst.octets();
    sum += u16::from_be_bytes([src_octets[0], src_octets[1]]) as u32;
    sum += u16::from_be_bytes([src_octets[2], src_octets[3]]) as u32;
    sum += u16::from_be_bytes([dst_octets[0], dst_octets[1]]) as u32;
    sum += u16::from_be_bytes([dst_octets[2], dst_octets[3]]) as u32;
    sum += 6u32; // protocol TCP
    sum += tcp_segment.len() as u32;

    // TCP segment (with checksum field zeroed - caller should have set it to 0)
    let mut i = 0;
    while i + 1 < tcp_segment.len() {
        sum += u16::from_be_bytes([tcp_segment[i], tcp_segment[i + 1]]) as u32;
        i += 2;
    }
    if i < tcp_segment.len() {
        sum += (tcp_segment[i] as u32) << 8;
    }

    // Fold carries
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_and_parse_roundtrip() {
        let pkt = build_tcp_packet(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            12345,
            5201,
            1000,
            0,
            TcpFlags::SYN,
            65535,
            &[],
        );
        let parsed = parse_tcp_packet(&pkt).unwrap();
        assert_eq!(parsed.src_port, 12345);
        assert_eq!(parsed.dst_port, 5201);
        assert_eq!(parsed.seq, 1000);
        assert!(parsed.flags.contains(TcpFlags::SYN));
    }

    #[test]
    fn test_build_with_payload() {
        let payload = vec![0xAA; 100];
        let pkt = build_tcp_packet(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            12345,
            5201,
            1000,
            500,
            TcpFlags::ACK | TcpFlags::PSH,
            65535,
            &payload,
        );
        let parsed = parse_tcp_packet(&pkt).unwrap();
        assert_eq!(parsed.payload.len(), 100);
        assert!(parsed.flags.contains(TcpFlags::ACK));
        assert!(parsed.flags.contains(TcpFlags::PSH));
    }
}
