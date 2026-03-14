use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::Command;
use std::sync::Arc;

use log::{info, warn};

/// Sending half of the raw socket
pub struct RawSender {
    fd: OwnedFd,
}

unsafe impl Send for RawSender {}

/// Receiving half of the raw socket
pub struct RawReceiver {
    fd: OwnedFd,
}

unsafe impl Send for RawReceiver {}

/// Manages iptables cleanup on drop
pub struct IptablesGuard {
    rules: Vec<Vec<String>>,
}

impl Drop for IptablesGuard {
    fn drop(&mut self) {
        for rule_args in &self.rules {
            remove_iptables_rule(rule_args);
        }
        info!("iptables rules cleaned up");
    }
}

impl RawSender {
    pub fn send_to(&self, packet: &[u8], dst: SocketAddrV4) -> io::Result<usize> {
        let addr = libc::sockaddr_in {
            sin_family: libc::AF_INET as u16,
            sin_port: dst.port().to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from(*dst.ip()).to_be(),
            },
            sin_zero: [0; 8],
        };

        let sent = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                packet.as_ptr() as *const libc::c_void,
                packet.len(),
                0,
                &addr as *const libc::sockaddr_in as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };

        if sent < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(sent as usize)
        }
    }
}

impl RawReceiver {
    /// Receive a raw IP packet. Returns bytes read, or None on timeout.
    pub fn recv(&self, buf: &mut [u8]) -> Option<usize> {
        let n = unsafe {
            libc::recvfrom(
                self.fd.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };

        if n <= 0 { None } else { Some(n as usize) }
    }
}

/// Create a raw socket pair (sender, receiver) and iptables guard.
pub fn create_raw_socket(
    local_ip: Ipv4Addr,
    local_port: u16,
) -> io::Result<(RawSender, RawReceiver, Arc<IptablesGuard>)> {
    let send_fd = unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        OwnedFd::from_raw_fd(fd)
    };

    let one: libc::c_int = 1;
    unsafe {
        let ret = libc::setsockopt(
            send_fd.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_HDRINCL,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
    }

    let recv_fd = unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_TCP);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        OwnedFd::from_raw_fd(fd)
    };

    // 1ms recv timeout
    let timeout = libc::timeval {
        tv_sec: 0,
        tv_usec: 1_000,
    };
    unsafe {
        libc::setsockopt(
            recv_fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &timeout as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }

    let mut rules = Vec::new();
    if !local_ip.is_unspecified() {
        let rule_args = vec![
            "-A".into(), "OUTPUT".into(),
            "-p".into(), "tcp".into(),
            "--tcp-flags".into(), "RST".into(), "RST".into(),
            "-s".into(), local_ip.to_string(),
            "--sport".into(), local_port.to_string(),
            "-j".into(), "DROP".into(),
        ];
        add_iptables_rule(&rule_args);
        rules.push(rule_args);
    } else {
        let rule_args = vec![
            "-A".into(), "OUTPUT".into(),
            "-p".into(), "tcp".into(),
            "--tcp-flags".into(), "RST".into(), "RST".into(),
            "--sport".into(), local_port.to_string(),
            "-j".into(), "DROP".into(),
        ];
        add_iptables_rule(&rule_args);
        rules.push(rule_args);
    }

    info!("Raw socket created, iptables RST suppression active for port {local_port}");

    Ok((
        RawSender { fd: send_fd },
        RawReceiver { fd: recv_fd },
        Arc::new(IptablesGuard { rules }),
    ))
}

fn add_iptables_rule(args: &[String]) {
    let status = Command::new("iptables").args(args).status();
    match status {
        Ok(s) if s.success() => info!("iptables rule added: {}", args.join(" ")),
        Ok(s) => warn!("iptables rule add failed (exit {}): {}", s, args.join(" ")),
        Err(e) => warn!("Failed to run iptables: {e}"),
    }
}

fn remove_iptables_rule(args: &[String]) {
    let del_args: Vec<String> = args
        .iter()
        .map(|a| if a == "-A" { "-D".to_string() } else { a.clone() })
        .collect();
    let status = Command::new("iptables").args(&del_args).status();
    match status {
        Ok(s) if s.success() => info!("iptables rule removed"),
        Ok(s) => warn!("iptables rule removal failed (exit {})", s),
        Err(e) => warn!("Failed to run iptables for cleanup: {e}"),
    }
}

/// Get the local IP address for reaching a given destination
pub fn get_local_ip_for(dst: Ipv4Addr) -> io::Result<Ipv4Addr> {
    let sock = unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        OwnedFd::from_raw_fd(fd)
    };

    let addr = libc::sockaddr_in {
        sin_family: libc::AF_INET as u16,
        sin_port: 80u16.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from(dst).to_be(),
        },
        sin_zero: [0; 8],
    };

    unsafe {
        let ret = libc::connect(
            sock.as_raw_fd(),
            &addr as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        );
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
    }

    let mut local_addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    unsafe {
        let ret = libc::getsockname(
            sock.as_raw_fd(),
            &mut local_addr as *mut libc::sockaddr_in as *mut libc::sockaddr,
            &mut len,
        );
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
    }

    let ip_u32 = u32::from_be(local_addr.sin_addr.s_addr);
    Ok(Ipv4Addr::from(ip_u32))
}
