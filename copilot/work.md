# Work Log - TCP Raw Socket Speed Test

## Summary
Implemented a network speed testing tool that operates on raw TCP sockets, allowing observation of actual network behavior including congestion, packet loss, and middlebox traversal.

## Architecture

### Threaded Design
The client uses a multi-threaded architecture:
- **Send thread**: Sends data packets at the rate controlled by the congestion algorithm. Uses `sleep()` for rate pacing.
- **Receive thread**: Processes incoming ACKs and updates atomic counters.
- **Main thread**: Runs stats reporting every interval and updates the congestion controller, feeding new rate back to the send thread via atomic.

The server is single-threaded since it primarily just receives and ACKs.

### Raw Socket Approach
- Uses `AF_INET` + `IPPROTO_RAW` for sending (with `IP_HDRINCL`)
- Uses `AF_INET` + `IPPROTO_TCP` for receiving
- Separate FDs for send and receive, split into `RawSender` and `RawReceiver` types for thread safety
- iptables rules automatically added/removed to suppress kernel RST packets

### TCP Packet Construction
All packets built manually in `packet.rs`:
- IP header (20 bytes, version 4, IHL 5)
- TCP header (20 bytes, no options)
- TCP checksum calculated over pseudo-header + segment
- Supports all needed flag combinations: SYN, SYN-ACK, ACK, PSH|ACK, FIN|ACK, RST

### Congestion/Rate Control (`congestion.rs`)
Proportional controller converging to target loss rate:
```
target_loss = 1 - 1/MULTIPLIER
error = target_loss - smoothed_loss
rate *= base^error
```

Key properties:
- Exponential ramp-up when no loss (error = target_loss ≈ 0.5 for M=2)
- Smooth convergence near equilibrium
- EMA smoothing (α=0.3) prevents oscillation
- Adjustment clamped to [0.5, 4.0] for stability

### Handshake
Full TCP 3-way handshake:
1. Client sends SYN with test parameters encoded in payload (8 bytes)
2. Server responds with SYN-ACK
3. Client sends ACK

### Teardown
- On Ctrl-C: active close with FIN-ACK
- On receiving FIN: respond with FIN-ACK
- On receiving RST: immediate close
- iptables rules cleaned up via `IptablesGuard` Drop impl

### ACK Modes
- **No-retransmission mode** (default): Server ACKs every unique packet. Even out-of-order packets advance the ACK number to the highest seen sequence.
- **Retransmission mode** (`--retransmit`): Standard TCP-like behavior:
  - **Server**: Only ACKs contiguous data. Out-of-order packets trigger duplicate ACKs.
  - **Client**: Tracks last ACK number and duplicate ACK count via atomics.
    - **Fast retransmit**: 3+ duplicate ACKs → retransmit from stalled ACK position.
    - **RTO**: If ACK doesn't advance for 500ms and there is unacked data, retransmit.
    - Retransmissions are rate-limited to the current sending rate.
    - Stats show per-interval and total retransmission counts.

## Files Created
| File | Purpose |
|------|---------|
| `src/main.rs` | CLI parsing, root check, signal handler, mode dispatch |
| `src/config.rs` | CLI structs (clap derive), TestConfig, TestParams serialization |
| `src/packet.rs` | TCP/IP packet construction, parsing, checksum |
| `src/socket.rs` | Raw socket wrapper (RawSender/RawReceiver), iptables management |
| `src/congestion.rs` | Rate controller with proportional control algorithm |
| `src/stats.rs` | Statistics tracker (available for future use) |
| `src/client.rs` | Client mode: threaded send/recv, handshake, stats, teardown |
| `src/server.rs` | Server mode: accept connections, ACK data, stats |
| `copilot/plan.md` | Design plan and architecture |

## Test Results (loopback)
```
[  1.0s] TX: 10  | ACK: 10  | Loss: 0.0% | Rate:  14 pps | Send: 112 Kbps
[  5.0s] TX: 40  | ACK: 40  | Loss: 0.0% | Rate:  57 pps | Send: 448 Kbps
[  8.0s] TX: 111 | ACK: 111 | Loss: 0.0% | Rate: 160 pps | Send: 1.24 Mbps
[ 11.0s] TX: 309 | ACK: 309 | Loss: 0.0% | Rate: 453 pps | Send: 3.46 Mbps
```

Rate ramps up exponentially (~√2x per second) on zero-loss loopback. On a real network, the rate will converge to `bandwidth * MULTIPLIER` where loss matches the target.

## Dependencies
- `clap 4` - CLI argument parsing with derive macros
- `pnet 0.35` - (available but not used directly; we build packets manually)
- `ctrlc 3` - Ctrl-C signal handling
- `log 0.4` + `env_logger 0.11` - Structured logging
- `rand 0.9` - ISN generation
- `libc 0.2` - Raw socket syscalls
