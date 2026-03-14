# TCP Raw Socket Speed Test - Design Plan

## Overview
A network speed testing tool that uses raw TCP sockets to measure bandwidth, RTT, and packet loss characteristics. By crafting actual TCP packets via raw sockets, the tool can observe real network behavior including congestion, middlebox effects, and NAT traversal.

## Architecture

### Modes
- **Server mode**: Listens for incoming test connections, sends ACKs, reports stats
- **Client mode**: Initiates connection, sends/receives data, computes metrics

### Key Design Decisions
1. **Actual TCP headers** on raw sockets (`AF_INET` / `IPPROTO_RAW`) for NAT traversal
2. **iptables RST suppression** to prevent OS kernel from interfering with our raw TCP
3. **Configurable payload size**, default 1400 bytes
4. **Run until Ctrl-C** with graceful FIN teardown

### Congestion/Rate Control Algorithm
Goal: Converge sending rate to `actual_bandwidth * MULTIPLIER`.

At equilibrium, loss rate = `1 - 1/MULTIPLIER`.

**Algorithm** (proportional controller):
```
Every measurement interval (100ms):
  1. Compute observed loss rate: L = 1 - (acked_packets / sent_packets)
  2. Smooth it: L_smooth = α * L + (1-α) * L_smooth_prev  (α = 0.3)
  3. Target loss rate: L_target = 1 - 1/MULTIPLIER
  4. Adjust rate: rate *= base^(L_target - L_smooth)
     where base = configurable (default 2.0)
  
  When L_smooth < L_target: exponent positive → rate increases
  When L_smooth > L_target: exponent negative → rate decreases
  When L_smooth = L_target: exponent zero → rate stable (converged)
```

The exponential form (`base^error`) provides:
- Exponential ramp-up when far from target (error is large positive)
- Gentle adjustment near equilibrium
- Natural convergence without oscillation (with proper smoothing)

Initial rate: 10 packets/sec, ramping up from there.

### TCP State Machine
```
Client                          Server
  |                               |
  |--- SYN (seq=ISN) ----------->|
  |<-- SYN-ACK (seq=ISN', ack) --|
  |--- ACK ---------------------->|
  |                               |
  |=== DATA TRANSFER PHASE ======|
  |--- DATA (seq++) ------------>|  (or reverse / bidirectional)
  |<-- ACK (ack=received_seq) ---|
  |                               |
  |--- FIN ---------------------->|  (on Ctrl-C)
  |<-- FIN-ACK ------------------|
  |--- ACK ---------------------->|
  |                               |
```

In **no-retransmission mode**: Server ACKs every non-duplicate packet, even out of order.
In **retransmission mode**: Standard TCP-like selective ACK behavior.

### Module Structure
```
src/
  main.rs          - CLI parsing, entry point, mode dispatch
  config.rs        - Configuration structures
  packet.rs        - TCP/IP packet construction & parsing
  socket.rs        - Raw socket wrapper + iptables management
  state.rs         - TCP state machine (handshake, teardown)
  client.rs        - Client mode implementation
  server.rs        - Server mode implementation
  congestion.rs    - Rate control algorithm
  stats.rs         - Statistics tracking & periodic reporting
```

### CLI Interface
```
tcp-raw-speedtest server --port <PORT>
tcp-raw-speedtest client --server <ADDR:PORT> [OPTIONS]

Client options:
  --payload-size <BYTES>     Payload size per packet (default: 1400)
  --multiplier <FLOAT>       Rate multiplier (default: 2.0)
  --retransmit               Enable retransmission mode
  --reverse                  Server sends data to client
  --bidirectional            Both sides send data
  --interval <SECS>          Stats reporting interval (default: 1.0)
  --base <FLOAT>             Rate adjustment base (default: 2.0)
```

### Dependencies
- `clap` - CLI argument parsing (derive)
- `pnet` - TCP/IP packet construction & raw sockets
- `ctrlc` - Signal handling
- `log` + `env_logger` - Logging
- `rand` - ISN generation

## TODO
- [x] Create plan
- [ ] Set up Cargo.toml with dependencies
- [ ] Implement config.rs (CLI + config structs)
- [ ] Implement packet.rs (TCP/IP packet crafting)
- [ ] Implement socket.rs (raw socket + iptables)
- [ ] Implement state.rs (TCP state machine)
- [ ] Implement congestion.rs (rate control)
- [ ] Implement stats.rs (periodic reporting)
- [ ] Implement server.rs
- [ ] Implement client.rs
- [ ] Wire together in main.rs
- [ ] Build and test
- [ ] Document work in copilot/work.md
