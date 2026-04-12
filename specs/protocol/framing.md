# Binary Frame Protocol

## Frame structure
- Every message is a binary frame: `[frame_len: u32 BE][msg_type: u8][flags: u8][payload]`
- `frame_len` includes the 2 bytes for msg_type and flags
- Maximum frame size is 1MB
- Payload is MessagePack encoded

## Connection
- Daemon listens on Unix socket at `/run/jalki/jalki.sock`
- Socket must be world-writable (0777) so non-root clients can connect
- Multiple connections are accepted simultaneously
- Each connection is independent — no shared state between connections

## Keepalive
- Client sends PING (0x07), daemon responds with PONG (0x08)
- PING/PONG payloads are empty MessagePack arrays
- Daemon must respond to PING within 5 seconds
