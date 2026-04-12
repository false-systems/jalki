# status method

Method ID: 0x05. Requires daemon.

## Behavior
- Accepts empty params `{}`
- Returns array of attached probe statuses
- Each status has: probe_id, function, events_total, ring_buffer_drops, sample_rate, attached_since

## Required fields
- probe_id: non-empty string, unique per probe instance
- function: kernel function name (e.g. "tcp_connect")
- events_total: u64, monotonically increasing
- ring_buffer_drops: u64, 0 under normal load
- sample_rate: f64, 1.0 for full capture
- attached_since: RFC3339 timestamp

## CLI verification
- `jalki status` shows a table with PROBE_ID, FUNCTION, EVENTS, DROPS, RATE columns
- After deploying tcp_connect, status shows it immediately
- events_total increases over time as kernel events flow
