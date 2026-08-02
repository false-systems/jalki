# get_events method

Method ID: 0x07. Requires daemon.

## Behavior
- Accepts optional `probe_id` (string) and optional `filter` (map)
- With `probe_id`: returns stored events for that probe only
- Without `probe_id`: returns stored events across all probes
- The filter is applied server-side — non-matching events never cross the wire
- Filter keys mirror the subscribe filter: src_ip, dst_ip, src_port, dst_port, pid, command, last_seconds, limit
- Default window is the last 60 seconds; default limit is 100 events

## Response
- Map with two keys:
  - `events`: array of compact events (same positional shape as STREAM_EVENT payloads)
  - `total`: number of events returned

## Notes
- Reads the daemon's in-memory EventStore; this is a query, not a stream —
  use subscribe (0x03) for live delivery
- MCP tool `jalki_get_events` forwards to this method
