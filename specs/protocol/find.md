# find method

Method ID: 0x01. No daemon required for SDK — KB is local. Daemon implements it for wire parity.

## Behavior
- Accepts `{"question": string}` as params
- Returns an array of matching probes, max 5, sorted by relevance
- Each result has: function, attachment, event_type, why, fields, combine_with

## Relevance scoring
- Function name match in question: highest score
- Answer description match: high score
- Keyword match: moderate score
- Results sorted by score descending

## Required matches
- "why are connections failing" must return tcp_connect as first result
- "packet loss" must return tcp_retransmit_skb as first result
- "connection refused" must return tcp_connect as first result
- "which process is writing to disk" must return a fs layer probe

## No daemon fallback
- In the Python SDK, `find()` works without any daemon running
- It uses the embedded knowledge base — same JSON files as the daemon
- Zero network, zero latency, zero tokens

## CLI verification
- `jalki list --layer tcp` shows tcp_connect, tcp_close, tcp_retransmit_skb, tcp_sendmsg, inet_csk_accept
- `jalki list` shows probes across all 5 layers: tcp, memory, fs, process, sched
