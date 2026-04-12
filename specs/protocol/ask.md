# ask method

Method ID: 0x06. The magic method. Works with and without daemon.

## Server-side orchestration (with daemon)
1. KnowledgeBase.find_probes(question) — select top 3
2. Deploy each probe
3. Collect events for collect_seconds into EventStore
4. Stop collecting
5. Run KnowledgeBase.explain() on most significant events
6. Return AskResult

## Request params
- question: string (required)
- collect_seconds: u64 (default 5)
- max_events: u32 (default 100)
- filter: EventFilter (optional)

## Response result (AskResult)
- interpretation: non-empty string describing what was observed
- severity: u8 (0=info, 1=warning, 2=error, 3=critical)
- action: non-empty string recommending next steps
- events: array of compact events (same shape as STREAM_EVENT)
- probes_used: array of function names that were deployed
- kb_only: bool — true if no live events were collected

## Fallback behavior
- If no probes match the question: return helpful error with kb_only=true
- If daemon not running: SDK returns KB-only analysis (interpretation from knowledge base)
- Never raises/fails — always returns something useful

## CLI verification
- `jalki ask "why are connections failing"` returns interpretation text
- Without daemon: shows KB-only analysis with probe recommendations
- With daemon: shows live event interpretation with sample events

## Required interpretations
- Question about connections failing → tcp_connect selected → interprets ret values
- Question about packet loss → tcp_retransmit_skb selected → interprets tcp_state
- ECONNREFUSED (-111) → "nothing is listening on dst_ip:dst_port"
- ESTABLISHED retransmit → "network is losing packets, not an application problem"
- SYN_SENT retransmit → "initial handshake failing, remote unreachable"
