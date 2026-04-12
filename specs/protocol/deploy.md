# deploy method

Method ID: 0x02. Requires daemon.

## Behavior
- Accepts `{"function": string, "sample_rate": f64}` as params
- Attaches a kernel probe at runtime
- Returns `{"probe_id": string, "function": string, "status": "attached"}`

## Pre-compiled probes
- tcp_connect, tcp_close, tcp_retransmit_skb are pre-compiled — deploy is fast
- These use the existing eBPF object loaded at daemon startup

## Codegen probes
- Any other function in the knowledge base triggers codegen
- BTF is parsed from /sys/kernel/btf/vmlinux
- BPF bytecode is generated at runtime — no C, no clang
- Generated probe is loaded via aya::Ebpf::load()

## Error cases
- Unknown function (not in KB and not resolvable via BTF) returns error
- Already attached probe returns error with "already attached" in message
- Probe attachment failure (permissions, kernel version) returns error

## CLI verification
- `jalki status` after deploy shows the probe with events_total, drops, sample_rate
- Probe appears immediately after deployment — no restart required
