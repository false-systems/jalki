# Knowledge Base

## Schema
- Every probe entry has: function, attachment, event_type, layer, answers, keywords, fields, use_when, not_when, combine_with, interpretations
- attachment is either "fentry" or "fexit"
- event_type follows format "kernel.{layer}.{name}"
- Every field has: name, type, meaning, important (bool)
- Every interpretation has: pattern, conclusion, severity, action

## Layers
- tcp: connection observability (tcp_connect, tcp_close, tcp_retransmit_skb, tcp_sendmsg, inet_csk_accept, tcp_recvmsg, tcp_v4_syn_recv_sock, tcp_reset)
- memory: resource observability (oom_kill_process, mm_page_alloc, try_charge_memcg)
- fs: filesystem I/O (vfs_open, vfs_write, vfs_read, filp_close)
- process: lifecycle (do_execve, do_exit, sys_clone)
- sched: CPU scheduling (finish_task_switch, try_to_wake_up)

## Semantic correctness
- tcp_connect must be fexit (needs return value for errno)
- tcp_retransmit_skb must be fentry (needs entry state, not return)
- tcp_retransmit_skb must have tcp_state field marked important
- ESTABLISHED retransmit interpretation must say "network problem", not "application problem"
- SYN_SENT retransmit interpretation must say "unreachable" or "handshake"
- ECONNREFUSED interpretation must reference "listening" or "port"
- No interpretation should blame the network for ECONNREFUSED (it's a port/process issue)
- No interpretation should blame the application for ESTABLISHED retransmit (it's network)
- CLOSE_WAIT retransmit must blame the application

## Cross-references
- Every function in combine_with must exist as a probe in some layer
- Function names must be unique across all layers
- No duplicate event_types across all probes
- Keywords must be lowercase

## Probe count
- At least 20 probes across all 5 layers
- Each layer has at least 1 probe
