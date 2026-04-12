# subscribe method

Method ID: 0x03. Requires daemon.

## Behavior
- Accepts `{"probe_id": string, "filter": EventFilter?, "interpreted": bool}`
- Returns immediate RESPONSE with `{"stream_id": string}`
- Followed by STREAM_START frame containing probe name table
- Then continuous STREAM_EVENT frames as events arrive
- Stream ends with STREAM_END when unsubscribed or connection drops

## STREAM_EVENT format
- Positional MessagePack array with 12 elements
- Position 0: id (ULID string)
- Position 1: probe_idx (u8, index into probe name table)
- Position 2: ts (u64, unix nanoseconds)
- Position 3: severity (u8: 0=info, 1=warning, 2=error, 3=critical)
- Position 4: outcome (u8: 0=success, 1=failure, 2=unknown)
- Position 5: net_src (string "ip:port" or nil)
- Position 6: net_dst (string "ip:port" or nil)
- Position 7: proto (u8: 0=tcp, 1=udp, or nil)
- Position 8: pid (u32 or nil)
- Position 9: cmd (string or nil)
- Position 10: labels (map or nil)
- Position 11: interp ([conclusion, action] array or nil)

## Compact event shape
- Events must NOT contain FALSE Protocol fields: source, enrichment_state, entity_ids, correlation_keys, occurrence_type
- The compact shape saves ~49 tokens per event compared to full FALSE Protocol JSON

## Server-side filtering
- EventFilter is applied in the daemon before serialization
- Events not matching the filter never cross the wire
- Filter fields: src_ip, dst_ip, src_port, dst_port, pid, command

## Interpretation
- When `interpreted: true` or FLAG_INTERPRETED set, position 11 contains [conclusion, action]
- Interpretation comes from KnowledgeBase.explain() matched against the event
