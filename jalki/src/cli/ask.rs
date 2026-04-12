use anyhow::Result;
use rmpv::Value;

use jalki::ipc::{self, msgpack_str, METHOD_ASK, METHOD_DEPLOY};
use jalki::knowledge::KnowledgeBase;

/// `jalki ask "why is postgres slow"`
///
/// 1. Search KB for relevant probes
/// 2. Deploy them via daemon IPC
/// 3. Collect events for N seconds
/// 4. Interpret the most interesting events
/// 5. Print a human answer
pub async fn run(question: &str, collect_seconds: u64) -> Result<()> {
    let kb = KnowledgeBase::load();

    // 1. Find relevant probes.
    let matches = kb.find_probes(question);
    if matches.is_empty() {
        eprintln!("No probes match that question. Try keywords like 'connect', 'retransmit', 'packet loss'.");
        return Ok(());
    }

    // Take up to 3 most relevant probes, deduplicated by function name.
    let mut seen = std::collections::HashSet::new();
    let selected: Vec<&_> = matches
        .into_iter()
        .filter(|p| seen.insert(p.function.clone()))
        .take(3)
        .collect();

    eprintln!("Probes selected:");
    for p in &selected {
        eprintln!("  {} ({}/{})", p.function, p.attachment, p.event_type);
    }

    // 2. Try to deploy probes via daemon. If no daemon, fall back to KB-only mode.
    let daemon_available = ipc::connect().await.is_ok();

    if !daemon_available {
        eprintln!("No daemon running — showing knowledge base analysis only.");
        eprintln!("For live events, start the daemon: sudo jalki --emit stdout");
        println!();
        return print_kb_answer(question, &selected, &kb);
    }

    let mut deployed = Vec::new();
    for probe in &selected {
        let params = Value::Map(vec![
            (msgpack_str("function"), msgpack_str(&probe.function)),
            (msgpack_str("sample_rate"), Value::F64(1.0)),
        ]);
        let resp = ipc::call_native(METHOD_DEPLOY, params).await;

        match resp {
            Ok(r) if r.ok => {
                let probe_id = r.get_str("probe_id").unwrap_or_else(|| "unknown".into());
                eprintln!("  attached {} → {}", probe.function, probe_id);
                deployed.push((probe.function.clone(), probe_id));
            }
            Ok(r) => {
                let err = r.error.unwrap_or_default();
                if err.contains("already attached") {
                    eprintln!("  {} already attached", probe.function);
                    deployed.push((probe.function.clone(), probe.function.clone()));
                } else {
                    eprintln!("  {} failed: {}", probe.function, err);
                }
            }
            Err(e) => {
                eprintln!("  deploy error: {e}");
            }
        }
    }

    if deployed.is_empty() {
        eprintln!("No probes could be deployed. Showing KB analysis instead.");
        println!();
        return print_kb_answer(question, &selected, &kb);
    }

    // 3. Use server-side ask for collection + interpretation.
    eprintln!("Collecting events for {}s...", collect_seconds);

    let ask_params = Value::Map(vec![
        (msgpack_str("question"), msgpack_str(question)),
        (msgpack_str("collect_seconds"), Value::Integer(collect_seconds.into())),
        (msgpack_str("max_events"), Value::Integer(100.into())),
    ]);
    let resp = ipc::call_native(METHOD_ASK, ask_params).await?;

    if !resp.ok {
        eprintln!(
            "Failed: {}",
            resp.error.unwrap_or_default()
        );
        return Ok(());
    }

    let json_result = resp.to_json();
    let events = json_result
        .get("events")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let total = events.len();

    if total == 0 {
        println!("No events observed in {}s.", collect_seconds);
        println!();
        println!("The kernel functions we hooked did not fire.");
        println!("Either nothing is happening, or the probes need more time.");
        println!();
        println!("Here's what to look for when events do arrive:");
        println!();
        return print_kb_answer(question, &selected, &kb);
    }

    eprintln!("Collected {} events. Interpreting...", total);
    println!();

    // Group events by source and summarize.
    let mut by_source: std::collections::HashMap<String, Vec<&serde_json::Value>> =
        std::collections::HashMap::new();
    for event in &events {
        let source = event
            .get("source")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        by_source.entry(source.to_string()).or_default().push(event);
    }

    // Print summary header.
    println!("# Question: {}", question);
    println!();
    println!("## Events observed ({} total in {}s)", total, collect_seconds);
    println!();

    for (source, events) in &by_source {
        println!("  {}: {} events", source, events.len());
    }
    println!();

    // 5. Interpret the most interesting events.
    println!("## Interpretation");
    println!();

    let mut interpreted = false;
    for probe_info in &selected {
        let source = format!("jalki/{}", probe_info.function.replace("_skb", ""));
        let source_events = by_source.get(&source).or_else(|| {
            let alt = format!("jalki/{}", probe_info.function);
            by_source.get(&alt)
        });

        if let Some(events) = source_events {
            if let Some(event) = events.first() {
                let fields = extract_fields(event, &probe_info.function);
                let interps = kb.explain(&probe_info.function, &fields);

                if let Some(interp) = interps.first() {
                    println!("**{}** ({})", probe_info.function, interp.severity);
                    println!();
                    println!("  {}", interp.conclusion);
                    println!();
                    println!("  Action: {}", interp.action);
                    if let Some(errno) = &interp.errno {
                        println!("  errno: {}", errno);
                    }
                    println!();
                    interpreted = true;
                }
            }
        }
    }

    if !interpreted {
        println!("Events were collected but no specific interpretation matched.");
        println!("This often means the observed behavior is normal.");
    }

    // Print sample events.
    println!("## Sample events");
    println!();
    for event in events.iter().take(5) {
        if let Ok(pretty) = serde_json::to_string_pretty(event) {
            println!("{}", pretty);
            println!();
        }
    }

    Ok(())
}

/// Print a KB-only answer without live events.
fn print_kb_answer(
    question: &str,
    selected: &[&jalki::knowledge::ProbeKnowledge],
    _kb: &KnowledgeBase,
) -> Result<()> {
    println!("# Question: {}", question);
    println!();
    println!("## Recommended probes");
    println!();

    for probe in selected {
        println!("### {} ({})", probe.function, probe.attachment);
        println!();
        println!("{}", probe.use_when);
        println!();

        let important_fields: Vec<_> = probe
            .fields
            .iter()
            .filter(|f| f.important)
            .collect();
        if !important_fields.is_empty() {
            println!("Key fields:");
            for f in &important_fields {
                println!("  {} — {}", f.name, f.meaning);
            }
            println!();
        }

        if !probe.combine_with.is_empty() {
            println!("Combine with: {}", probe.combine_with.join(", "));
            println!();
        }

        if !probe.interpretations.is_empty() {
            println!("What to look for:");
            for interp in &probe.interpretations {
                println!("  [{}] {} → {}", interp.severity, interp.pattern, interp.conclusion);
                println!("    Action: {}", interp.action);
            }
            println!();
        }
    }

    println!("## To collect live events");
    println!();
    println!("  sudo jalki --emit stdout    # terminal 1");
    println!("  jalki ask \"{}\"              # terminal 2", question);
    println!();

    Ok(())
}

/// Extract ret / tcp_state from an occurrence JSON for interpretation matching.
fn extract_fields(event: &serde_json::Value, function: &str) -> jalki::knowledge::EventFields {
    let mut fields = jalki::knowledge::EventFields {
        ret: None,
        tcp_state: None,
    };

    // Check for return value in error.code (e.g., "ECONNREFUSED" → -111).
    if let Some(err) = event.get("error") {
        if let Some(code) = err.get("code").and_then(|v| v.as_str()) {
            fields.ret = Some(errno_from_name(code));
        }
    }

    // Check outcome for success/failure.
    if fields.ret.is_none() {
        if let Some(outcome) = event.get("outcome").and_then(|v| v.as_str()) {
            match outcome {
                "success" => fields.ret = Some(0),
                "failure" => {
                    if fields.ret.is_none() {
                        fields.ret = Some(-1);
                    }
                }
                _ => {}
            }
        }
    }

    // For retransmit events, check metadata or type-specific fields.
    if function.contains("retransmit") {
        // Check if the occurrence has metadata with tcp_state.
        if let Some(meta) = event.get("metadata") {
            if let Some(state) = meta.get("tcp_state").and_then(|v| v.as_u64()) {
                fields.tcp_state = Some(state as u8);
            }
        }
        // Also check process_data and network_data for hints.
        // For now, default to ESTABLISHED if we see retransmits and don't know the state.
        if fields.tcp_state.is_none() {
            fields.tcp_state = Some(1); // ESTABLISHED is most common
        }
    }

    fields
}

fn errno_from_name(name: &str) -> i32 {
    match name {
        "ECONNREFUSED" => -111,
        "ETIMEDOUT" => -110,
        "EHOSTUNREACH" => -113,
        "ENETUNREACH" => -101,
        _ => {
            // Try "E42" format.
            if let Some(num) = name.strip_prefix('E') {
                if let Ok(n) = num.parse::<i32>() {
                    return -n;
                }
            }
            -1
        }
    }
}
