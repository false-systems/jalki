use jalki::knowledge::KnowledgeBase;

/// `jalki list [--layer tcp]`
///
/// Print available kernel probes from the knowledge base.
pub fn run(layer: Option<&str>) {
    let kb = KnowledgeBase::load();

    if let Some(layer_name) = layer {
        let probes = kb.probes_in_layer(layer_name);
        if probes.is_empty() {
            eprintln!("Unknown layer '{}'. Available: {:?}", layer_name, kb.layers());
            return;
        }
        println!("Layer: {}", layer_name);
        println!();
        for p in probes {
            print_probe(p);
        }
    } else {
        for layer_name in kb.layers() {
            println!("## {}", layer_name);
            println!();
            for p in kb.probes_in_layer(layer_name) {
                print_probe(p);
            }
        }
    }
}

fn print_probe(p: &jalki::knowledge::ProbeKnowledge) {
    println!(
        "  {} ({})  {}",
        p.function, p.attachment, p.event_type
    );
    println!("    {}", p.use_when);
    if !p.combine_with.is_empty() {
        println!("    combine with: {}", p.combine_with.join(", "));
    }
    let important_fields: Vec<_> = p
        .fields
        .iter()
        .filter(|f| f.important)
        .map(|f| f.name.as_str())
        .collect();
    if !important_fields.is_empty() {
        println!("    key fields: {}", important_fields.join(", "));
    }
    println!();
}
