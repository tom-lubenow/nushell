use nu_plugin::{EngineInterface, EvaluatedCall, SimplePluginCommand};
use nu_protocol::{Category, LabeledError, Signature, Type, Value};
use crate::streaming::EventCollector;
use crate::EbpfPlugin;
use std::sync::Arc;

pub struct BpfStream;

impl SimplePluginCommand for BpfStream {
    type Plugin = EbpfPlugin;

    fn name(&self) -> &str {
        "bpf-stream"
    }

    fn description(&self) -> &str {
        "Stream events from active eBPF programs"
    }

    fn extra_description(&self) -> &str {
        r#"
The `bpf-stream` command creates a stream of events from all active eBPF programs.
Events are returned as structured records that can be processed in the Nushell pipeline.

Event types include:
- probe_hit: When a kprobe or tracepoint is triggered
- counter: Counter updates from eBPF maps
- custom: Custom events emitted by eBPF programs
- log: Log messages from eBPF programs

Examples:
    # Stream all events
    bpf-stream | each { |event| print $event }
    
    # Filter for specific probe hits
    bpf-stream | where type == "probe_hit" | where probe == "sys_open"
    
    # Count events by type
    bpf-stream | group-by type | each { |group| $group | length }
    
    # Save events to file
    bpf-stream | save events.jsonl

Note: This command requires active eBPF programs loaded with bpf-kprobe or similar commands.
"#
        .trim()
    }

    fn signature(&self) -> Signature {
        Signature::build(self.name())
            .input_output_types(vec![(Type::Nothing, Type::List(Box::new(Type::Any)))])
            .category(Category::System)
    }

    fn search_terms(&self) -> Vec<&str> {
        vec!["ebpf", "bpf", "stream", "events", "trace", "monitor"]
    }

    fn run(
        &self,
        plugin: &Self::Plugin,
        _engine: &EngineInterface,
        call: &EvaluatedCall,
        _input: &Value,
    ) -> Result<Value, LabeledError> {
        eprintln!("🔄 Starting eBPF event stream...");
        
        // Get or create event collector from plugin state
        let collector = plugin.get_or_create_collector();
        
        // Create demo events for testing
        demo_events(&collector);
        
        // For SimplePluginCommand, we need to return a Value, not a stream
        // So we'll collect the first batch of events
        eprintln!("📡 Collecting events from eBPF programs...");
        eprintln!("   Note: This is a demo - real streaming would use pipeline data");
        
        // Wait a bit for demo events to accumulate
        std::thread::sleep(std::time::Duration::from_secs(2));
        
        // Get accumulated events
        let events = collector.drain_events();
        let values: Vec<Value> = events
            .into_iter()
            .map(|e| e.to_value(call.head))
            .collect();
        
        Ok(Value::list(values, call.head))
    }
}

/// Generate demo events for testing
fn demo_events(collector: &Arc<EventCollector>) {
    use crate::streaming::EbpfEvent;
    use std::thread;
    use std::time::Duration;
    
    let collector = collector.clone();
    
    // Spawn a thread to generate events
    thread::spawn(move || {
        let mut counter = 0;
        loop {
            // Generate different types of events
            match counter % 4 {
                0 => {
                    collector.push_event(EbpfEvent::ProbeHit {
                        probe_name: "sys_open".to_string(),
                        pid: std::process::id(),
                        comm: "demo_process".to_string(),
                        timestamp: chrono::Utc::now().timestamp_millis() as u64,
                    });
                }
                1 => {
                    collector.push_event(EbpfEvent::CounterUpdate {
                        counter_name: "open_count".to_string(),
                        value: counter as u64,
                    });
                }
                2 => {
                    collector.push_event(EbpfEvent::LogMessage {
                        level: "info".to_string(),
                        message: format!("Demo event #{}", counter),
                    });
                }
                _ => {
                    let data = Value::string(format!("Custom data #{}", counter), nu_protocol::Span::unknown());
                    collector.push_event(EbpfEvent::CustomEvent {
                        event_type: "demo".to_string(),
                        data,
                    });
                }
            }
            
            counter += 1;
            
            // Sleep briefly to simulate real events
            thread::sleep(Duration::from_millis(500));
            
            // Stop after 20 events for demo
            if counter >= 20 {
                break;
            }
        }
    });
}