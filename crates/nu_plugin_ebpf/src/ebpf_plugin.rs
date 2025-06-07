use std::sync::{Arc, Mutex};
use crate::streaming::EventCollector;

/// The main eBPF plugin struct
/// 
/// This plugin provides commands for attaching eBPF programs to kernel events
/// and collecting tracing data using Nushell's scripting capabilities.
pub struct EbpfPlugin {
    /// Shared event collector for all eBPF programs
    event_collector: Arc<Mutex<Option<Arc<EventCollector>>>>,
}

impl EbpfPlugin {
    pub fn new() -> Self {
        Self {
            event_collector: Arc::new(Mutex::new(None)),
        }
    }
    
    /// Get or create the event collector
    pub fn get_or_create_collector(&self) -> Arc<EventCollector> {
        let mut collector_opt = self.event_collector.lock().unwrap();
        
        if let Some(collector) = &*collector_opt {
            collector.clone()
        } else {
            let collector = Arc::new(EventCollector::new());
            *collector_opt = Some(collector.clone());
            collector
        }
    }
}

impl Default for EbpfPlugin {
    fn default() -> Self {
        Self::new()
    }
} 