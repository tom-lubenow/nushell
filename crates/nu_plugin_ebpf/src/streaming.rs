/// Event streaming from eBPF programs to Nushell pipeline
/// This module handles the real-time streaming of events from kernel
/// eBPF programs back to Nushell as structured data

use nu_protocol::{Value, Record, Span};
use std::sync::{Arc, Mutex};
use std::collections::VecDeque;

#[cfg(target_os = "linux")]
use aya::maps::perf::{AsyncPerfEventArray, PerfBufferError};
#[cfg(target_os = "linux")]
use aya::util::online_cpus;
#[cfg(target_os = "linux")]
use bytes::BytesMut;
#[cfg(target_os = "linux")]
use tokio::task;

/// Event types that can be streamed from eBPF programs
#[derive(Debug, Clone)]
pub enum EbpfEvent {
    /// A probe was triggered
    ProbeHit {
        probe_name: String,
        pid: u32,
        comm: String,
        timestamp: u64,
    },
    /// A counter was incremented
    CounterUpdate {
        counter_name: String,
        value: u64,
    },
    /// A custom event with arbitrary data
    CustomEvent {
        event_type: String,
        data: Value,
    },
    /// Log message from eBPF program
    LogMessage {
        level: String,
        message: String,
    },
}

impl EbpfEvent {
    /// Convert event to Nushell Value
    pub fn to_value(&self, span: Span) -> Value {
        match self {
            EbpfEvent::ProbeHit { probe_name, pid, comm, timestamp } => {
                let mut record = Record::new();
                record.insert("type", Value::string("probe_hit", span));
                record.insert("probe", Value::string(probe_name, span));
                record.insert("pid", Value::int(*pid as i64, span));
                record.insert("comm", Value::string(comm, span));
                record.insert("timestamp", Value::int(*timestamp as i64, span));
                Value::record(record, span)
            }
            EbpfEvent::CounterUpdate { counter_name, value } => {
                let mut record = Record::new();
                record.insert("type", Value::string("counter", span));
                record.insert("name", Value::string(counter_name, span));
                record.insert("value", Value::int(*value as i64, span));
                Value::record(record, span)
            }
            EbpfEvent::CustomEvent { event_type, data } => {
                let mut record = Record::new();
                record.insert("type", Value::string("custom", span));
                record.insert("event_type", Value::string(event_type, span));
                record.insert("data", data.clone());
                Value::record(record, span)
            }
            EbpfEvent::LogMessage { level, message } => {
                let mut record = Record::new();
                record.insert("type", Value::string("log", span));
                record.insert("level", Value::string(level, span));
                record.insert("message", Value::string(message, span));
                Value::record(record, span)
            }
        }
    }
}

/// Event collector that aggregates events from multiple sources
pub struct EventCollector {
    events: Arc<Mutex<VecDeque<EbpfEvent>>>,
    #[cfg(target_os = "linux")]
    shutdown: Arc<Mutex<bool>>,
}

impl EventCollector {
    pub fn new() -> Self {
        Self {
            events: Arc::new(Mutex::new(VecDeque::new())),
            #[cfg(target_os = "linux")]
            shutdown: Arc::new(Mutex::new(false)),
        }
    }
    
    /// Add an event to the collector
    pub fn push_event(&self, event: EbpfEvent) {
        if let Ok(mut events) = self.events.lock() {
            events.push_back(event);
            // Keep only last 10000 events to prevent unbounded growth
            while events.len() > 10000 {
                events.pop_front();
            }
        }
    }
    
    /// Get all pending events
    pub fn drain_events(&self) -> Vec<EbpfEvent> {
        if let Ok(mut events) = self.events.lock() {
            events.drain(..).collect()
        } else {
            Vec::new()
        }
    }
    
    /// Check if collector has events
    pub fn has_events(&self) -> bool {
        if let Ok(events) = self.events.lock() {
            !events.is_empty()
        } else {
            false
        }
    }
    
    #[cfg(target_os = "linux")]
    pub fn shutdown(&self) {
        if let Ok(mut shutdown) = self.shutdown.lock() {
            *shutdown = true;
        }
    }
}

/// Start streaming events from a perf event array (Linux only)
#[cfg(target_os = "linux")]
pub async fn start_perf_event_streaming(
    mut perf_array: AsyncPerfEventArray<aya::maps::MapData>,
    collector: Arc<EventCollector>,
) -> Result<(), Box<dyn std::error::Error>> {
    let cpus = online_cpus()?;
    let mut buffers = Vec::new();
    
    // Set up per-CPU buffers
    for cpu in cpus {
        let buf = perf_array.open(cpu, None)?;
        buffers.push(buf);
    }
    
    // Spawn tasks to read from each CPU buffer
    let mut tasks = Vec::new();
    for mut buf in buffers {
        let collector = collector.clone();
        
        let task = task::spawn(async move {
            let mut bufs = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();
            
            loop {
                // Check for shutdown
                if let Ok(shutdown) = collector.shutdown.lock() {
                    if *shutdown {
                        break;
                    }
                }
                
                // Read events
                let events = match buf.read_events(&mut bufs).await {
                    Ok(events) => events,
                    Err(PerfBufferError::NoMoreData) => {
                        // No data available, yield and retry
                        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                        continue;
                    }
                    Err(e) => {
                        eprintln!("Error reading perf events: {:?}", e);
                        break;
                    }
                };
                
                // Process events
                for buf in bufs.iter_mut().take(events.read) {
                    let event = parse_event_data(&buf);
                    collector.push_event(event);
                    buf.clear();
                }
            }
        });
        
        tasks.push(task);
    }
    
    // Wait for all tasks
    for task in tasks {
        let _ = task.await;
    }
    
    Ok(())
}

/// Parse raw event data into structured event
#[cfg(target_os = "linux")]
fn parse_event_data(data: &[u8]) -> EbpfEvent {
    // This is a simplified parser - in reality, you'd deserialize
    // based on the event structure defined in your eBPF program
    
    // For now, create a generic log event
    let message = String::from_utf8_lossy(data).to_string();
    EbpfEvent::LogMessage {
        level: "info".to_string(),
        message,
    }
}

/// Create a stream iterator for Nushell pipeline
pub struct EventStream {
    collector: Arc<EventCollector>,
    span: Span,
}

impl EventStream {
    pub fn new(collector: Arc<EventCollector>, span: Span) -> Self {
        Self { collector, span }
    }
}

impl Iterator for EventStream {
    type Item = Value;
    
    fn next(&mut self) -> Option<Self::Item> {
        // Get events from collector
        let events = self.collector.drain_events();
        
        if events.is_empty() {
            // No events available
            None
        } else {
            // Return events as a list
            let values: Vec<Value> = events
                .into_iter()
                .map(|e| e.to_value(self.span))
                .collect();
            
            Some(Value::list(values, self.span))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_event_to_value() {
        let event = EbpfEvent::ProbeHit {
            probe_name: "test_probe".to_string(),
            pid: 1234,
            comm: "test_process".to_string(),
            timestamp: 1234567890,
        };
        
        let value = event.to_value(Span::test_data());
        assert!(matches!(value, Value::Record { .. }));
    }
    
    #[test]
    fn test_event_collector() {
        let collector = EventCollector::new();
        
        // Add some events
        collector.push_event(EbpfEvent::LogMessage {
            level: "info".to_string(),
            message: "test".to_string(),
        });
        
        assert!(collector.has_events());
        
        let events = collector.drain_events();
        assert_eq!(events.len(), 1);
        assert!(!collector.has_events());
    }
}