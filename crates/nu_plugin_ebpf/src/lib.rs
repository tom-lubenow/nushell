use nu_plugin::{Plugin, PluginCommand};

mod commands;
mod ebpf_plugin;
pub mod parser;  // Made public for tests
pub mod loader;  // Made public for tests
mod streaming;
pub mod probe_context;  // Made public for tests

pub use commands::*;
pub use ebpf_plugin::EbpfPlugin;

impl Plugin for EbpfPlugin {
    fn version(&self) -> String {
        env!("CARGO_PKG_VERSION").into()
    }

    fn commands(&self) -> Vec<Box<dyn PluginCommand<Plugin = Self>>> {
        vec![
            // Phase 4: Expanded eBPF commands for different probe types
            Box::new(BpfKprobe),
            Box::new(BpfTracepoint),
            // Phase 5: Event streaming
            Box::new(BpfStream),
        ]
    }
} 