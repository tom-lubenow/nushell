use nu_plugin::{Plugin, PluginCommand};

mod commands;
mod ebpf_plugin;

pub use commands::*;
pub use ebpf_plugin::EbpfPlugin;

impl Plugin for EbpfPlugin {
    fn version(&self) -> String {
        env!("CARGO_PKG_VERSION").into()
    }

    fn commands(&self) -> Vec<Box<dyn PluginCommand<Plugin = Self>>> {
        vec![
            // Basic eBPF commands
            Box::new(BpfKprobe),
        ]
    }
} 