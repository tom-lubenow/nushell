/// The main eBPF plugin struct
/// 
/// This plugin provides commands for attaching eBPF programs to kernel events
/// and collecting tracing data using Nushell's scripting capabilities.
pub struct EbpfPlugin {
    // For now, we'll keep this stateless, but in the future we might
    // want to track active programs or shared resources
}

impl EbpfPlugin {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for EbpfPlugin {
    fn default() -> Self {
        Self::new()
    }
} 