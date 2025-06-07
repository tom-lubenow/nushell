use nu_plugin::{MsgPackSerializer, serve_plugin};
use nu_plugin_ebpf::EbpfPlugin;

fn main() {
    // Serve the eBPF plugin using MsgPackSerializer for efficient communication
    serve_plugin(&EbpfPlugin::new(), MsgPackSerializer {})
} 