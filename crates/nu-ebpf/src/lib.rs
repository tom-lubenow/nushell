#![doc = include_str!("../README.md")]

use nu_protocol::ast::Block;

/// Generate Rust source for a kprobe eBPF program.
///
/// Currently this function ignores the `code` parameter and returns a
/// hard-coded program that prints "hello" when the probe is hit.
pub fn generate_kprobe(_code: &Block, fn_name: &str) -> String {
    format!(
        r#"use aya_bpf::macros::kprobe;
use aya_bpf::programs::KProbeContext;
use aya_log_ebpf::info;

#[kprobe(name = "{name}")]
pub fn {name}(ctx: KProbeContext) -> u32 {{
    info!(&ctx, "hello");
    0
}}
"#,
        name = fn_name
    )
}
