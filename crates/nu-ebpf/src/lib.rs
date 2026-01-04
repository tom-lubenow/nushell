//! eBPF tracing for Nushell
//!
//! This crate compiles Nushell closures to eBPF bytecode and attaches them to
//! kernel probe points for high-performance tracing.
//!
//! # Commands
//!
//! ## Probe Management
//!
//! | Command | Description |
//! |---------|-------------|
//! | `ebpf attach` | Attach a probe to a kernel function, tracepoint, or userspace function |
//! | `ebpf detach` | Detach a probe by ID |
//! | `ebpf list` | List active probes |
//!
//! ## Data Collection
//!
//! | Command | Description |
//! |---------|-------------|
//! | `ebpf trace` | Stream events from probes using `emit` |
//! | `ebpf counters` | Display counter aggregations from `count` |
//! | `ebpf histogram` | Display histogram data from `histogram` |
//! | `ebpf stacks` | Display stack traces from `$ctx.kstack` / `$ctx.ustack` |
//!
//! ## Closure Commands
//!
//! These commands are used inside eBPF closures:
//!
//! | Command | Description |
//! |---------|-------------|
//! | `emit` | Send a value to userspace |
//! | `count` | Increment a counter by key |
//! | `histogram` | Add value to log2 histogram |
//! | `read-str` | Read string from userspace pointer |
//! | `read-kernel-str` | Read string from kernel pointer |
//! | `start-timer` | Start latency timer |
//! | `stop-timer` | Stop timer, return elapsed nanoseconds |
//!
//! # Probe Types
//!
//! ```text
//! kprobe:func_name         Kernel function entry
//! kretprobe:func_name      Kernel function return
//! tracepoint:cat/name      Kernel tracepoint
//! uprobe:/path:func        Userspace function entry
//! uretprobe:/path:func     Userspace function return
//! ```
//!
//! # Context Fields
//!
//! The closure parameter provides access to probe context:
//!
//! ```text
//! $ctx.pid      Process ID (tid)
//! $ctx.tgid     Thread group ID (pid)
//! $ctx.uid      User ID
//! $ctx.gid      Group ID
//! $ctx.comm     Command name (8 bytes)
//! $ctx.ktime    Kernel timestamp (ns)
//! $ctx.arg0-5   Function arguments (kprobe/uprobe)
//! $ctx.retval   Return value (kretprobe/uretprobe)
//! $ctx.kstack   Kernel stack trace
//! $ctx.ustack   User stack trace
//! ```
//!
//! Tracepoints expose event-specific fields (e.g., `$ctx.filename` for openat).
//!
//! # Examples
//!
//! ```nushell
//! # Trace process creation
//! ebpf attach 'kprobe:do_fork' {|ctx| { pid: $ctx.pid, comm: $ctx.comm } | emit }
//! ebpf trace
//!
//! # Count syscalls by process
//! ebpf attach 'tracepoint:raw_syscalls/sys_enter' {|ctx| $ctx.comm | count }
//! ebpf counters
//!
//! # Histogram of read sizes
//! ebpf attach 'tracepoint:syscalls/sys_exit_read' {|ctx|
//!     if $ctx.ret > 0 { $ctx.ret | histogram }
//! }
//! ebpf histogram
//!
//! # Measure function latency
//! ebpf attach --pin lat 'kprobe:vfs_read' {|ctx| start-timer }
//! ebpf attach --pin lat -s 'kretprobe:vfs_read' {|ctx| stop-timer | histogram }
//! ```
//!
//! # Compiler Architecture
//!
//! The compiler transforms Nushell closures through several stages:
//!
//! ```text
//! Nushell IR → MIR → CFG analysis → optimizations → register allocation → eBPF
//! ```
//!
//! See [`compiler`] module for details.
//!
//! # Platform Support
//!
//! Linux only. Other platforms return an error.
//!
//! # Requirements
//!
//! - Linux kernel 4.18+
//! - Root or CAP_BPF capability

use nu_protocol::engine::{EngineState, StateWorkingSet};

#[cfg(target_os = "linux")]
pub mod compiler;
#[cfg(target_os = "linux")]
pub mod kernel_btf;
#[cfg(target_os = "linux")]
pub mod loader;
#[cfg(target_os = "linux")]
pub mod symbolize;

pub mod commands;

#[cfg(target_os = "linux")]
pub use compiler::EbpfProgram;

/// Add eBPF commands to the engine state
pub fn add_ebpf_context(mut engine_state: EngineState) -> EngineState {
    let delta = {
        let mut working_set = StateWorkingSet::new(&engine_state);

        for cmd in commands::commands() {
            working_set.add_decl(cmd);
        }

        working_set.render()
    };

    if let Err(err) = engine_state.merge_delta(delta) {
        eprintln!("Error creating eBPF command context: {err:?}");
    }

    engine_state
}
