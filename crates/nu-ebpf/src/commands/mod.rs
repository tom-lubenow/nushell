//! eBPF commands for Nushell
//!
//! ## Management Commands
//!
//! - [`EbpfAttach`] - Compile and attach a closure to a probe point
//! - [`EbpfDetach`] - Detach a probe by ID
//! - [`EbpfList`] - List active probes
//!
//! ## Data Commands
//!
//! - [`EbpfTrace`] - Stream events from `emit`
//! - [`EbpfCounters`] - Display `count` aggregations
//! - [`EbpfHistogram`] - Display `histogram` data
//! - [`EbpfStacks`] - Display stack traces
//!
//! ## Closure Commands
//!
//! Used inside eBPF closures (compiled to bytecode, not executed in Nushell):
//!
//! - [`Emit`] - Send value to userspace
//! - [`Count`] - Increment counter by key
//! - [`Histogram`] - Add to log2 histogram
//! - [`ReadStr`] / [`ReadKernelStr`] - Read strings from pointers
//! - [`StartTimer`] / [`StopTimer`] - Latency measurement

mod attach;
mod counters;
mod detach;
mod helpers;
mod histogram;
mod list;
mod stacks;
mod trace;

use nu_protocol::{ShellError, Span};

/// Create the "eBPF not supported" error for non-Linux platforms
#[cfg(not(target_os = "linux"))]
pub(crate) fn linux_only_error(span: Span) -> ShellError {
    ShellError::GenericError {
        error: "eBPF is only supported on Linux".into(),
        msg: "This command requires a Linux system with eBPF support".into(),
        span: Some(span),
        help: None,
        inner: vec![],
    }
}

/// Macro to handle platform-specific command dispatch
///
/// On Linux, calls the provided function. On other platforms, returns an error.
macro_rules! run_on_linux {
    ($engine_state:expr, $stack:expr, $call:expr, $func:expr) => {{
        #[cfg(not(target_os = "linux"))]
        {
            let _ = ($engine_state, $stack);
            return Err(crate::commands::linux_only_error($call.head));
        }

        #[cfg(target_os = "linux")]
        {
            $func($engine_state, $stack, $call)
        }
    }};
}

pub(crate) use run_on_linux;

/// Validate and convert a probe ID from i64 to u32
///
/// Returns an error if the ID is negative or exceeds u32::MAX
pub(crate) fn validate_probe_id(id: i64, span: Span) -> Result<u32, ShellError> {
    u32::try_from(id).map_err(|_| ShellError::GenericError {
        error: "Invalid probe ID".into(),
        msg: format!("Probe ID must be between 0 and {}, got {}", u32::MAX, id),
        span: Some(span),
        help: Some("Use 'ebpf list' to see valid probe IDs".into()),
        inner: vec![],
    })
}

pub use attach::EbpfAttach;
pub use counters::EbpfCounters;
pub use detach::EbpfDetach;
pub use helpers::{Count, Emit, Filter, Histogram, ReadKernelStr, ReadStr, StartTimer, StopTimer};
pub use histogram::EbpfHistogram;
pub use list::EbpfList;
pub use stacks::EbpfStacks;
pub use trace::EbpfTrace;

use nu_protocol::engine::Command;

/// Get all eBPF commands
pub fn commands() -> Vec<Box<dyn Command>> {
    vec![
        // Main eBPF management commands
        Box::new(EbpfAttach),
        Box::new(EbpfCounters),
        Box::new(EbpfDetach),
        Box::new(EbpfHistogram),
        Box::new(EbpfList),
        Box::new(EbpfStacks),
        Box::new(EbpfTrace),
        // Helper commands for use in eBPF closures
        Box::new(Emit),
        Box::new(Filter),
        Box::new(Count),
        Box::new(Histogram),
        Box::new(StartTimer),
        Box::new(StopTimer),
        Box::new(ReadStr),
        Box::new(ReadKernelStr),
    ]
}
