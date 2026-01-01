//! eBPF commands for Nushell
//!
//! These commands allow attaching Nushell closures (compiled to eBPF) to kernel
//! probe points for tracing.

mod attach;
mod counters;
mod detach;
mod events;
mod helpers;
mod histogram;
mod list;
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
pub use events::EbpfEvents;
pub use histogram::EbpfHistogram;
pub use helpers::{
    BpfArg, BpfComm, BpfCount, BpfEmit, BpfEmitComm, BpfFilterComm, BpfFilterPid, BpfHistogram,
    BpfKtime, BpfPid, BpfReadStr, BpfReadUserStr, BpfRetval, BpfStartTimer, BpfStopTimer, BpfTgid,
    BpfUid,
};
pub use list::EbpfList;
pub use trace::EbpfTrace;

use nu_protocol::engine::Command;

/// Get all eBPF commands
pub fn commands() -> Vec<Box<dyn Command>> {
    vec![
        Box::new(EbpfAttach),
        Box::new(EbpfCounters),
        Box::new(EbpfDetach),
        Box::new(EbpfEvents),
        Box::new(EbpfHistogram),
        Box::new(EbpfList),
        Box::new(EbpfTrace),
        // BPF helper commands (usable in closures)
        Box::new(BpfPid),
        Box::new(BpfTgid),
        Box::new(BpfUid),
        Box::new(BpfKtime),
        Box::new(BpfComm),
        Box::new(BpfArg),
        Box::new(BpfRetval),
        Box::new(BpfReadStr),
        Box::new(BpfReadUserStr),
        Box::new(BpfCount),
        Box::new(BpfEmit),
        Box::new(BpfEmitComm),
        Box::new(BpfFilterPid),
        Box::new(BpfFilterComm),
        Box::new(BpfStartTimer),
        Box::new(BpfStopTimer),
        Box::new(BpfHistogram),
    ]
}
