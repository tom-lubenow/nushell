//! BPF helper command compilation
//!
//! This module organizes the compilation of eBPF commands into categories.
//! Each submodule defines extension traits for IrToEbpfCompiler.

mod aggregation;
mod filter;
mod output;
mod timing;

pub use aggregation::AggregationHelpers;
pub use filter::FilterHelpers;
pub use output::OutputHelpers;
pub use timing::TimingHelpers;
