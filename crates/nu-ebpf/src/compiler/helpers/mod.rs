//! BPF helper command compilation
//!
//! This module organizes the compilation of bpf-* commands into categories.
//! Each submodule defines extension traits for IrToEbpfCompiler.

mod aggregation;
mod data;
mod filter;
mod output;
mod timing;

pub use aggregation::AggregationHelpers;
pub use data::DataHelpers;
pub use filter::FilterHelpers;
pub use output::OutputHelpers;
pub use timing::TimingHelpers;
