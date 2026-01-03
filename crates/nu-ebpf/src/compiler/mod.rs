//! eBPF bytecode compiler
//!
//! This module handles compilation from Nushell IR to eBPF bytecode.
//!
//! ## Compilation Pipeline
//!
//! Current (legacy):
//! ```text
//! Nushell IR → [ir_to_ebpf] → eBPF bytecode
//! ```
//!
//! New (MIR-based, in progress):
//! ```text
//! Nushell IR → [ir_to_mir] → MIR → [mir_to_ebpf] → eBPF bytecode
//! ```
//!
//! The MIR compiler can be enabled with `--mir-compiler` flag (experimental).

mod btf;
mod elf;
mod helpers;
pub mod instruction;
mod ir_ops;
mod ir_to_ebpf;
pub mod ir_to_mir;
pub mod mir;
mod register_alloc;

pub use elf::{
    BpfFieldType, BpfMapDef, EbpfMap, EbpfProgram, EbpfProgramType, EventSchema, MapRelocation,
    ProbeContext, SchemaField,
};
pub use instruction::{BpfHelper, EbpfInsn, EbpfReg};
pub use ir_to_ebpf::{CompileResult, IrToEbpfCompiler};

use thiserror::Error;

/// Errors that can occur during eBPF compilation
#[derive(Debug, Error)]
pub enum CompileError {
    #[error("Unsupported instruction: {0}")]
    UnsupportedInstruction(String),

    #[error("Unsupported literal type")]
    UnsupportedLiteral,

    #[error("Stack overflow: eBPF stack is limited to 512 bytes")]
    StackOverflow,

    #[error("Register exhaustion: too many live values")]
    RegisterExhaustion,

    #[error("ELF generation failed: {0}")]
    ElfError(String),

    #[error("Invalid probe specification: {0}")]
    InvalidProbeSpec(String),

    #[error("'retval' is only available on return probes (kretprobe, uretprobe)")]
    RetvalOnNonReturnProbe,

    #[error("Tracepoint field '{field}' not found. Available: {available}")]
    TracepointFieldNotFound { field: String, available: String },

    #[error("Could not load tracepoint context for '{category}/{name}': {reason}")]
    TracepointContextError {
        category: String,
        name: String,
        reason: String,
    },
}
