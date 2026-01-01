//! eBPF bytecode compiler
//!
//! This module handles compilation from Nushell IR to eBPF bytecode.

mod btf;
mod elf;
mod helpers;
pub mod instruction;
mod ir_to_ebpf;
mod register_alloc;

pub use elf::{
    BpfFieldType, BpfMapDef, EbpfMap, EbpfProgram, EbpfProgramType, EventSchema, MapRelocation,
    SchemaField,
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
}
