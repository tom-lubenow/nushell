//! Filter helper compilation
//!
//! Compiles the `filter` command that exits the eBPF program early
//! if the input condition is false.

use nu_protocol::RegId;

use crate::compiler::CompileError;
use crate::compiler::instruction::{EbpfInsn, EbpfReg};
use crate::compiler::ir_to_ebpf::IrToEbpfCompiler;

/// Extension trait for filter helper
pub trait FilterHelpers {
    fn compile_bpf_filter(&mut self, src_dst: RegId) -> Result<(), CompileError>;
}

impl FilterHelpers for IrToEbpfCompiler<'_> {
    /// Compile filter: exit program early if input is false (0)
    ///
    /// Takes a boolean value from the pipeline:
    /// - If 0 (false): exit program with return code 0 (event filtered)
    /// - If non-zero (true): continue execution (event passes filter)
    ///
    /// This is implemented as:
    /// ```text
    ///   JNE src, 0, +2   ; if src != 0, skip exit (continue)
    ///   MOV R0, 0        ; set return value to 0
    ///   EXIT             ; exit program
    ///   ; continue here if condition was true
    /// ```
    fn compile_bpf_filter(&mut self, src_dst: RegId) -> Result<(), CompileError> {
        let ebpf_src = self.ensure_reg(src_dst)?;

        // JNE src, 0, +2 - if condition is true (non-zero), skip the exit
        // Jump offset is +2 because we need to skip MOV and EXIT instructions
        self.builder().push(EbpfInsn::new(
            0x55, // JNE imm: BPF_JMP | BPF_JNE | BPF_K
            ebpf_src.as_u8(),
            0,
            2, // Skip next 2 instructions
            0, // Compare against 0
        ));

        // If we're here, condition was false (0) - exit early
        // MOV R0, 0 - set return value
        self.builder().push(EbpfInsn::mov64_imm(EbpfReg::R0, 0));

        // EXIT - exit the program
        self.builder().push(EbpfInsn::exit());

        // If condition was true, execution continues here
        // The pipeline value is consumed; subsequent commands start fresh
        Ok(())
    }
}
