//! Filter BPF helpers
//!
//! Helpers for early-exit filtering:
//! - bpf-filter-pid
//! - bpf-filter-comm

use crate::compiler::instruction::{BpfHelper, EbpfInsn, EbpfReg};
use crate::compiler::ir_to_ebpf::IrToEbpfCompiler;
use crate::compiler::CompileError;

/// Extension trait for filter helpers
pub trait FilterHelpers {
    fn compile_bpf_filter_pid(&mut self) -> Result<(), CompileError>;
    fn compile_bpf_filter_comm(&mut self) -> Result<(), CompileError>;
}

impl FilterHelpers for IrToEbpfCompiler<'_> {
    /// Compile bpf-filter-pid: exit early if current TGID doesn't match
    ///
    /// Gets the first pushed positional argument (target PID) and compares
    /// with the current TGID. If they don't match, exits the program early.
    fn compile_bpf_filter_pid(&mut self) -> Result<(), CompileError> {
        // Get the target PID from pushed arguments
        let arg_reg = self.pop_pushed_arg().ok_or_else(|| {
            CompileError::UnsupportedInstruction("bpf-filter-pid requires a PID argument".into())
        })?;

        // Get the target PID value (should already be loaded in a register)
        let target_reg = self.ensure_reg(arg_reg)?;

        // Get current TGID
        self.builder()
            .push(EbpfInsn::call(BpfHelper::GetCurrentPidTgid));
        // Right-shift by 32 to get the TGID
        self.builder().push(EbpfInsn::rsh64_imm(EbpfReg::R0, 32));

        // Compare R0 (current TGID) with target
        // If equal, continue; if not equal, exit with 0
        // jne r0, target_reg, +2 (skip to exit)
        self.builder()
            .push(EbpfInsn::jeq_reg(EbpfReg::R0, target_reg, 2));

        // Not matching - exit early
        self.builder().push(EbpfInsn::mov64_imm(EbpfReg::R0, 0));
        self.builder().push(EbpfInsn::exit());

        // Matching - continue execution (fall through)
        Ok(())
    }

    /// Compile bpf-filter-comm: exit early if current comm doesn't match
    ///
    /// Gets the first pushed positional argument (target comm as i64) and
    /// compares with the first 8 bytes of current comm. If they don't match,
    /// exits the program early.
    fn compile_bpf_filter_comm(&mut self) -> Result<(), CompileError> {
        // Get the target comm from pushed arguments
        let arg_reg = self.pop_pushed_arg().ok_or_else(|| {
            CompileError::UnsupportedInstruction("bpf-filter-comm requires a comm argument".into())
        })?;

        // Get the target comm value (should already be loaded in a register)
        let target_reg = self.ensure_reg(arg_reg)?;

        // Get current comm (first 8 bytes)
        // Allocate 16 bytes on stack for TASK_COMM_LEN
        self.check_stack_space(16)?;
        let comm_stack_offset = self.current_stack_offset() - 16;
        self.advance_stack_offset(16);

        // R1 = pointer to buffer on stack
        self.builder()
            .push(EbpfInsn::mov64_reg(EbpfReg::R1, EbpfReg::R10));
        self.builder()
            .push(EbpfInsn::add64_imm(EbpfReg::R1, comm_stack_offset as i32));

        // R2 = size (16 = TASK_COMM_LEN)
        self.builder().push(EbpfInsn::mov64_imm(EbpfReg::R2, 16));

        // Call bpf_get_current_comm
        self.builder().push(EbpfInsn::call(BpfHelper::GetCurrentComm));

        // Load first 8 bytes from buffer into R0
        self.builder().push(EbpfInsn::ldxdw(
            EbpfReg::R0,
            EbpfReg::R10,
            comm_stack_offset,
        ));

        // Compare R0 (current comm first 8 bytes) with target
        // If equal, continue; if not equal, exit with 0
        self.builder()
            .push(EbpfInsn::jeq_reg(EbpfReg::R0, target_reg, 2));

        // Not matching - exit early
        self.builder().push(EbpfInsn::mov64_imm(EbpfReg::R0, 0));
        self.builder().push(EbpfInsn::exit());

        // Matching - continue execution (fall through)
        Ok(())
    }
}
