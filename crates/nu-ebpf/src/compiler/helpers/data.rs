//! Data access BPF helpers
//!
//! Helpers for accessing process/kernel data:
//! - bpf-pid, bpf-tgid, bpf-uid, bpf-ktime
//! - bpf-comm
//! - bpf-arg, bpf-retval

use nu_protocol::RegId;

use crate::compiler::elf::BpfFieldType;
use crate::compiler::instruction::{BpfHelper, EbpfInsn, EbpfReg};
use crate::compiler::ir_to_ebpf::{pt_regs_offsets, IrToEbpfCompiler};
use crate::compiler::CompileError;

/// Extension trait for data access helpers
pub trait DataHelpers {
    fn compile_bpf_pid(&mut self, src_dst: RegId) -> Result<(), CompileError>;
    fn compile_bpf_tgid(&mut self, src_dst: RegId) -> Result<(), CompileError>;
    fn compile_bpf_uid(&mut self, src_dst: RegId) -> Result<(), CompileError>;
    fn compile_bpf_ktime(&mut self, src_dst: RegId) -> Result<(), CompileError>;
    fn compile_bpf_comm(&mut self, src_dst: RegId) -> Result<(), CompileError>;
    fn compile_bpf_arg(&mut self, src_dst: RegId) -> Result<(), CompileError>;
    fn compile_bpf_retval(&mut self, src_dst: RegId) -> Result<(), CompileError>;
}

impl DataHelpers for IrToEbpfCompiler<'_> {
    /// Compile bpf-pid: get full pid_tgid value
    fn compile_bpf_pid(&mut self, src_dst: RegId) -> Result<(), CompileError> {
        // bpf_get_current_pid_tgid() returns (tgid << 32) | pid
        // We'll return the full value and let user extract pid with bit ops
        self.builder()
            .push(EbpfInsn::call(BpfHelper::GetCurrentPidTgid));
        // Result is in R0, move to destination register
        let ebpf_dst = self.alloc_reg(src_dst)?;
        if ebpf_dst.as_u8() != EbpfReg::R0.as_u8() {
            self.builder()
                .push(EbpfInsn::mov64_reg(ebpf_dst, EbpfReg::R0));
        }
        Ok(())
    }

    /// Compile bpf-tgid: get process ID (thread group ID)
    fn compile_bpf_tgid(&mut self, src_dst: RegId) -> Result<(), CompileError> {
        // bpf_get_current_pid_tgid() returns (tgid << 32) | pid
        // TGID is in the upper 32 bits - this is the "process ID" users expect
        self.builder()
            .push(EbpfInsn::call(BpfHelper::GetCurrentPidTgid));
        // Right-shift by 32 to get the TGID
        self.builder().push(EbpfInsn::rsh64_imm(EbpfReg::R0, 32));
        // Result is in R0, move to destination register
        let ebpf_dst = self.alloc_reg(src_dst)?;
        if ebpf_dst.as_u8() != EbpfReg::R0.as_u8() {
            self.builder()
                .push(EbpfInsn::mov64_reg(ebpf_dst, EbpfReg::R0));
        }
        Ok(())
    }

    /// Compile bpf-uid: get user ID
    fn compile_bpf_uid(&mut self, src_dst: RegId) -> Result<(), CompileError> {
        // bpf_get_current_uid_gid() returns (uid << 32) | gid
        self.builder()
            .push(EbpfInsn::call(BpfHelper::GetCurrentUidGid));
        let ebpf_dst = self.alloc_reg(src_dst)?;
        if ebpf_dst.as_u8() != EbpfReg::R0.as_u8() {
            self.builder()
                .push(EbpfInsn::mov64_reg(ebpf_dst, EbpfReg::R0));
        }
        Ok(())
    }

    /// Compile bpf-ktime: get kernel monotonic time in nanoseconds
    fn compile_bpf_ktime(&mut self, src_dst: RegId) -> Result<(), CompileError> {
        // bpf_ktime_get_ns() returns kernel time in nanoseconds
        self.builder().push(EbpfInsn::call(BpfHelper::KtimeGetNs));
        let ebpf_dst = self.alloc_reg(src_dst)?;
        if ebpf_dst.as_u8() != EbpfReg::R0.as_u8() {
            self.builder()
                .push(EbpfInsn::mov64_reg(ebpf_dst, EbpfReg::R0));
        }
        Ok(())
    }

    /// Compile bpf-comm: get current process name
    ///
    /// Calls bpf_get_current_comm to get the process name, then returns
    /// the first 8 bytes as an i64 for easy comparison/emission.
    fn compile_bpf_comm(&mut self, src_dst: RegId) -> Result<(), CompileError> {
        // Track that this register contains a comm value
        self.set_register_type(src_dst, BpfFieldType::Comm);

        // Allocate 16 bytes on stack for TASK_COMM_LEN
        let comm_stack_offset = self.alloc_stack(16)?;

        // R1 = pointer to buffer on stack
        self.builder()
            .push(EbpfInsn::mov64_reg(EbpfReg::R1, EbpfReg::R10));
        self.builder()
            .push(EbpfInsn::add64_imm(EbpfReg::R1, comm_stack_offset as i32));

        // R2 = size (16 = TASK_COMM_LEN)
        self.builder().push(EbpfInsn::mov64_imm(EbpfReg::R2, 16));

        // Call bpf_get_current_comm
        self.builder().push(EbpfInsn::call(BpfHelper::GetCurrentComm));

        // Load first 8 bytes from buffer into destination register
        let ebpf_dst = self.alloc_reg(src_dst)?;
        self.builder()
            .push(EbpfInsn::ldxdw(ebpf_dst, EbpfReg::R10, comm_stack_offset));

        Ok(())
    }

    /// Compile bpf-arg: read a function argument from pt_regs
    ///
    /// The argument index is passed as a positional argument.
    /// Reads from the context pointer (saved in R9) at the appropriate offset.
    fn compile_bpf_arg(&mut self, src_dst: RegId) -> Result<(), CompileError> {
        // Get the argument index from pushed arguments
        let arg_reg = self.pop_pushed_arg().ok_or_else(|| {
            CompileError::UnsupportedInstruction("bpf-arg requires an index argument".into())
        })?;

        // Look up the compile-time literal value for the index
        let index = self.get_literal_value(arg_reg).ok_or_else(|| {
            CompileError::UnsupportedInstruction(
                "bpf-arg index must be a compile-time constant (literal integer)".into(),
            )
        })?;

        // Validate the index
        let max_args = pt_regs_offsets::ARG_OFFSETS.len();
        if index < 0 || index as usize >= max_args {
            return Err(CompileError::UnsupportedInstruction(format!(
                "bpf-arg index {} out of range (0-{})",
                index,
                max_args - 1
            )));
        }

        // Get the offset for this argument
        let offset = pt_regs_offsets::ARG_OFFSETS[index as usize];

        // Allocate destination register
        let ebpf_dst = self.alloc_reg(src_dst)?;

        // ldxdw dst, [r9 + offset] - load 64-bit value from ctx
        self.builder()
            .push(EbpfInsn::ldxdw(ebpf_dst, EbpfReg::R9, offset));

        Ok(())
    }

    /// Compile bpf-retval: read the return value from pt_regs (for kretprobe)
    ///
    /// Reads the return value register from the context pointer.
    fn compile_bpf_retval(&mut self, src_dst: RegId) -> Result<(), CompileError> {
        // Allocate destination register
        let ebpf_dst = self.alloc_reg(src_dst)?;

        // Read the return value from context (R9 has the ctx pointer)
        // On x86_64, return value is in rax at offset 80
        let offset = pt_regs_offsets::RETVAL_OFFSET;

        // ldxdw dst, [r9 + offset] - load 64-bit value from ctx
        self.builder()
            .push(EbpfInsn::ldxdw(ebpf_dst, EbpfReg::R9, offset));

        Ok(())
    }
}
