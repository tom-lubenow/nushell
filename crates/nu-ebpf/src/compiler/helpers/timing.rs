//! Timing BPF helpers
//!
//! Helpers for latency measurement:
//! - bpf-start-timer
//! - bpf-stop-timer

use nu_protocol::RegId;

use crate::compiler::CompileError;
use crate::compiler::elf::MapRelocation;
use crate::compiler::instruction::{BpfHelper, EbpfInsn, EbpfReg};
use crate::compiler::ir_to_ebpf::{IrToEbpfCompiler, TIMESTAMP_MAP_NAME};

/// Extension trait for timing helpers
pub trait TimingHelpers {
    fn compile_bpf_start_timer(&mut self, src_dst: RegId) -> Result<(), CompileError>;
    fn compile_bpf_stop_timer(&mut self, src_dst: RegId) -> Result<(), CompileError>;
}

impl TimingHelpers for IrToEbpfCompiler<'_> {
    /// Compile bpf-start-timer: store current ktime keyed by TID
    ///
    /// Stores the current kernel timestamp in a hash map keyed by the thread ID.
    /// Used for latency measurement - call bpf-stop-timer to get elapsed time.
    fn compile_bpf_start_timer(&mut self, src_dst: RegId) -> Result<(), CompileError> {
        self.set_needs_timestamp_map(true);

        // Allocate stack space for key (TID) and value (timestamp)
        self.check_stack_space(16)?;
        let key_stack_offset = self.current_stack_offset() - 8;
        let value_stack_offset = self.current_stack_offset() - 16;
        self.advance_stack_offset(16);

        // Get current TGID (thread group ID) as the key
        // Using TGID instead of TID allows matching entry/return across threads
        // Note: For per-thread tracking, use the lower 32 bits (PID/TID)
        self.builder()
            .push(EbpfInsn::call(BpfHelper::GetCurrentPidTgid));
        // Store the full pid_tgid as key (allows unique per-thread tracking)
        self.builder()
            .push(EbpfInsn::stxdw(EbpfReg::R10, key_stack_offset, EbpfReg::R0));

        // Get current kernel time
        self.builder().push(EbpfInsn::call(BpfHelper::KtimeGetNs));
        // Store as value
        self.builder().push(EbpfInsn::stxdw(
            EbpfReg::R10,
            value_stack_offset,
            EbpfReg::R0,
        ));

        // Call bpf_map_update_elem(map, &key, &value, BPF_ANY)
        // R1 = map fd (will be relocated)
        let reloc_offset = self.builder().len() * 8;
        let [insn1, insn2] = EbpfInsn::ld_map_fd(EbpfReg::R1);
        self.builder().push(insn1);
        self.builder().push(insn2);
        self.add_relocation(MapRelocation {
            insn_offset: reloc_offset,
            map_name: TIMESTAMP_MAP_NAME.to_string(),
        });

        // R2 = pointer to key
        self.builder()
            .push(EbpfInsn::mov64_reg(EbpfReg::R2, EbpfReg::R10));
        self.builder()
            .push(EbpfInsn::add64_imm(EbpfReg::R2, key_stack_offset as i32));

        // R3 = pointer to value
        self.builder()
            .push(EbpfInsn::mov64_reg(EbpfReg::R3, EbpfReg::R10));
        self.builder()
            .push(EbpfInsn::add64_imm(EbpfReg::R3, value_stack_offset as i32));

        // R4 = flags (BPF_ANY = 0)
        self.builder().push(EbpfInsn::mov64_imm(EbpfReg::R4, 0));

        // Call bpf_map_update_elem
        self.builder()
            .push(EbpfInsn::call(BpfHelper::MapUpdateElem));

        // Set destination to 0 (void return)
        let ebpf_dst = self.alloc_reg(src_dst)?;
        self.builder().push(EbpfInsn::mov64_imm(ebpf_dst, 0));

        Ok(())
    }

    /// Compile bpf-stop-timer: look up start time, compute delta, delete entry
    ///
    /// Looks up the start timestamp for the current TID, computes the elapsed
    /// time, deletes the map entry, and returns the delta in nanoseconds.
    /// Returns 0 if no matching start timer was found.
    fn compile_bpf_stop_timer(&mut self, src_dst: RegId) -> Result<(), CompileError> {
        self.set_needs_timestamp_map(true);

        // Allocate destination register early so both paths can use it
        let ebpf_dst = self.alloc_reg(src_dst)?;

        // Create labels for control flow
        let no_timer_label = self.create_label();
        let done_label = self.create_label();

        // Allocate stack space for key (TID)
        self.check_stack_space(8)?;
        let key_stack_offset = self.current_stack_offset() - 8;
        self.advance_stack_offset(8);

        // Get current pid_tgid as the key
        self.builder()
            .push(EbpfInsn::call(BpfHelper::GetCurrentPidTgid));
        self.builder()
            .push(EbpfInsn::stxdw(EbpfReg::R10, key_stack_offset, EbpfReg::R0));

        // Look up the start timestamp
        // bpf_map_lookup_elem(map, &key) -> *value or NULL
        let lookup_reloc_offset = self.builder().len() * 8;
        let [insn1, insn2] = EbpfInsn::ld_map_fd(EbpfReg::R1);
        self.builder().push(insn1);
        self.builder().push(insn2);
        self.add_relocation(MapRelocation {
            insn_offset: lookup_reloc_offset,
            map_name: TIMESTAMP_MAP_NAME.to_string(),
        });

        // R2 = pointer to key
        self.builder()
            .push(EbpfInsn::mov64_reg(EbpfReg::R2, EbpfReg::R10));
        self.builder()
            .push(EbpfInsn::add64_imm(EbpfReg::R2, key_stack_offset as i32));

        // Call bpf_map_lookup_elem
        self.builder()
            .push(EbpfInsn::call(BpfHelper::MapLookupElem));

        // R0 = pointer to value or NULL
        // If NULL, jump to no_timer path
        self.emit_jump_if_zero_to_label(EbpfReg::R0, no_timer_label);

        // Value exists - load the start timestamp
        // Save to callee-saved register R6 (not clobbered by helper calls)
        self.builder()
            .push(EbpfInsn::ldxdw(EbpfReg::R6, EbpfReg::R0, 0));

        // Get current time
        self.builder().push(EbpfInsn::call(BpfHelper::KtimeGetNs));
        // R0 = current_time

        // Compute delta = current_time - start_time
        // R0 = R0 - R6
        self.builder()
            .push(EbpfInsn::sub64_reg(EbpfReg::R0, EbpfReg::R6));

        // Save the delta temporarily
        self.check_stack_space(8)?;
        let delta_stack_offset = self.current_stack_offset() - 8;
        self.advance_stack_offset(8);
        self.builder().push(EbpfInsn::stxdw(
            EbpfReg::R10,
            delta_stack_offset,
            EbpfReg::R0,
        ));

        // Delete the map entry
        // bpf_map_delete_elem(map, &key)
        let delete_reloc_offset = self.builder().len() * 8;
        let [insn1, insn2] = EbpfInsn::ld_map_fd(EbpfReg::R1);
        self.builder().push(insn1);
        self.builder().push(insn2);
        self.add_relocation(MapRelocation {
            insn_offset: delete_reloc_offset,
            map_name: TIMESTAMP_MAP_NAME.to_string(),
        });

        // R2 = pointer to key
        self.builder()
            .push(EbpfInsn::mov64_reg(EbpfReg::R2, EbpfReg::R10));
        self.builder()
            .push(EbpfInsn::add64_imm(EbpfReg::R2, key_stack_offset as i32));

        // Call bpf_map_delete_elem
        self.builder()
            .push(EbpfInsn::call(BpfHelper::MapDeleteElem));

        // Restore the delta to destination register
        self.builder()
            .push(EbpfInsn::ldxdw(ebpf_dst, EbpfReg::R10, delta_stack_offset));

        // Jump to done
        self.emit_jump_to_label(done_label);

        // No matching timer - return 0
        self.bind_label(no_timer_label);
        self.builder().push(EbpfInsn::mov64_imm(ebpf_dst, 0));

        // Done
        self.bind_label(done_label);

        Ok(())
    }
}
