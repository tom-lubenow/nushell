//! Aggregation BPF helpers
//!
//! Helpers for counting and histograms:
//! - bpf-count
//! - bpf-histogram

use nu_protocol::RegId;

use crate::compiler::elf::MapRelocation;
use crate::compiler::instruction::{opcode, BpfHelper, EbpfInsn, EbpfReg};
use crate::compiler::ir_to_ebpf::{IrToEbpfCompiler, COUNTER_MAP_NAME, HISTOGRAM_MAP_NAME};
use crate::compiler::CompileError;

/// Extension trait for aggregation helpers
pub trait AggregationHelpers {
    fn compile_bpf_count(&mut self, src_dst: RegId) -> Result<(), CompileError>;
    fn compile_bpf_histogram(&mut self, src_dst: RegId) -> Result<(), CompileError>;
}

impl AggregationHelpers for IrToEbpfCompiler<'_> {
    /// Compile bpf-count: increment a counter for the input key
    ///
    /// Uses a hash map to count occurrences by key. The input value is used
    /// as the key, and the counter is atomically incremented.
    fn compile_bpf_count(&mut self, src_dst: RegId) -> Result<(), CompileError> {
        // Mark that we need the counter map
        self.set_needs_counter_map(true);

        let ebpf_src = self.ensure_reg(src_dst)?;

        // Allocate stack space for key and value
        // Key: 8 bytes (i64)
        // Value: 8 bytes (i64)
        let base_offset = self.alloc_stack(16)?;
        let key_stack_offset = base_offset + 8; // key at higher address
        let value_stack_offset = base_offset; // value at lower address

        // Store the key to stack
        self.builder()
            .push(EbpfInsn::stxdw(EbpfReg::R10, key_stack_offset, ebpf_src));

        // Create labels for control flow
        let init_label = self.create_label();
        let done_label = self.create_label();

        // Step 1: Try to look up existing value
        // R1 = map (will be relocated)
        let lookup_reloc_offset = self.builder().len() * 8;
        let [insn1, insn2] = EbpfInsn::ld_map_fd(EbpfReg::R1);
        self.builder().push(insn1);
        self.builder().push(insn2);
        self.add_relocation(MapRelocation {
            insn_offset: lookup_reloc_offset,
            map_name: COUNTER_MAP_NAME.to_string(),
        });

        // R2 = pointer to key
        self.builder()
            .push(EbpfInsn::mov64_reg(EbpfReg::R2, EbpfReg::R10));
        self.builder()
            .push(EbpfInsn::add64_imm(EbpfReg::R2, key_stack_offset as i32));

        // Call bpf_map_lookup_elem
        self.builder().push(EbpfInsn::call(BpfHelper::MapLookupElem));

        // R0 = pointer to value or NULL
        // If NULL, jump to init path
        self.emit_jump_if_zero_to_label(EbpfReg::R0, init_label);

        // Value exists - load it, increment, store back
        // Load current value: r1 = *r0
        self.builder()
            .push(EbpfInsn::ldxdw(EbpfReg::R1, EbpfReg::R0, 0));
        // Increment: r1 += 1
        self.builder().push(EbpfInsn::add64_imm(EbpfReg::R1, 1));
        // Store back: *r0 = r1
        self.builder()
            .push(EbpfInsn::stxdw(EbpfReg::R0, 0, EbpfReg::R1));
        // Jump to end
        self.emit_jump_to_label(done_label);

        // Value doesn't exist - initialize to 1 and insert
        self.bind_label(init_label);
        // Store 1 to value slot on stack
        self.builder().push(EbpfInsn::mov64_imm(EbpfReg::R1, 1));
        self.builder().push(EbpfInsn::stxdw(
            EbpfReg::R10,
            value_stack_offset,
            EbpfReg::R1,
        ));

        // R1 = map (reload for update)
        let update_reloc_offset = self.builder().len() * 8;
        let [insn1, insn2] = EbpfInsn::ld_map_fd(EbpfReg::R1);
        self.builder().push(insn1);
        self.builder().push(insn2);
        self.add_relocation(MapRelocation {
            insn_offset: update_reloc_offset,
            map_name: COUNTER_MAP_NAME.to_string(),
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

        // R4 = flags (0 = BPF_ANY)
        self.builder().push(EbpfInsn::mov64_imm(EbpfReg::R4, 0));

        // Call bpf_map_update_elem
        self.builder().push(EbpfInsn::call(BpfHelper::MapUpdateElem));

        // End: bpf-count passes through the input value unchanged
        self.bind_label(done_label);

        Ok(())
    }

    /// Compile bpf-histogram: compute log2 bucket and increment counter
    ///
    /// Computes the log2 bucket of the input value and atomically increments
    /// the counter for that bucket in the histogram map.
    fn compile_bpf_histogram(&mut self, src_dst: RegId) -> Result<(), CompileError> {
        self.set_needs_histogram_map(true);

        let ebpf_src = self.ensure_reg(src_dst)?;

        // Allocate stack space for key (bucket) and value (count)
        self.check_stack_space(16)?;
        let key_stack_offset = self.current_stack_offset() - 8;
        let value_stack_offset = self.current_stack_offset() - 16;
        self.advance_stack_offset(16);

        // Create labels for control flow
        let bucket_zero_label = self.create_label();
        let store_bucket_label = self.create_label();
        let init_value_label = self.create_label();
        let done_label = self.create_label();

        // Compute log2 bucket
        // bucket = 64 - clz(value) for value > 0, else bucket = 0
        // eBPF doesn't have clz, so we use binary search

        // if value <= 0, jump to bucket_zero
        self.emit_jump_if_le_zero_to_label(ebpf_src, bucket_zero_label);

        // For positive values, compute log2 using binary search
        // Copy value to R0 for manipulation, bucket in R1
        self.builder()
            .push(EbpfInsn::mov64_reg(EbpfReg::R0, ebpf_src));
        self.builder().push(EbpfInsn::mov64_imm(EbpfReg::R1, 0));

        // Binary search for highest set bit
        // Check each power of 2, accumulating the bucket value

        // if value >= 2^32, bucket += 32
        self.emit_load_64bit_imm(EbpfReg::R2, 1i64 << 32);
        self.builder().push(EbpfInsn::new(
            opcode::BPF_JMP | opcode::BPF_JLT | opcode::BPF_X,
            EbpfReg::R0.as_u8(),
            EbpfReg::R2.as_u8(),
            2, // Skip next 2 instructions if less
            0,
        ));
        self.builder().push(EbpfInsn::add64_imm(EbpfReg::R1, 32));
        self.builder().push(EbpfInsn::rsh64_imm(EbpfReg::R0, 32));

        // if remaining >= 2^16, bucket += 16
        self.builder().push(EbpfInsn::new(
            opcode::BPF_JMP | opcode::BPF_JLT | opcode::BPF_K,
            EbpfReg::R0.as_u8(),
            0,
            2,
            1 << 16,
        ));
        self.builder().push(EbpfInsn::add64_imm(EbpfReg::R1, 16));
        self.builder().push(EbpfInsn::rsh64_imm(EbpfReg::R0, 16));

        // if remaining >= 2^8, bucket += 8
        self.builder().push(EbpfInsn::new(
            opcode::BPF_JMP | opcode::BPF_JLT | opcode::BPF_K,
            EbpfReg::R0.as_u8(),
            0,
            2,
            1 << 8,
        ));
        self.builder().push(EbpfInsn::add64_imm(EbpfReg::R1, 8));
        self.builder().push(EbpfInsn::rsh64_imm(EbpfReg::R0, 8));

        // if remaining >= 2^4, bucket += 4
        self.builder().push(EbpfInsn::new(
            opcode::BPF_JMP | opcode::BPF_JLT | opcode::BPF_K,
            EbpfReg::R0.as_u8(),
            0,
            2,
            1 << 4,
        ));
        self.builder().push(EbpfInsn::add64_imm(EbpfReg::R1, 4));
        self.builder().push(EbpfInsn::rsh64_imm(EbpfReg::R0, 4));

        // if remaining >= 2^2, bucket += 2
        self.builder().push(EbpfInsn::new(
            opcode::BPF_JMP | opcode::BPF_JLT | opcode::BPF_K,
            EbpfReg::R0.as_u8(),
            0,
            2,
            1 << 2,
        ));
        self.builder().push(EbpfInsn::add64_imm(EbpfReg::R1, 2));
        self.builder().push(EbpfInsn::rsh64_imm(EbpfReg::R0, 2));

        // if remaining >= 2^1, bucket += 1
        self.builder().push(EbpfInsn::new(
            opcode::BPF_JMP | opcode::BPF_JLT | opcode::BPF_K,
            EbpfReg::R0.as_u8(),
            0,
            1,
            1 << 1,
        ));
        self.builder().push(EbpfInsn::add64_imm(EbpfReg::R1, 1));

        // Jump to store_bucket (bucket is in R1)
        self.emit_jump_to_label(store_bucket_label);

        // bucket_zero: set bucket = 0
        self.bind_label(bucket_zero_label);
        self.builder().push(EbpfInsn::mov64_imm(EbpfReg::R1, 0));

        // store_bucket: common path - store bucket and update map
        self.bind_label(store_bucket_label);
        self.builder()
            .push(EbpfInsn::stxdw(EbpfReg::R10, key_stack_offset, EbpfReg::R1));

        // Look up current count
        let lookup_reloc_offset = self.builder().len() * 8;
        let [insn1, insn2] = EbpfInsn::ld_map_fd(EbpfReg::R1);
        self.builder().push(insn1);
        self.builder().push(insn2);
        self.add_relocation(MapRelocation {
            insn_offset: lookup_reloc_offset,
            map_name: HISTOGRAM_MAP_NAME.to_string(),
        });

        self.builder()
            .push(EbpfInsn::mov64_reg(EbpfReg::R2, EbpfReg::R10));
        self.builder()
            .push(EbpfInsn::add64_imm(EbpfReg::R2, key_stack_offset as i32));
        self.builder().push(EbpfInsn::call(BpfHelper::MapLookupElem));

        // If NULL, jump to init_value; otherwise increment in place
        self.emit_jump_if_zero_to_label(EbpfReg::R0, init_value_label);

        // Exists - load, increment, store back (in-place update)
        self.builder()
            .push(EbpfInsn::ldxdw(EbpfReg::R1, EbpfReg::R0, 0));
        self.builder().push(EbpfInsn::add64_imm(EbpfReg::R1, 1));
        self.builder()
            .push(EbpfInsn::stxdw(EbpfReg::R0, 0, EbpfReg::R1));
        self.emit_jump_to_label(done_label);

        // init_value: key not found, insert with count = 1
        self.bind_label(init_value_label);
        self.builder().push(EbpfInsn::mov64_imm(EbpfReg::R1, 1));
        self.builder().push(EbpfInsn::stxdw(
            EbpfReg::R10,
            value_stack_offset,
            EbpfReg::R1,
        ));

        let update_reloc_offset = self.builder().len() * 8;
        let [insn1, insn2] = EbpfInsn::ld_map_fd(EbpfReg::R1);
        self.builder().push(insn1);
        self.builder().push(insn2);
        self.add_relocation(MapRelocation {
            insn_offset: update_reloc_offset,
            map_name: HISTOGRAM_MAP_NAME.to_string(),
        });

        self.builder()
            .push(EbpfInsn::mov64_reg(EbpfReg::R2, EbpfReg::R10));
        self.builder()
            .push(EbpfInsn::add64_imm(EbpfReg::R2, key_stack_offset as i32));
        self.builder()
            .push(EbpfInsn::mov64_reg(EbpfReg::R3, EbpfReg::R10));
        self.builder()
            .push(EbpfInsn::add64_imm(EbpfReg::R3, value_stack_offset as i32));
        self.builder().push(EbpfInsn::mov64_imm(EbpfReg::R4, 0)); // BPF_ANY
        self.builder().push(EbpfInsn::call(BpfHelper::MapUpdateElem));

        // done: common exit
        self.bind_label(done_label);

        // Return the original value (pass-through for chaining)
        Ok(())
    }
}
