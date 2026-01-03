//! Output BPF helpers
//!
//! Helpers for emitting data to userspace:
//! - bpf-emit (integers, strings, records)
//! - bpf-read-str, bpf-read-kernel-str

use nu_protocol::RegId;

use crate::compiler::CompileError;
use crate::compiler::elf::{EventSchema, MapRelocation, SchemaField};
use crate::compiler::instruction::{BpfHelper, EbpfInsn, EbpfReg};
use crate::compiler::ir_to_ebpf::{IrToEbpfCompiler, RINGBUF_MAP_NAME, RecordBuilder};

/// Extension trait for output helpers
pub trait OutputHelpers {
    fn compile_bpf_emit(&mut self, src_dst: RegId) -> Result<(), CompileError>;
    fn compile_bpf_read_str(
        &mut self,
        src_dst: RegId,
        user_space: bool,
    ) -> Result<(), CompileError>;
    fn compile_bpf_emit_record(
        &mut self,
        src_dst: RegId,
        record: RecordBuilder,
    ) -> Result<(), CompileError>;
}

impl OutputHelpers for IrToEbpfCompiler<'_> {
    /// Compile bpf-emit: output a value to the ring buffer
    ///
    /// This uses bpf_ringbuf_output to send a 64-bit value to userspace.
    /// Ring buffer is more efficient than perf buffer:
    /// - Single shared buffer instead of per-CPU buffers
    /// - Lower overhead for event submission
    fn compile_bpf_emit(&mut self, src_dst: RegId) -> Result<(), CompileError> {
        // Check if the source is a record
        if let Some(record) = self.take_record_builder(src_dst) {
            return self.compile_bpf_emit_record(src_dst, record);
        }

        // Mark that we need the ring buffer map
        self.set_needs_ringbuf(true);

        let ebpf_src = self.ensure_reg(src_dst)?;

        // Allocate stack space for the event data (8 bytes for u64)
        self.check_stack_space(8)?;
        let event_stack_offset = self.current_stack_offset();
        self.advance_stack_offset(8);

        // Store the value to the stack for bpf_ringbuf_output
        self.builder()
            .push(EbpfInsn::stxdw(EbpfReg::R10, event_stack_offset, ebpf_src));

        // bpf_ringbuf_output(map, data, size, flags)
        // R1 = map (ring buffer map pointer, will be relocated)
        // R2 = data pointer (stack address)
        // R3 = data size (8 bytes)
        // R4 = flags (0 = normal wakeup)

        // R1 = map fd (load with relocation)
        let reloc_offset = self.builder().len() * 8; // Byte offset
        let [insn1, insn2] = EbpfInsn::ld_map_fd(EbpfReg::R1);
        self.builder().push(insn1);
        self.builder().push(insn2);

        // Record relocation
        self.add_relocation(MapRelocation {
            insn_offset: reloc_offset,
            map_name: RINGBUF_MAP_NAME.to_string(),
        });

        // R2 = pointer to data on stack
        self.builder()
            .push(EbpfInsn::mov64_reg(EbpfReg::R2, EbpfReg::R10));
        self.builder()
            .push(EbpfInsn::add64_imm(EbpfReg::R2, event_stack_offset as i32));

        // R3 = size (8 bytes)
        self.builder().push(EbpfInsn::mov64_imm(EbpfReg::R3, 8));

        // R4 = flags (0 = normal wakeup behavior)
        self.builder().push(EbpfInsn::mov64_imm(EbpfReg::R4, 0));

        // Call bpf_ringbuf_output
        self.builder()
            .push(EbpfInsn::call(BpfHelper::RingbufOutput));

        // bpf-emit returns the original value for chaining
        // The value is still in ebpf_src register (we only copied it to stack)

        Ok(())
    }

    /// Compile bpf-read-str / bpf-read-user-str: read a string and emit it
    ///
    /// Takes a pointer from the pipeline input, reads up to 128 bytes of
    /// null-terminated string from memory, and emits to ring buffer.
    ///
    /// If `user_space` is true, reads from user-space memory (for syscall args).
    /// If `user_space` is false, reads from kernel memory.
    fn compile_bpf_read_str(
        &mut self,
        src_dst: RegId,
        user_space: bool,
    ) -> Result<(), CompileError> {
        // Mark that we need the ring buffer map
        self.set_needs_ringbuf(true);

        // Get the source pointer from the input register
        let src_ptr = self.ensure_reg(src_dst)?;

        // Allocate stack space for the string buffer (128 bytes max)
        const STR_BUF_SIZE: i16 = 128;
        self.check_stack_space(STR_BUF_SIZE)?;
        let str_stack_offset = self.current_stack_offset() - STR_BUF_SIZE;
        self.advance_stack_offset(STR_BUF_SIZE);

        // Call bpf_probe_read_{kernel,user}_str(dst, size, unsafe_ptr)
        // R1 = dst (stack buffer)
        self.builder()
            .push(EbpfInsn::mov64_reg(EbpfReg::R1, EbpfReg::R10));
        self.builder()
            .push(EbpfInsn::add64_imm(EbpfReg::R1, str_stack_offset as i32));

        // R2 = size
        self.builder()
            .push(EbpfInsn::mov64_imm(EbpfReg::R2, STR_BUF_SIZE as i32));

        // R3 = src pointer (from input)
        self.builder()
            .push(EbpfInsn::mov64_reg(EbpfReg::R3, src_ptr));

        // Call appropriate helper based on memory type
        let helper = if user_space {
            BpfHelper::ProbeReadUserStr
        } else {
            BpfHelper::ProbeReadKernelStr
        };
        self.builder().push(EbpfInsn::call(helper));

        // R0 now contains the number of bytes read (including null terminator)
        // or negative error code

        // Now emit the string to ring buffer
        // bpf_ringbuf_output(map, data, size, flags)

        // R1 = map (will be relocated)
        let reloc_offset = self.builder().len() * 8;
        let [insn1, insn2] = EbpfInsn::ld_map_fd(EbpfReg::R1);
        self.builder().push(insn1);
        self.builder().push(insn2);
        self.add_relocation(MapRelocation {
            insn_offset: reloc_offset,
            map_name: RINGBUF_MAP_NAME.to_string(),
        });

        // R2 = pointer to data on stack
        self.builder()
            .push(EbpfInsn::mov64_reg(EbpfReg::R2, EbpfReg::R10));
        self.builder()
            .push(EbpfInsn::add64_imm(EbpfReg::R2, str_stack_offset as i32));

        // R3 = size (use full buffer size)
        self.builder()
            .push(EbpfInsn::mov64_imm(EbpfReg::R3, STR_BUF_SIZE as i32));

        // R4 = flags (0 = normal wakeup)
        self.builder().push(EbpfInsn::mov64_imm(EbpfReg::R4, 0));

        // Call bpf_ringbuf_output
        self.builder()
            .push(EbpfInsn::call(BpfHelper::RingbufOutput));

        // Set result to 0 (success indicator)
        let ebpf_dst = self.alloc_reg(src_dst)?;
        self.builder().push(EbpfInsn::mov64_imm(ebpf_dst, 0));

        Ok(())
    }

    /// Compile bpf-emit for a structured record
    ///
    /// The field values are stored on the stack during RecordInsert, but they may
    /// not be contiguous (due to register spills between inserts). We need to copy
    /// them to a contiguous buffer before emitting.
    fn compile_bpf_emit_record(
        &mut self,
        src_dst: RegId,
        record: RecordBuilder,
    ) -> Result<(), CompileError> {
        self.set_needs_ringbuf(true);

        if record.fields.is_empty() {
            // Empty record - just emit nothing
            let ebpf_dst = self.alloc_reg(src_dst)?;
            self.builder().push(EbpfInsn::mov64_imm(ebpf_dst, 0));
            return Ok(());
        }

        // Build schema from fields (in insertion order)
        let mut fields_schema = Vec::new();
        let mut offset = 0usize;
        let mut total_size = 0usize;

        for field in record.fields.iter() {
            let size = field.field_type.size();
            fields_schema.push(SchemaField {
                name: field.name.clone(),
                field_type: field.field_type,
                offset,
            });
            offset += size;
            total_size += size;
        }

        // Store the schema for the loader
        self.set_event_schema(Some(EventSchema {
            fields: fields_schema,
            total_size,
        }));

        // Allocate a contiguous buffer for the record
        self.check_stack_space(total_size as i16)?;
        let buffer_offset = self.current_stack_offset() - total_size as i16;
        self.advance_stack_offset(total_size as i16);

        // Copy each field to the contiguous buffer in order
        let mut dest_offset = buffer_offset;
        for field in record.fields.iter() {
            let field_size = field.field_type.size();

            // Load field value from its original location
            // For Int (8 bytes), use a single load/store
            // For larger types (Comm=16, String=128), copy in 8-byte chunks
            let chunks = field_size / 8;
            for chunk in 0..chunks {
                let src = field.stack_offset + (chunk * 8) as i16;
                let dst = dest_offset + (chunk * 8) as i16;

                // Load from source
                self.builder()
                    .push(EbpfInsn::ldxdw(EbpfReg::R0, EbpfReg::R10, src));
                // Store to destination
                self.builder()
                    .push(EbpfInsn::stxdw(EbpfReg::R10, dst, EbpfReg::R0));
            }

            dest_offset += field_size as i16;
        }

        // Emit the contiguous buffer to ring buffer
        // bpf_ringbuf_output(map, data, size, flags)

        // R1 = map (will be relocated)
        let reloc_offset = self.builder().len() * 8;
        let [insn1, insn2] = EbpfInsn::ld_map_fd(EbpfReg::R1);
        self.builder().push(insn1);
        self.builder().push(insn2);
        self.add_relocation(MapRelocation {
            insn_offset: reloc_offset,
            map_name: RINGBUF_MAP_NAME.to_string(),
        });

        // R2 = pointer to contiguous buffer
        self.builder()
            .push(EbpfInsn::mov64_reg(EbpfReg::R2, EbpfReg::R10));
        self.builder()
            .push(EbpfInsn::add64_imm(EbpfReg::R2, buffer_offset as i32));

        // R3 = total record size
        self.builder()
            .push(EbpfInsn::mov64_imm(EbpfReg::R3, total_size as i32));

        // R4 = flags (0 = normal wakeup)
        self.builder().push(EbpfInsn::mov64_imm(EbpfReg::R4, 0));

        // Call bpf_ringbuf_output
        self.builder()
            .push(EbpfInsn::call(BpfHelper::RingbufOutput));

        // Set destination to 0
        let ebpf_dst = self.alloc_reg(src_dst)?;
        self.builder().push(EbpfInsn::mov64_imm(ebpf_dst, 0));

        Ok(())
    }
}
