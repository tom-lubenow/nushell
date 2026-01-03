//! IR operation compilation
//!
//! Handles compilation of Nushell IR instructions to eBPF bytecode:
//! - Literals (int, bool, string, record)
//! - Moves and clones
//! - Binary operations (math, bitwise, comparison)
//! - Variable load/store
//! - Logical NOT

use nu_protocol::ast::{Bits, Comparison, Math, Operator, RangeInclusion};
use nu_protocol::ir::Literal;
use nu_protocol::{RegId, VarId};

use crate::compiler::CompileError;
use crate::compiler::elf::BpfFieldType;
use crate::compiler::instruction::{EbpfInsn, EbpfReg, opcode};
use crate::compiler::ir_to_ebpf::{BoundedIterator, IrToEbpfCompiler, RecordBuilder, StackString};

/// Extension trait for IR operation compilation
pub trait IrOps {
    fn compile_load_literal(&mut self, dst: RegId, lit: &Literal) -> Result<(), CompileError>;
    fn compile_move(&mut self, dst: RegId, src: RegId) -> Result<(), CompileError>;
    fn compile_binary_op(
        &mut self,
        lhs_dst: RegId,
        op: &Operator,
        rhs: RegId,
    ) -> Result<(), CompileError>;
    fn compile_comparison(
        &mut self,
        lhs: EbpfReg,
        cmp: &Comparison,
        rhs: EbpfReg,
    ) -> Result<(), CompileError>;
    /// Compare two stack-based strings
    /// Returns result (0 or 1) in dst_reg
    fn compile_string_comparison(
        &mut self,
        lhs_str: StackString,
        rhs_str: StackString,
        cmp: &Comparison,
        dst_reg: EbpfReg,
    ) -> Result<(), CompileError>;
    fn compile_return(&mut self, src: RegId) -> Result<(), CompileError>;
    fn compile_store_variable(&mut self, var_id: VarId, src: RegId) -> Result<(), CompileError>;
    fn compile_load_variable(&mut self, dst: RegId, var_id: VarId) -> Result<(), CompileError>;
    fn compile_not(&mut self, src_dst: RegId) -> Result<(), CompileError>;
}

impl IrOps for IrToEbpfCompiler<'_> {
    fn compile_load_literal(&mut self, dst: RegId, lit: &Literal) -> Result<(), CompileError> {
        // Invalidate all metadata for this register before writing a new value.
        // This prevents stale data from previous uses affecting compilation,
        // which was the root cause of nested loop bugs.
        self.invalidate_register(dst);

        let ebpf_dst = self.alloc_reg(dst)?;

        match lit {
            Literal::Int(val) => {
                // Track the literal value for commands that need compile-time constants
                self.set_literal_value(dst, *val);

                // Check if value fits in i32 immediate
                if *val >= i32::MIN as i64 && *val <= i32::MAX as i64 {
                    self.builder()
                        .push(EbpfInsn::mov64_imm(ebpf_dst, *val as i32));
                } else {
                    // For 64-bit values, we need LD_DW_IMM (two instruction slots)
                    self.emit_load_64bit_imm(ebpf_dst, *val);
                }
                Ok(())
            }
            Literal::Bool(b) => {
                self.builder()
                    .push(EbpfInsn::mov64_imm(ebpf_dst, if *b { 1 } else { 0 }));
                Ok(())
            }
            Literal::Nothing => {
                // Nothing is represented as 0
                // No need to clear metadata - invalidate_register() already did that
                self.builder().push(EbpfInsn::mov64_imm(ebpf_dst, 0));
                Ok(())
            }
            Literal::String(data_slice) => {
                // Get the string data from the IrBlock's data buffer
                // We need to copy the data to avoid borrow conflicts
                let string_bytes =
                    self.get_data_slice(data_slice.start as usize, data_slice.len as usize);
                let string_owned: Vec<u8> = string_bytes.to_vec();

                // Track the string value for field names in records
                if let Ok(s) = std::str::from_utf8(&string_owned) {
                    self.set_literal_string(dst, s.to_string());
                }

                // Store string on stack for proper comparison support
                // The register will hold a pointer to the stack location
                let stack_str = self.store_string_literal_on_stack(&string_owned, ebpf_dst)?;

                // Track the stack string for comparison operations
                self.set_stack_string(dst, stack_str);
                self.set_register_type(dst, BpfFieldType::String);

                Ok(())
            }
            Literal::Record { .. } => {
                // Create a RecordBuilder for this register
                // Records are built on the stack - we'll allocate space as fields are added
                // For now, just track the starting position
                let record_builder = RecordBuilder {
                    fields: Vec::new(),
                    base_offset: self.current_stack_offset(),
                };
                self.set_record_builder(dst, record_builder);
                // Records in eBPF are represented as 0 (a placeholder)
                self.builder().push(EbpfInsn::mov64_imm(ebpf_dst, 0));
                Ok(())
            }
            Literal::CellPath(cell_path) => {
                // Track the cell path for later use in FollowCellPath
                // Cell paths themselves don't need a register value - they're used
                // to guide field access compilation
                self.set_literal_cell_path(dst, (**cell_path).clone());
                // Set a dummy value in the register (won't be used)
                self.builder().push(EbpfInsn::mov64_imm(ebpf_dst, 0));
                Ok(())
            }
            Literal::Range {
                start,
                step,
                end,
                inclusion,
            } => {
                // For eBPF bounded loops, we need compile-time known bounds
                // Check if start, step, and end are all literal integers
                let start_val = self.get_literal_value(*start).ok_or_else(|| {
                    CompileError::UnsupportedInstruction(
                        "Range start must be a compile-time known integer for eBPF loops".into(),
                    )
                })?;
                // Step can be `nothing` (default step of 1) or an explicit integer
                // Nushell uses `nothing` when no step is specified (e.g., 1..10)
                let step_val = self.get_literal_value(*step).unwrap_or(1);
                let end_val = self.get_literal_value(*end).ok_or_else(|| {
                    CompileError::UnsupportedInstruction(
                        "Range end must be a compile-time known integer for eBPF loops".into(),
                    )
                })?;

                // Validate step is non-zero
                if step_val == 0 {
                    return Err(CompileError::UnsupportedInstruction(
                        "Range step cannot be zero".into(),
                    ));
                }

                // Allocate stack space for the current iterator value
                let stack_offset = self.alloc_stack(8)?;

                // Store initial value (start) on stack
                if start_val >= i32::MIN as i64 && start_val <= i32::MAX as i64 {
                    self.builder()
                        .push(EbpfInsn::mov64_imm(EbpfReg::R0, start_val as i32));
                } else {
                    self.emit_load_64bit_imm(EbpfReg::R0, start_val);
                }
                self.builder()
                    .push(EbpfInsn::stxdw(EbpfReg::R10, stack_offset, EbpfReg::R0));

                // Create bounded iterator info for use by Iterate instruction
                let iter = BoundedIterator {
                    current_offset: stack_offset,
                    end_value: end_val,
                    step: step_val,
                    inclusive: *inclusion == RangeInclusion::Inclusive,
                };
                self.set_bounded_iterator(dst, iter);

                // Set a placeholder value in the register (actual iteration happens in Iterate)
                self.builder().push(EbpfInsn::mov64_imm(ebpf_dst, 0));

                Ok(())
            }
            _ => Err(CompileError::UnsupportedLiteral),
        }
    }

    fn compile_move(&mut self, dst: RegId, src: RegId) -> Result<(), CompileError> {
        // Save src value to scratch register before allocating dst,
        // in case alloc_reg evicts the source register
        let ebpf_src = self.ensure_reg(src)?;
        self.builder()
            .push(EbpfInsn::mov64_reg(EbpfReg::R5, ebpf_src));

        let ebpf_dst = self.alloc_reg(dst)?;

        self.builder()
            .push(EbpfInsn::mov64_reg(ebpf_dst, EbpfReg::R5));
        Ok(())
    }

    fn compile_binary_op(
        &mut self,
        lhs_dst: RegId,
        op: &Operator,
        rhs: RegId,
    ) -> Result<(), CompileError> {
        // Check for string comparison before allocating registers
        // String comparisons need special handling since strings are on the stack
        if let Operator::Comparison(cmp) = op {
            let lhs_str = self.get_stack_string(lhs_dst);
            let rhs_str = self.get_stack_string(rhs);

            if lhs_str.is_some() || rhs_str.is_some() {
                // At least one operand is a stack string - use string comparison
                let lhs_str = lhs_str.unwrap_or_else(|| {
                    // RHS is a string but LHS is not - this is unusual but handle it
                    // by treating LHS as an 8-byte value (likely an error in the program)
                    StackString {
                        offset: 0,
                        size: 8,
                    }
                });
                let rhs_str = rhs_str.unwrap_or_else(|| {
                    // LHS is a string but RHS is not
                    StackString {
                        offset: 0,
                        size: 8,
                    }
                });

                // Allocate result register
                let ebpf_lhs = self.alloc_reg(lhs_dst)?;

                return self.compile_string_comparison(lhs_str, rhs_str, cmp, ebpf_lhs);
            }
        }

        let ebpf_lhs = self.ensure_reg(lhs_dst)?;
        let ebpf_rhs = self.ensure_reg(rhs)?;

        match op {
            // Math operations
            Operator::Math(math) => match math {
                Math::Add => {
                    self.builder().push(EbpfInsn::add64_reg(ebpf_lhs, ebpf_rhs));
                }
                Math::Subtract => {
                    self.builder().push(EbpfInsn::sub64_reg(ebpf_lhs, ebpf_rhs));
                }
                Math::Multiply => {
                    self.builder().push(EbpfInsn::mul64_reg(ebpf_lhs, ebpf_rhs));
                }
                Math::Divide | Math::FloorDivide => {
                    self.builder().push(EbpfInsn::div64_reg(ebpf_lhs, ebpf_rhs));
                }
                Math::Modulo => {
                    self.builder().push(EbpfInsn::mod64_reg(ebpf_lhs, ebpf_rhs));
                }
                _ => {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "Math operator {:?}",
                        math
                    )));
                }
            },
            // Bitwise operations
            Operator::Bits(bits) => match bits {
                Bits::BitOr => {
                    self.builder().push(EbpfInsn::or64_reg(ebpf_lhs, ebpf_rhs));
                }
                Bits::BitAnd => {
                    self.builder().push(EbpfInsn::and64_reg(ebpf_lhs, ebpf_rhs));
                }
                Bits::BitXor => {
                    self.builder().push(EbpfInsn::xor64_reg(ebpf_lhs, ebpf_rhs));
                }
                Bits::ShiftLeft => {
                    self.builder().push(EbpfInsn::lsh64_reg(ebpf_lhs, ebpf_rhs));
                }
                Bits::ShiftRight => {
                    self.builder().push(EbpfInsn::rsh64_reg(ebpf_lhs, ebpf_rhs));
                }
            },
            // Comparison operations - result is 0 or 1 (non-string comparisons)
            Operator::Comparison(cmp) => {
                self.compile_comparison(ebpf_lhs, cmp, ebpf_rhs)?;
            }
            // Boolean logical operations
            Operator::Boolean(bool_op) => {
                use nu_protocol::ast::Boolean;
                match bool_op {
                    Boolean::And => {
                        // Logical AND: result = lhs & rhs (works for boolean 0/1 values)
                        self.builder().push(EbpfInsn::and64_reg(ebpf_lhs, ebpf_rhs));
                    }
                    Boolean::Or => {
                        // Logical OR: result = lhs | rhs (works for boolean 0/1 values)
                        self.builder().push(EbpfInsn::or64_reg(ebpf_lhs, ebpf_rhs));
                    }
                    Boolean::Xor => {
                        // Logical XOR: result = lhs ^ rhs (works for boolean 0/1 values)
                        self.builder().push(EbpfInsn::xor64_reg(ebpf_lhs, ebpf_rhs));
                    }
                }
            }
            _ => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "Operator {:?}",
                    op
                )));
            }
        }

        Ok(())
    }

    fn compile_comparison(
        &mut self,
        lhs: EbpfReg,
        cmp: &Comparison,
        rhs: EbpfReg,
    ) -> Result<(), CompileError> {
        // Comparison in eBPF is done via conditional jumps
        // We emit: if (lhs cmp rhs) goto +1; r0 = 0; goto +1; r0 = 1
        // But we need to put result back in lhs register

        // Strategy:
        // 1. mov lhs, 1 (assume true)
        // 2. if (comparison fails) goto skip
        // 3. mov lhs, 0
        // skip:

        // First, save lhs value to a temp if needed and set lhs = 0
        let temp = EbpfReg::R0; // Use R0 as temp
        self.builder().push(EbpfInsn::mov64_reg(temp, lhs));
        self.builder().push(EbpfInsn::mov64_imm(lhs, 0)); // Assume false

        // Emit conditional jump based on comparison type
        // If condition is TRUE, skip the next instruction (which would keep lhs=0)
        // and fall through to setting lhs=1
        let jump_opcode = match cmp {
            Comparison::Equal => opcode::BPF_JMP | opcode::BPF_JEQ | opcode::BPF_X,
            Comparison::NotEqual => opcode::BPF_JMP | opcode::BPF_JNE | opcode::BPF_X,
            Comparison::LessThan => opcode::BPF_JMP | opcode::BPF_JLT | opcode::BPF_X,
            Comparison::LessThanOrEqual => opcode::BPF_JMP | opcode::BPF_JLE | opcode::BPF_X,
            Comparison::GreaterThan => opcode::BPF_JMP | opcode::BPF_JGT | opcode::BPF_X,
            Comparison::GreaterThanOrEqual => opcode::BPF_JMP | opcode::BPF_JGE | opcode::BPF_X,
            _ => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "Comparison {:?}",
                    cmp
                )));
            }
        };

        // Jump over the "goto skip" if condition is true
        // temp (original lhs) cmp rhs -> if true, skip 1 instruction
        self.builder().push(EbpfInsn::new(
            jump_opcode,
            temp.as_u8(),
            rhs.as_u8(),
            1, // Skip 1 instruction
            0,
        ));

        // If we get here, condition was false, skip setting to 1
        self.builder().push(EbpfInsn::new(
            opcode::BPF_JMP | opcode::BPF_JA,
            0,
            0,
            1, // Skip 1 instruction
            0,
        ));

        // Set lhs = 1 (condition was true)
        self.builder().push(EbpfInsn::mov64_imm(lhs, 1));

        Ok(())
    }

    /// Compare two stack-based strings byte-by-byte
    ///
    /// Compares strings 8 bytes at a time up to the shorter string's length.
    /// String literals include a null terminator in their size, so:
    /// - "nginx" (stored as "nginx\0", size=6) matches "nginx\0..." but NOT "nginxmaster"
    /// - The null terminator acts as an "end of string" marker in the comparison
    fn compile_string_comparison(
        &mut self,
        lhs_str: StackString,
        rhs_str: StackString,
        cmp: &Comparison,
        dst_reg: EbpfReg,
    ) -> Result<(), CompileError> {
        // Only Equal and NotEqual are supported for strings
        match cmp {
            Comparison::Equal | Comparison::NotEqual => {}
            _ => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "String comparison {:?} not supported (only == and != work)",
                    cmp
                )));
            }
        }

        // Determine comparison length - use the minimum of both sizes
        // This handles cases like comparing a 16-byte comm with a 5-byte literal "nginx"
        let compare_len = lhs_str.size.min(rhs_str.size);
        let num_chunks = (compare_len + 7) / 8; // Round up to 8-byte chunks

        // Strategy for Equal:
        //   Set result = 1 (assume equal)
        //   For each 8-byte chunk:
        //     Load LHS chunk into R0
        //     Load RHS chunk into R1
        //     If R0 != R1, set result = 0 and jump to end
        //   End: result is in dst_reg
        //
        // Strategy for NotEqual:
        //   Set result = 0 (assume equal, i.e., not-not-equal)
        //   For each 8-byte chunk:
        //     Load LHS chunk into R0
        //     Load RHS chunk into R1
        //     If R0 != R1, set result = 1 and jump to end
        //   End: result is in dst_reg

        let is_equal = matches!(cmp, Comparison::Equal);

        // Create label for the "not equal found" early exit
        let end_label = self.create_label();

        // Set initial assumption
        if is_equal {
            self.builder().push(EbpfInsn::mov64_imm(dst_reg, 1)); // Assume equal
        } else {
            self.builder().push(EbpfInsn::mov64_imm(dst_reg, 0)); // Assume equal (not != yet)
        }

        // Compare each 8-byte chunk
        for i in 0..num_chunks {
            let chunk_offset = (i * 8) as i16;
            let lhs_chunk_offset = lhs_str.offset + chunk_offset;
            let rhs_chunk_offset = rhs_str.offset + chunk_offset;

            // Load LHS chunk
            self.builder()
                .push(EbpfInsn::ldxdw(EbpfReg::R0, EbpfReg::R10, lhs_chunk_offset));

            // Load RHS chunk
            self.builder()
                .push(EbpfInsn::ldxdw(EbpfReg::R1, EbpfReg::R10, rhs_chunk_offset));

            // For the last chunk, we may need to mask off bytes beyond the comparison length
            let bytes_in_chunk = compare_len - (i * 8);
            if bytes_in_chunk < 8 {
                // Mask to only compare the relevant bytes
                // Create a mask with 1s in the positions we care about
                let mask: u64 = (1u64 << (bytes_in_chunk * 8)) - 1;
                let mask_i64 = mask as i64;

                // AND both with the mask
                self.emit_load_64bit_imm(EbpfReg::R2, mask_i64);
                self.builder()
                    .push(EbpfInsn::and64_reg(EbpfReg::R0, EbpfReg::R2));
                self.builder()
                    .push(EbpfInsn::and64_reg(EbpfReg::R1, EbpfReg::R2));
            }

            // Compare R0 and R1
            if is_equal {
                // For Equal: if not equal, set result to 0 and jump to end
                // jne r0, r1, +2 (skip the next 2 instructions if not equal)
                self.builder().push(EbpfInsn::new(
                    opcode::BPF_JMP | opcode::BPF_JNE | opcode::BPF_X,
                    EbpfReg::R0.as_u8(),
                    EbpfReg::R1.as_u8(),
                    2, // Skip 2 instructions
                    0,
                ));
                // Skip setting to 0 and jumping if equal (fall through to next chunk)
                self.builder().push(EbpfInsn::jump(2)); // Skip the set-to-0 and jump-to-end

                // Set result to 0 (not equal)
                self.builder().push(EbpfInsn::mov64_imm(dst_reg, 0));
                // Jump to end
                self.emit_jump_to_label(end_label);
            } else {
                // For NotEqual: if not equal, set result to 1 and jump to end
                self.builder().push(EbpfInsn::new(
                    opcode::BPF_JMP | opcode::BPF_JNE | opcode::BPF_X,
                    EbpfReg::R0.as_u8(),
                    EbpfReg::R1.as_u8(),
                    2, // Skip 2 instructions
                    0,
                ));
                // Skip setting to 1 and jumping if equal (fall through to next chunk)
                self.builder().push(EbpfInsn::jump(2)); // Skip the set-to-1 and jump-to-end

                // Set result to 1 (not equal)
                self.builder().push(EbpfInsn::mov64_imm(dst_reg, 1));
                // Jump to end
                self.emit_jump_to_label(end_label);
            }
        }

        // Bind the end label
        self.bind_label(end_label);

        Ok(())
    }

    fn compile_return(&mut self, src: RegId) -> Result<(), CompileError> {
        let ebpf_src = self.ensure_reg(src)?;

        // Move result to R0 (return register) if not already there
        if ebpf_src.as_u8() != EbpfReg::R0.as_u8() {
            self.builder()
                .push(EbpfInsn::mov64_reg(EbpfReg::R0, ebpf_src));
        }

        self.builder().push(EbpfInsn::exit());
        Ok(())
    }

    fn compile_store_variable(&mut self, var_id: VarId, src: RegId) -> Result<(), CompileError> {
        let ebpf_src = self.ensure_reg(src)?;

        // Store variables on the stack to avoid register allocation issues with loops
        // Get or allocate a stack slot for this variable
        let stack_offset = self.get_or_alloc_var_stack(var_id)?;

        // Store the value to the stack
        self.builder()
            .push(EbpfInsn::stxdw(EbpfReg::R10, stack_offset, ebpf_src));
        Ok(())
    }

    fn compile_load_variable(&mut self, dst: RegId, var_id: VarId) -> Result<(), CompileError> {
        // Check if this is loading the context parameter
        if self.is_context_param(var_id) {
            // Mark the destination register as containing the context
            // We don't emit any code here - actual BPF helpers are called
            // when fields are accessed via FollowCellPath
            self.set_context_register(dst, true);
            // Allocate the register but don't load anything yet
            let ebpf_dst = self.alloc_reg(dst)?;
            // Set a placeholder value (won't be used directly)
            self.builder().push(EbpfInsn::mov64_imm(ebpf_dst, 0));
            return Ok(());
        }

        // Check if this is a captured variable from outer scope
        // We can inline integer values as compile-time constants
        if let Some(value) = self.get_captured_value(var_id) {
            // Only 32-bit values are supported (covers PIDs, UIDs, etc.)
            if value < i32::MIN as i64 || value > i32::MAX as i64 {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "Captured value {} is too large. Only 32-bit integers are supported.",
                    value
                )));
            }

            let ebpf_dst = self.alloc_reg(dst)?;
            // Track the literal value for commands that need compile-time constants
            self.set_literal_value(dst, value);

            // Load the captured value as an immediate
            self.builder()
                .push(EbpfInsn::mov64_imm(ebpf_dst, value as i32));
            return Ok(());
        }

        // Load variable from stack
        // Get the stack slot for this variable
        let stack_offset = self.get_var_stack(var_id).ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "Variable ${} not found. Variables must be assigned before use.",
                var_id.get()
            ))
        })?;

        // Allocate destination register
        let ebpf_dst = self.alloc_reg(dst)?;

        // Load the value from the stack
        self.builder()
            .push(EbpfInsn::ldxdw(ebpf_dst, EbpfReg::R10, stack_offset));
        Ok(())
    }

    /// Compile logical NOT (flip boolean: 0 -> 1, non-zero -> 0)
    fn compile_not(&mut self, src_dst: RegId) -> Result<(), CompileError> {
        let ebpf_reg = self.ensure_reg(src_dst)?;

        // In Nushell, NOT is logical (boolean), not bitwise
        // We want: if reg == 0 then 1 else 0
        // Strategy:
        // 1. jeq reg, 0, +2  (if reg == 0, skip to setting 1)
        // 2. mov reg, 0      (reg was non-zero, set to 0)
        // 3. ja +1           (skip setting to 1)
        // 4. mov reg, 1      (reg was 0, set to 1)
        self.builder().push(EbpfInsn::jeq_imm(ebpf_reg, 0, 2));
        self.builder().push(EbpfInsn::mov64_imm(ebpf_reg, 0));
        self.builder().push(EbpfInsn::jump(1));
        self.builder().push(EbpfInsn::mov64_imm(ebpf_reg, 1));

        Ok(())
    }
}
