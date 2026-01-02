//! IR operation compilation
//!
//! Handles compilation of Nushell IR instructions to eBPF bytecode:
//! - Literals (int, bool, string, record)
//! - Moves and clones
//! - Binary operations (math, bitwise, comparison)
//! - Variable load/store
//! - Logical NOT

use nu_protocol::ast::{Bits, Comparison, Math, Operator};
use nu_protocol::ir::Literal;
use nu_protocol::{RegId, VarId};

use crate::compiler::elf::BpfFieldType;
use crate::compiler::instruction::{opcode, EbpfInsn, EbpfReg};
use crate::compiler::ir_to_ebpf::{IrToEbpfCompiler, RecordBuilder};
use crate::compiler::CompileError;

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
    fn compile_return(&mut self, src: RegId) -> Result<(), CompileError>;
    fn compile_store_variable(&mut self, var_id: VarId, src: RegId) -> Result<(), CompileError>;
    fn compile_load_variable(&mut self, dst: RegId, var_id: VarId) -> Result<(), CompileError>;
    fn compile_not(&mut self, src_dst: RegId) -> Result<(), CompileError>;
}

impl IrOps for IrToEbpfCompiler<'_> {
    fn compile_load_literal(&mut self, dst: RegId, lit: &Literal) -> Result<(), CompileError> {
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
                self.builder().push(EbpfInsn::mov64_imm(ebpf_dst, 0));
                Ok(())
            }
            Literal::String(data_slice) => {
                // Get the string data from the IrBlock's data buffer
                // We need to copy the data to avoid borrow conflicts
                let string_bytes = self.get_data_slice(data_slice.start as usize, data_slice.len as usize);
                let string_owned: Vec<u8> = string_bytes.to_vec();

                // Track the string value for field names in records
                if let Ok(s) = std::str::from_utf8(&string_owned) {
                    self.set_literal_string(dst, s.to_string());
                }

                // Convert first 8 bytes of string to i64 for comparison
                // This matches how bpf-comm encodes process names
                let mut arr = [0u8; 8];
                let len = string_owned.len().min(8);
                arr[..len].copy_from_slice(&string_owned[..len]);
                let val = i64::from_le_bytes(arr);
                self.emit_load_64bit_imm(ebpf_dst, val);
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
            _ => Err(CompileError::UnsupportedLiteral),
        }
    }

    fn compile_move(&mut self, dst: RegId, src: RegId) -> Result<(), CompileError> {
        let ebpf_src = self.ensure_reg(src)?;
        let ebpf_dst = self.alloc_reg(dst)?;

        if ebpf_src.as_u8() != ebpf_dst.as_u8() {
            self.builder().push(EbpfInsn::mov64_reg(ebpf_dst, ebpf_src));
        }
        Ok(())
    }

    fn compile_binary_op(
        &mut self,
        lhs_dst: RegId,
        op: &Operator,
        rhs: RegId,
    ) -> Result<(), CompileError> {
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
            // Comparison operations - result is 0 or 1
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
        let ebpf_var = self.alloc_var(var_id)?;

        // Copy the value to the variable's register
        if ebpf_src.as_u8() != ebpf_var.as_u8() {
            self.builder().push(EbpfInsn::mov64_reg(ebpf_var, ebpf_src));
        }
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

        let ebpf_var = self.ensure_var(var_id)?;
        let ebpf_dst = self.alloc_reg(dst)?;

        // Copy from variable's register to destination
        if ebpf_var.as_u8() != ebpf_dst.as_u8() {
            self.builder().push(EbpfInsn::mov64_reg(ebpf_dst, ebpf_var));
        }
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
