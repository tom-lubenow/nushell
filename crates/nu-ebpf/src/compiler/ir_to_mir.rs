//! Nushell IR to MIR lowering
//!
//! This module converts Nushell's internal IR representation into MIR,
//! which is then lowered to eBPF bytecode by mir_to_ebpf.

use std::collections::HashMap;

use nu_protocol::ir::{Instruction, IrBlock};
use nu_protocol::RegId;

use super::elf::ProbeContext;
use super::mir::{
    BasicBlock, BinOpKind, BlockId, MirFunction, MirInst, MirProgram, MirValue, StackSlotKind,
    VReg,
};
use super::CompileError;

/// Lowering context for IR to MIR conversion
pub struct IrToMirLowering<'a> {
    /// The MIR function being built
    func: MirFunction,
    /// Mapping from Nushell RegId to MIR VReg
    reg_map: HashMap<u32, VReg>,
    /// Current basic block being built
    current_block: BlockId,
    /// Probe context for field access
    probe_ctx: Option<&'a ProbeContext>,
    /// Captured closure values to inline
    captures: &'a [(String, i64)],
    /// Context parameter register (if any)
    ctx_param: Option<RegId>,
}

impl<'a> IrToMirLowering<'a> {
    /// Create a new lowering context
    pub fn new(
        probe_ctx: Option<&'a ProbeContext>,
        captures: &'a [(String, i64)],
        ctx_param: Option<RegId>,
    ) -> Self {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        Self {
            func,
            reg_map: HashMap::new(),
            current_block: entry,
            probe_ctx,
            captures,
            ctx_param,
        }
    }

    /// Get or create a VReg for a Nushell RegId
    fn get_vreg(&mut self, reg: RegId) -> VReg {
        let reg_id = reg.get();
        if let Some(&vreg) = self.reg_map.get(&reg_id) {
            vreg
        } else {
            let vreg = self.func.alloc_vreg();
            self.reg_map.insert(reg_id, vreg);
            vreg
        }
    }

    /// Get the current block being built
    fn current_block_mut(&mut self) -> &mut BasicBlock {
        self.func.block_mut(self.current_block)
    }

    /// Add an instruction to the current block
    fn emit(&mut self, inst: MirInst) {
        self.current_block_mut().instructions.push(inst);
    }

    /// Set the terminator for the current block
    fn terminate(&mut self, inst: MirInst) {
        self.func.block_mut(self.current_block).terminator = inst;
    }

    /// Lower an entire IR block to MIR
    pub fn lower_block(&mut self, ir_block: &IrBlock) -> Result<(), CompileError> {
        for (idx, instruction) in ir_block.instructions.iter().enumerate() {
            self.lower_instruction(instruction, idx)?;
        }
        Ok(())
    }

    /// Lower a single IR instruction to MIR
    fn lower_instruction(
        &mut self,
        instruction: &Instruction,
        _idx: usize,
    ) -> Result<(), CompileError> {
        match instruction {
            Instruction::LoadLiteral { dst, lit } => {
                self.lower_load_literal(*dst, lit)?;
            }

            Instruction::Move { dst, src } => {
                let src_vreg = self.get_vreg(*src);
                let dst_vreg = self.get_vreg(*dst);
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::VReg(src_vreg),
                });
            }

            Instruction::BinaryOp { lhs_dst, op, rhs } => {
                self.lower_binary_op(*lhs_dst, *op, *rhs)?;
            }

            Instruction::Not { src_dst } => {
                let vreg = self.get_vreg(*src_dst);
                self.emit(MirInst::UnaryOp {
                    dst: vreg,
                    op: super::mir::UnaryOpKind::Not,
                    src: MirValue::VReg(vreg),
                });
            }

            Instruction::BranchIf { cond, index } => {
                self.lower_branch_if(*cond, *index)?;
            }

            Instruction::Jump { index } => {
                // Create target block if needed (placeholder for now)
                let target = BlockId(*index as u32);
                self.terminate(MirInst::Jump { target });
            }

            Instruction::Return { src } => {
                let val = Some(MirValue::VReg(self.get_vreg(*src)));
                self.terminate(MirInst::Return { val });
            }

            // TODO: Implement remaining instructions
            _ => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{:?} (MIR lowering not yet implemented)",
                    instruction
                )));
            }
        }
        Ok(())
    }

    /// Lower LoadLiteral instruction
    fn lower_load_literal(
        &mut self,
        dst: RegId,
        lit: &nu_protocol::ir::Literal,
    ) -> Result<(), CompileError> {
        use nu_protocol::ir::Literal;

        let dst_vreg = self.get_vreg(dst);

        match lit {
            Literal::Int(val) => {
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::Const(*val),
                });
            }

            Literal::Bool(val) => {
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::Const(if *val { 1 } else { 0 }),
                });
            }

            Literal::String(data_slice) => {
                // Allocate stack slot for string
                let slot = self.func.alloc_stack_slot(
                    data_slice.len as usize + 1, // Include null terminator
                    8,
                    StackSlotKind::StringBuffer,
                );
                // TODO: Store string bytes to slot
                // For now, just record slot ID in a vreg (placeholder)
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::StackSlot(slot),
                });
            }

            _ => {
                return Err(CompileError::UnsupportedLiteral);
            }
        }
        Ok(())
    }

    /// Lower BinaryOp instruction
    fn lower_binary_op(
        &mut self,
        lhs_dst: RegId,
        op: nu_protocol::ast::Operator,
        rhs: RegId,
    ) -> Result<(), CompileError> {
        use nu_protocol::ast::{Comparison, Math, Operator};

        let lhs_vreg = self.get_vreg(lhs_dst);
        let rhs_vreg = self.get_vreg(rhs);

        let mir_op = match op {
            Operator::Math(Math::Add) => BinOpKind::Add,
            Operator::Math(Math::Subtract) => BinOpKind::Sub,
            Operator::Math(Math::Multiply) => BinOpKind::Mul,
            Operator::Math(Math::Divide) => BinOpKind::Div,
            Operator::Math(Math::Modulo) => BinOpKind::Mod,
            Operator::Comparison(Comparison::Equal) => BinOpKind::Eq,
            Operator::Comparison(Comparison::NotEqual) => BinOpKind::Ne,
            Operator::Comparison(Comparison::LessThan) => BinOpKind::Lt,
            Operator::Comparison(Comparison::LessThanOrEqual) => BinOpKind::Le,
            Operator::Comparison(Comparison::GreaterThan) => BinOpKind::Gt,
            Operator::Comparison(Comparison::GreaterThanOrEqual) => BinOpKind::Ge,
            Operator::Bits(nu_protocol::ast::Bits::BitAnd) => BinOpKind::And,
            Operator::Bits(nu_protocol::ast::Bits::BitOr) => BinOpKind::Or,
            Operator::Bits(nu_protocol::ast::Bits::BitXor) => BinOpKind::Xor,
            Operator::Bits(nu_protocol::ast::Bits::ShiftLeft) => BinOpKind::Shl,
            Operator::Bits(nu_protocol::ast::Bits::ShiftRight) => BinOpKind::Shr,
            _ => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "Operator {:?} not supported in eBPF",
                    op
                )));
            }
        };

        self.emit(MirInst::BinOp {
            dst: lhs_vreg,
            op: mir_op,
            lhs: MirValue::VReg(lhs_vreg),
            rhs: MirValue::VReg(rhs_vreg),
        });

        Ok(())
    }

    /// Lower BranchIf instruction
    fn lower_branch_if(&mut self, cond: RegId, then_branch: usize) -> Result<(), CompileError> {
        let cond_vreg = self.get_vreg(cond);

        // Create blocks for true and false branches
        let true_block = BlockId(then_branch as u32);
        let false_block = self.func.alloc_block();

        self.terminate(MirInst::Branch {
            cond: cond_vreg,
            if_true: true_block,
            if_false: false_block,
        });

        // Continue building in the false block
        self.current_block = false_block;

        Ok(())
    }

    /// Finish lowering and return the MIR program
    pub fn finish(self) -> MirProgram {
        MirProgram::new(self.func)
    }
}

/// Lower Nushell IR to MIR
///
/// This is the main entry point for the IR → MIR conversion.
pub fn lower_ir_to_mir(
    ir_block: &IrBlock,
    probe_ctx: Option<&ProbeContext>,
    captures: &[(String, i64)],
    ctx_param: Option<RegId>,
) -> Result<MirProgram, CompileError> {
    let mut lowering = IrToMirLowering::new(probe_ctx, captures, ctx_param);
    lowering.lower_block(ir_block)?;
    Ok(lowering.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mir_function_creation() {
        let mut func = MirFunction::new();
        let v0 = func.alloc_vreg();
        let v1 = func.alloc_vreg();

        assert_eq!(v0.0, 0);
        assert_eq!(v1.0, 1);
        assert_eq!(func.vreg_count, 2);
    }

    #[test]
    fn test_basic_block_creation() {
        let mut func = MirFunction::new();
        let b0 = func.alloc_block();
        let b1 = func.alloc_block();

        assert_eq!(b0.0, 0);
        assert_eq!(b1.0, 1);
        assert_eq!(func.blocks.len(), 2);
    }
}
