//! Nushell IR to MIR lowering
//!
//! This module converts Nushell's internal IR representation into MIR,
//! which is then lowered to eBPF bytecode by mir_to_ebpf.

use std::collections::HashMap;

use nu_protocol::ast::{CellPath, PathMember, Pattern};
use nu_protocol::engine::EngineState;
use nu_protocol::ir::{Instruction, IrBlock};
use nu_protocol::{DeclId, RegId, Value, VarId};

use super::elf::ProbeContext;
use super::mir::{
    BasicBlock, BinOpKind, BlockId, CtxField, MapKind, MapRef, MirFunction, MirInst, MirProgram,
    MirType, MirValue, RecordFieldDef, StackSlotId, StackSlotKind, VReg,
};
use super::CompileError;

/// Command types we recognize for eBPF
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BpfCommand {
    Emit,
    ReadStr,
    ReadKernelStr,
    Filter,
    Count,
    Histogram,
    StartTimer,
    StopTimer,
}

/// A field in a record being built
#[derive(Debug, Clone)]
struct RecordField {
    name: String,
    value_vreg: VReg,
    /// Stack offset where this field's value is stored (for safety)
    stack_offset: Option<i16>,
    ty: MirType,
}

/// Metadata tracked for each Nushell register during lowering
#[derive(Debug, Clone, Default)]
struct RegMetadata {
    /// Compile-time integer constant
    literal_int: Option<i64>,
    /// Compile-time string (for field names)
    literal_string: Option<String>,
    /// Whether this register holds the context parameter
    is_context: bool,
    /// Cell path for field access (like $ctx.pid)
    cell_path: Option<CellPath>,
    /// Stack slot for string storage
    string_slot: Option<StackSlotId>,
    /// Record fields being built
    record_fields: Vec<RecordField>,
}

/// Lowering context for IR to MIR conversion
pub struct IrToMirLowering<'a> {
    /// The MIR function being built
    func: MirFunction,
    /// Mapping from Nushell RegId to MIR VReg
    reg_map: HashMap<u32, VReg>,
    /// Metadata for each register
    reg_metadata: HashMap<u32, RegMetadata>,
    /// Current basic block being built
    current_block: BlockId,
    /// IR block for data access
    ir_block: Option<&'a IrBlock>,
    /// Probe context for field access
    probe_ctx: Option<&'a ProbeContext>,
    /// Engine state for looking up commands
    engine_state: Option<&'a EngineState>,
    /// Captured closure values to inline
    captures: &'a [(String, i64)],
    /// Context parameter variable ID (if any)
    ctx_param: Option<VarId>,
    /// Pipeline input register (for commands)
    pipeline_input: Option<VReg>,
    /// Pipeline input source RegId (for metadata lookup)
    pipeline_input_reg: Option<RegId>,
    /// Needs ringbuf map
    pub needs_ringbuf: bool,
    /// Needs counter map
    pub needs_counter_map: bool,
}

impl<'a> IrToMirLowering<'a> {
    /// Create a new lowering context
    pub fn new(
        ir_block: &'a IrBlock,
        probe_ctx: Option<&'a ProbeContext>,
        engine_state: Option<&'a EngineState>,
        captures: &'a [(String, i64)],
        ctx_param: Option<VarId>,
    ) -> Self {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        Self {
            func,
            reg_map: HashMap::new(),
            reg_metadata: HashMap::new(),
            current_block: entry,
            ir_block: Some(ir_block),
            probe_ctx,
            engine_state,
            captures,
            ctx_param,
            pipeline_input: None,
            pipeline_input_reg: None,
            needs_ringbuf: false,
            needs_counter_map: false,
        }
    }

    /// Get a slice of data from the IR block
    fn get_data_slice(&self, start: usize, len: usize) -> Option<&[u8]> {
        self.ir_block.map(|b| &b.data[start..start + len])
    }

    /// Get metadata for a register
    fn get_metadata(&self, reg: RegId) -> Option<&RegMetadata> {
        self.reg_metadata.get(&reg.get())
    }

    /// Get or create metadata for a register
    fn get_or_create_metadata(&mut self, reg: RegId) -> &mut RegMetadata {
        self.reg_metadata.entry(reg.get()).or_default()
    }

    /// Clear metadata for a register (when it's written to)
    fn clear_metadata(&mut self, reg: RegId) {
        self.reg_metadata.remove(&reg.get());
    }

    /// Check if a register holds the context value
    fn is_context_reg(&self, reg: RegId) -> bool {
        self.get_metadata(reg).map(|m| m.is_context).unwrap_or(false)
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
            // === Data Movement ===
            Instruction::LoadLiteral { dst, lit } => {
                self.lower_load_literal(*dst, lit)?;
            }

            Instruction::Move { dst, src } => {
                // Copy value and metadata
                let src_vreg = self.get_vreg(*src);
                let dst_vreg = self.get_vreg(*dst);
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::VReg(src_vreg),
                });
                // Copy metadata
                if let Some(meta) = self.get_metadata(*src).cloned() {
                    self.reg_metadata.insert(dst.get(), meta);
                }
            }

            Instruction::Clone { dst, src } => {
                // Same as Move for our purposes
                let src_vreg = self.get_vreg(*src);
                let dst_vreg = self.get_vreg(*dst);
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::VReg(src_vreg),
                });
                if let Some(meta) = self.get_metadata(*src).cloned() {
                    self.reg_metadata.insert(dst.get(), meta);
                }
            }

            // === Arithmetic ===
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

            // === Control Flow ===
            Instruction::BranchIf { cond, index } => {
                self.lower_branch_if(*cond, *index)?;
            }

            Instruction::Jump { index } => {
                let target = BlockId(*index as u32);
                self.terminate(MirInst::Jump { target });
            }

            Instruction::Match { pattern, src, index } => {
                // Match is used for short-circuit boolean evaluation
                self.lower_match(pattern, *src, *index)?;
            }

            Instruction::Return { src } => {
                let val = Some(MirValue::VReg(self.get_vreg(*src)));
                self.terminate(MirInst::Return { val });
            }

            // === Field Access ===
            Instruction::FollowCellPath { src_dst, path } => {
                self.lower_follow_cell_path(*src_dst, *path)?;
            }

            // === Commands ===
            Instruction::Call { decl_id, src_dst } => {
                self.lower_call(*decl_id, *src_dst)?;
            }

            Instruction::PushPositional { src } => {
                // Set up pipeline input for the next command
                let src_vreg = self.get_vreg(*src);
                self.pipeline_input = Some(src_vreg);
                self.pipeline_input_reg = Some(*src);
            }

            Instruction::AppendRest { src } => {
                // Same as PushPositional for our simple case
                let src_vreg = self.get_vreg(*src);
                self.pipeline_input = Some(src_vreg);
                self.pipeline_input_reg = Some(*src);
            }

            // === Records ===
            Instruction::RecordInsert { src_dst, key, val } => {
                self.lower_record_insert(*src_dst, *key, *val)?;
            }

            // === Variables ===
            Instruction::LoadVariable { dst, var_id } => {
                self.lower_load_variable(*dst, *var_id)?;
            }

            Instruction::StoreVariable { var_id, src } => {
                // Store variable - for now just track the vreg
                let _src_vreg = self.get_vreg(*src);
                let _ = var_id; // Would need a var_map to track this
            }

            Instruction::DropVariable { .. } => {
                // No-op in eBPF
            }

            // === No-ops ===
            Instruction::Span { .. } => {
                // Span tracking - no-op
            }

            Instruction::OnError { index } | Instruction::OnErrorInto { index, .. } => {
                // Error handling - we don't have try/catch in eBPF, record jump target
                let _ = index;
            }

            Instruction::PopErrorHandler => {
                // No-op
            }

            Instruction::RedirectOut { mode } | Instruction::RedirectErr { mode } => {
                // Redirection - no-op in eBPF, we don't have stdout/stderr
                let _ = mode;
            }

            // === Unsupported ===
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
                // Track literal value for constant propagation
                let meta = self.get_or_create_metadata(dst);
                meta.literal_int = Some(*val);
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
                // Get the string value first (before mutable borrow for metadata)
                let string_value = self
                    .get_data_slice(data_slice.start as usize, data_slice.len as usize)
                    .and_then(|bytes| std::str::from_utf8(bytes).ok())
                    .map(|s| s.to_string());
                // TODO: Store string bytes to slot
                // For now, just record slot ID in a vreg (placeholder)
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::StackSlot(slot),
                });
                // Track the string slot and value
                let meta = self.get_or_create_metadata(dst);
                meta.string_slot = Some(slot);
                // Also track the literal string value for record field names
                if let Some(s) = string_value {
                    meta.literal_string = Some(s);
                }
            }

            Literal::CellPath(cell_path) => {
                // Cell paths are metadata-only - they guide field access compilation
                // They don't need a runtime value
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::Const(0), // Dummy value
                });
                // Track the cell path for use in FollowCellPath
                let meta = self.get_or_create_metadata(dst);
                meta.cell_path = Some((**cell_path).clone());
            }

            Literal::Record { capacity: _ } => {
                // Record allocation - just track that this is a record
                // Actual fields are added via RecordInsert
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::Const(0), // Placeholder
                });
                // Initialize empty record fields in metadata
                let meta = self.get_or_create_metadata(dst);
                meta.record_fields = Vec::new();
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

    /// Lower Match instruction (used for short-circuit boolean evaluation)
    fn lower_match(
        &mut self,
        pattern: &Pattern,
        src: RegId,
        index: usize,
    ) -> Result<(), CompileError> {
        let src_vreg = self.get_vreg(src);
        let target_block = BlockId(index as u32);
        let continue_block = self.func.alloc_block();

        match pattern {
            Pattern::Value(value) => {
                // Branch if src matches the literal value
                if let Value::Bool { val, .. } = value {
                    // For `and`: match(false) - jump if src == 0
                    // For `or`: match(true) - jump if src != 0
                    if *val {
                        // Jump if src != 0 (true)
                        self.terminate(MirInst::Branch {
                            cond: src_vreg,
                            if_true: target_block,
                            if_false: continue_block,
                        });
                    } else {
                        // Jump if src == 0 (false) - need to negate
                        let tmp = self.func.alloc_vreg();
                        self.emit(MirInst::UnaryOp {
                            dst: tmp,
                            op: super::mir::UnaryOpKind::Not,
                            src: MirValue::VReg(src_vreg),
                        });
                        self.terminate(MirInst::Branch {
                            cond: tmp,
                            if_true: target_block,
                            if_false: continue_block,
                        });
                    }
                } else {
                    return Err(CompileError::UnsupportedInstruction(
                        "Match pattern must be boolean".into(),
                    ));
                }
            }
            _ => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "Match pattern {:?} not supported",
                    pattern
                )));
            }
        }

        self.current_block = continue_block;
        Ok(())
    }

    /// Lower FollowCellPath instruction (context field access like $ctx.pid)
    fn lower_follow_cell_path(
        &mut self,
        src_dst: RegId,
        path_reg: RegId,
    ) -> Result<(), CompileError> {
        // Check if this is a context field access
        if !self.is_context_reg(src_dst) {
            return Err(CompileError::UnsupportedInstruction(
                "FollowCellPath only supported on context parameter".into(),
            ));
        }

        // Get the cell path from the path register's metadata
        let path = self
            .get_metadata(path_reg)
            .and_then(|m| m.cell_path.clone())
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction("Cell path literal not found".into())
            })?;

        // Extract field name from path
        if path.members.len() != 1 {
            return Err(CompileError::UnsupportedInstruction(
                "Only single-level field access supported (e.g., $ctx.pid)".into(),
            ));
        }

        let field_name = match &path.members[0] {
            PathMember::String { val, .. } => val.clone(),
            PathMember::Int { val, .. } => {
                // For arg0, arg1, etc. represented as integers
                format!("arg{}", val)
            }
        };

        // Map field name to CtxField
        let ctx_field = match field_name.as_str() {
            "pid" => CtxField::Pid,
            "tid" => CtxField::Tid,
            "uid" => CtxField::Uid,
            "gid" => CtxField::Gid,
            "comm" => CtxField::Comm,
            "cpu" => CtxField::Cpu,
            "ktime" | "timestamp" => CtxField::Timestamp,
            "retval" => CtxField::RetVal,
            "kstack" => CtxField::KStack,
            "ustack" => CtxField::UStack,
            s if s.starts_with("arg") => {
                let num: u8 = s[3..].parse().map_err(|_| {
                    CompileError::UnsupportedInstruction(format!("Invalid arg: {}", s))
                })?;
                CtxField::Arg(num)
            }
            _ => CtxField::TracepointField(field_name),
        };

        let dst_vreg = self.get_vreg(src_dst);
        self.emit(MirInst::LoadCtxField {
            dst: dst_vreg,
            field: ctx_field,
        });

        // Clear context flag since result is now a value
        self.clear_metadata(src_dst);

        Ok(())
    }

    /// Lower Call instruction (emit, count, etc.)
    fn lower_call(&mut self, decl_id: DeclId, src_dst: RegId) -> Result<(), CompileError> {
        let cmd_name = self
            .engine_state
            .map(|es| es.get_decl(decl_id).name().to_string())
            .unwrap_or_else(|| format!("decl_{}", decl_id.get()));

        let dst_vreg = self.get_vreg(src_dst);

        match cmd_name.as_str() {
            "emit" => {
                self.needs_ringbuf = true;
                // Check if we're emitting a record - check both pipeline_input_reg and src_dst
                // (src_dst is used when record is piped directly: { ... } | emit)
                let record_fields = self
                    .pipeline_input_reg
                    .and_then(|reg| self.get_metadata(reg))
                    .map(|m| m.record_fields.clone())
                    .filter(|f| !f.is_empty())
                    .or_else(|| {
                        self.get_metadata(src_dst)
                            .map(|m| m.record_fields.clone())
                            .filter(|f| !f.is_empty())
                    })
                    .unwrap_or_default();

                if !record_fields.is_empty() {
                    // Emit a structured record
                    let fields: Vec<RecordFieldDef> = record_fields
                        .iter()
                        .map(|f| RecordFieldDef {
                            name: f.name.clone(),
                            value: f.value_vreg,
                            ty: f.ty.clone(),
                        })
                        .collect();
                    self.emit(MirInst::EmitRecord { fields });
                } else {
                    // Emit a single value
                    let data_vreg = self.pipeline_input.unwrap_or(dst_vreg);
                    self.emit(MirInst::EmitEvent {
                        data: data_vreg,
                        size: 8, // Default to 8 bytes
                    });
                }
                // Set result to 0
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::Const(0),
                });
            }

            "count" => {
                self.needs_counter_map = true;
                let key_vreg = self.pipeline_input.unwrap_or(dst_vreg);
                self.emit(MirInst::MapUpdate {
                    map: MapRef {
                        name: "counters".to_string(),
                        kind: MapKind::Hash,
                    },
                    key: key_vreg,
                    val: dst_vreg, // Will be handled specially in MIR->eBPF
                    flags: 0,
                });
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::Const(0),
                });
            }

            "filter" => {
                // Filter: if input is 0/false, exit early
                let input_vreg = self.pipeline_input.unwrap_or(dst_vreg);
                // Create exit block and continue block
                let exit_block = self.func.alloc_block();
                let continue_block = self.func.alloc_block();

                // Branch: if input is 0, exit
                let negated = self.func.alloc_vreg();
                self.emit(MirInst::UnaryOp {
                    dst: negated,
                    op: super::mir::UnaryOpKind::Not,
                    src: MirValue::VReg(input_vreg),
                });
                self.terminate(MirInst::Branch {
                    cond: negated,
                    if_true: exit_block,
                    if_false: continue_block,
                });

                // Exit block returns 0
                self.current_block = exit_block;
                self.terminate(MirInst::Return {
                    val: Some(MirValue::Const(0)),
                });

                // Continue in the continue block
                self.current_block = continue_block;
            }

            "read-str" => {
                let ptr_vreg = self.pipeline_input.unwrap_or(dst_vreg);
                let slot = self.func.alloc_stack_slot(128, 8, StackSlotKind::StringBuffer);
                self.emit(MirInst::ReadStr {
                    dst: slot,
                    ptr: ptr_vreg,
                    user_space: true,
                    max_len: 128,
                });
            }

            "read-kernel-str" => {
                let ptr_vreg = self.pipeline_input.unwrap_or(dst_vreg);
                let slot = self.func.alloc_stack_slot(128, 8, StackSlotKind::StringBuffer);
                self.emit(MirInst::ReadStr {
                    dst: slot,
                    ptr: ptr_vreg,
                    user_space: false,
                    max_len: 128,
                });
            }

            _ => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "Command '{}' not supported in eBPF",
                    cmd_name
                )));
            }
        }

        self.pipeline_input = None;
        self.pipeline_input_reg = None;
        Ok(())
    }

    /// Lower RecordInsert instruction
    fn lower_record_insert(
        &mut self,
        src_dst: RegId,
        key: RegId,
        val: RegId,
    ) -> Result<(), CompileError> {
        // Get field name from key register's metadata
        let field_name = self
            .get_metadata(key)
            .and_then(|m| m.literal_string.clone())
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction("Record key must be a literal string".into())
            })?;

        let val_vreg = self.get_vreg(val);

        // IMPORTANT: Create a fresh VReg and copy the value to preserve it.
        // The IR reuses registers, so val_vreg might be overwritten by subsequent operations.
        // By copying to a fresh VReg, we ensure the value is preserved until emit time.
        let preserved_vreg = self.func.alloc_vreg();
        self.emit(MirInst::Copy {
            dst: preserved_vreg,
            src: MirValue::VReg(val_vreg),
        });

        // Add field to the record being built (using preserved VReg)
        let field = RecordField {
            name: field_name,
            value_vreg: preserved_vreg,
            stack_offset: None,
            ty: MirType::I64, // Default, could be inferred
        };

        let meta = self.get_or_create_metadata(src_dst);
        meta.record_fields.push(field);

        Ok(())
    }

    /// Lower LoadVariable instruction
    fn lower_load_variable(
        &mut self,
        dst: RegId,
        var_id: nu_protocol::VarId,
    ) -> Result<(), CompileError> {
        // Check if this is the context parameter variable
        if let Some(ctx_var) = self.ctx_param {
            if var_id == ctx_var {
                let dst_vreg = self.get_vreg(dst);
                // Mark this register as holding the context
                let meta = self.get_or_create_metadata(dst);
                meta.is_context = true;
                // Emit a placeholder - actual context access happens in FollowCellPath
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::Const(0), // Placeholder
                });
                return Ok(());
            }
        }

        // Check if this is a captured variable
        for (name, value) in self.captures {
            // We'd need the variable name to match, but we only have var_id
            // For now, check if any capture matches by trying them all
            let _ = (name, value);
        }

        Err(CompileError::UnsupportedInstruction(format!(
            "Variable {} not found in captures",
            var_id.get()
        )))
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
    engine_state: Option<&EngineState>,
    captures: &[(String, i64)],
    ctx_param: Option<VarId>,
) -> Result<MirProgram, CompileError> {
    let mut lowering = IrToMirLowering::new(ir_block, probe_ctx, engine_state, captures, ctx_param);
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
