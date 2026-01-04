//! Type Inference for MIR
//!
//! Infers types for all virtual registers in a MIR function.
//! Types are internal to the compiler - users write idiomatic Nushell
//! and the compiler determines types from context.
//!
//! ## How It Works
//!
//! 1. Context fields have known types based on probe type
//! 2. Constants are typed as I64
//! 3. Operations propagate types (copy, binop, etc.)
//! 4. Type errors are reported in Nushell terms

use std::collections::HashMap;

use super::elf::{EbpfProgramType, ProbeContext};
use super::mir::{
    AddressSpace, BasicBlock, BinOpKind, CtxField, MirFunction, MirInst, MirType, MirValue,
    UnaryOpKind, VReg,
};

/// Type inference error
#[derive(Debug, Clone)]
pub struct TypeError {
    pub message: String,
    pub hint: Option<String>,
}

impl TypeError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            hint: None,
        }
    }

    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }
}

impl std::fmt::Display for TypeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)?;
        if let Some(hint) = &self.hint {
            write!(f, " (hint: {})", hint)?;
        }
        Ok(())
    }
}

impl std::error::Error for TypeError {}

/// Type inference pass for MIR
pub struct TypeInference {
    /// Inferred types for each virtual register
    vreg_types: HashMap<VReg, MirType>,
    /// Probe context for determining context field types
    probe_ctx: Option<ProbeContext>,
}

impl TypeInference {
    /// Create a new type inference pass
    pub fn new(probe_ctx: Option<ProbeContext>) -> Self {
        Self {
            vreg_types: HashMap::new(),
            probe_ctx,
        }
    }

    /// Run type inference on a MIR function
    ///
    /// Returns the type map on success, or a list of type errors.
    pub fn infer(&mut self, func: &MirFunction) -> Result<HashMap<VReg, MirType>, Vec<TypeError>> {
        let mut errors = Vec::new();

        // Process each block
        for block in &func.blocks {
            self.infer_block(block, &mut errors);
        }

        if errors.is_empty() {
            Ok(self.vreg_types.clone())
        } else {
            Err(errors)
        }
    }

    /// Infer types for a basic block
    fn infer_block(&mut self, block: &BasicBlock, errors: &mut Vec<TypeError>) {
        for inst in &block.instructions {
            if let Err(e) = self.infer_inst(inst) {
                errors.push(e);
            }
        }

        // Handle terminator
        if let Err(e) = self.infer_inst(&block.terminator) {
            errors.push(e);
        }
    }

    /// Infer type for a single instruction
    fn infer_inst(&mut self, inst: &MirInst) -> Result<(), TypeError> {
        match inst {
            MirInst::Copy { dst, src } => {
                let src_ty = self.value_type(src);
                self.set_type(*dst, src_ty);
            }

            MirInst::Load { dst, ty, .. } => {
                self.set_type(*dst, ty.clone());
            }

            MirInst::LoadSlot { dst, ty, .. } => {
                self.set_type(*dst, ty.clone());
            }

            MirInst::BinOp { dst, op, lhs, rhs } => {
                let lhs_ty = self.value_type(lhs);
                let rhs_ty = self.value_type(rhs);
                let result_ty = self.infer_binop(*op, &lhs_ty, &rhs_ty)?;
                self.set_type(*dst, result_ty);
            }

            MirInst::UnaryOp { dst, op, src } => {
                let src_ty = self.value_type(src);
                let result_ty = self.infer_unaryop(*op, &src_ty)?;
                self.set_type(*dst, result_ty);
            }

            MirInst::CallHelper { dst, .. } => {
                // Most BPF helpers return i64
                self.set_type(*dst, MirType::I64);
            }

            MirInst::MapLookup { dst, map, .. } => {
                // Map lookup returns pointer to value (or null)
                let val_ty = match &map.kind {
                    super::mir::MapKind::Hash | super::mir::MapKind::PerCpuHash => MirType::I64,
                    super::mir::MapKind::Array | super::mir::MapKind::PerCpuArray => MirType::I64,
                    _ => MirType::I64,
                };
                self.set_type(
                    *dst,
                    MirType::Ptr {
                        pointee: Box::new(val_ty),
                        address_space: AddressSpace::Map,
                    },
                );
            }

            MirInst::LoadCtxField { dst, field } => {
                let field_ty = self.ctx_field_type(field);
                self.set_type(*dst, field_ty);
            }

            MirInst::StrCmp { dst, .. } => {
                // String comparison returns bool (0 or 1)
                self.set_type(*dst, MirType::Bool);
            }

            MirInst::StopTimer { dst } => {
                // Timer returns elapsed nanoseconds (u64)
                self.set_type(*dst, MirType::U64);
            }

            MirInst::LoopHeader { counter, .. } => {
                // Loop counter is i64
                self.set_type(*counter, MirType::I64);
            }

            // Instructions that don't define a vreg
            MirInst::Store { .. }
            | MirInst::StoreSlot { .. }
            | MirInst::MapUpdate { .. }
            | MirInst::MapDelete { .. }
            | MirInst::Histogram { .. }
            | MirInst::StartTimer
            | MirInst::EmitEvent { .. }
            | MirInst::EmitRecord { .. }
            | MirInst::ReadStr { .. }
            | MirInst::RecordStore { .. }
            | MirInst::Jump { .. }
            | MirInst::Branch { .. }
            | MirInst::Return { .. }
            | MirInst::TailCall { .. }
            | MirInst::LoopBack { .. } => {}
        }

        Ok(())
    }

    /// Get the type of a MirValue
    fn value_type(&self, value: &MirValue) -> MirType {
        match value {
            MirValue::VReg(vreg) => self.get_type(*vreg).cloned().unwrap_or(MirType::Unknown),
            MirValue::Const(_) => MirType::I64,
            MirValue::StackSlot(_) => MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::Stack,
            },
        }
    }

    /// Get the type of a context field based on probe type
    fn ctx_field_type(&self, field: &CtxField) -> MirType {
        match field {
            // 32-bit integer fields
            CtxField::Pid | CtxField::Tid | CtxField::Uid | CtxField::Gid | CtxField::Cpu => {
                MirType::U32
            }

            // 64-bit fields
            CtxField::Timestamp => MirType::U64,

            // Function arguments (varies by probe type but we use i64)
            CtxField::Arg(_) => {
                // For uprobes, args might be pointers to user memory
                if self.is_userspace_probe() {
                    MirType::Ptr {
                        pointee: Box::new(MirType::U8),
                        address_space: AddressSpace::User,
                    }
                } else {
                    MirType::I64
                }
            }

            // Return value
            CtxField::RetVal => MirType::I64,

            // Stack trace IDs
            CtxField::KStack | CtxField::UStack => MirType::I64,

            // Process name (16-byte array)
            CtxField::Comm => MirType::Array {
                elem: Box::new(MirType::U8),
                len: 16,
            },

            // Tracepoint fields - type depends on the field name
            // For now, default to i64; could be enhanced with BTF later
            CtxField::TracepointField(_) => MirType::I64,
        }
    }

    /// Check if the current probe is a userspace probe
    fn is_userspace_probe(&self) -> bool {
        self.probe_ctx
            .as_ref()
            .map(|ctx| {
                matches!(
                    ctx.probe_type,
                    EbpfProgramType::Uprobe | EbpfProgramType::Uretprobe
                )
            })
            .unwrap_or(false)
    }

    /// Infer result type of a binary operation
    fn infer_binop(
        &self,
        op: BinOpKind,
        lhs: &MirType,
        rhs: &MirType,
    ) -> Result<MirType, TypeError> {
        // Comparison operators always return bool
        if matches!(
            op,
            BinOpKind::Eq
                | BinOpKind::Ne
                | BinOpKind::Lt
                | BinOpKind::Le
                | BinOpKind::Gt
                | BinOpKind::Ge
        ) {
            // Check that operands are compatible
            if !self.types_comparable(lhs, rhs) {
                return Err(TypeError::new(format!(
                    "Cannot compare {} with {}",
                    self.type_name(lhs),
                    self.type_name(rhs)
                ))
                .with_hint("comparison requires matching types"));
            }
            return Ok(MirType::Bool);
        }

        // Arithmetic operations
        match op {
            BinOpKind::Add | BinOpKind::Sub => {
                // Pointer arithmetic: ptr + int -> ptr
                if let MirType::Ptr { .. } = lhs {
                    if self.is_integer(rhs) {
                        return Ok(lhs.clone());
                    }
                }
                // Regular arithmetic
                self.promote_numeric(lhs, rhs)
            }

            BinOpKind::Mul | BinOpKind::Div | BinOpKind::Mod => {
                // Only integers
                if !self.is_integer(lhs) || !self.is_integer(rhs) {
                    return Err(TypeError::new(format!(
                        "Arithmetic operation requires integers, got {} and {}",
                        self.type_name(lhs),
                        self.type_name(rhs)
                    )));
                }
                self.promote_numeric(lhs, rhs)
            }

            BinOpKind::And | BinOpKind::Or | BinOpKind::Xor => {
                // Bitwise ops on integers
                if !self.is_integer(lhs) || !self.is_integer(rhs) {
                    return Err(TypeError::new(format!(
                        "Bitwise operation requires integers, got {} and {}",
                        self.type_name(lhs),
                        self.type_name(rhs)
                    )));
                }
                self.promote_numeric(lhs, rhs)
            }

            BinOpKind::Shl | BinOpKind::Shr => {
                // Shift: result type is lhs type
                if !self.is_integer(lhs) {
                    return Err(TypeError::new(format!(
                        "Shift operation requires integer, got {}",
                        self.type_name(lhs)
                    )));
                }
                Ok(lhs.clone())
            }

            _ => Ok(MirType::I64), // Fallback
        }
    }

    /// Infer result type of a unary operation
    fn infer_unaryop(&self, op: UnaryOpKind, src: &MirType) -> Result<MirType, TypeError> {
        match op {
            UnaryOpKind::Not => {
                // Logical not: any value -> bool
                Ok(MirType::Bool)
            }
            UnaryOpKind::BitNot | UnaryOpKind::Neg => {
                // Bitwise/arithmetic negation preserves type
                if !self.is_integer(src) {
                    return Err(TypeError::new(format!(
                        "Negation requires integer, got {}",
                        self.type_name(src)
                    )));
                }
                Ok(src.clone())
            }
        }
    }

    /// Check if two types can be compared
    fn types_comparable(&self, lhs: &MirType, rhs: &MirType) -> bool {
        // Same types are always comparable
        if lhs == rhs {
            return true;
        }

        // All integer types are comparable
        if self.is_integer(lhs) && self.is_integer(rhs) {
            return true;
        }

        // Pointers can be compared (for null checks)
        if matches!(lhs, MirType::Ptr { .. }) && matches!(rhs, MirType::Ptr { .. }) {
            return true;
        }

        // Pointer can be compared with integer (for null check: ptr == 0)
        if matches!(lhs, MirType::Ptr { .. }) && self.is_integer(rhs) {
            return true;
        }
        if self.is_integer(lhs) && matches!(rhs, MirType::Ptr { .. }) {
            return true;
        }

        // Unknown type is comparable with anything
        if matches!(lhs, MirType::Unknown) || matches!(rhs, MirType::Unknown) {
            return true;
        }

        false
    }

    /// Check if a type is an integer
    fn is_integer(&self, ty: &MirType) -> bool {
        matches!(
            ty,
            MirType::I8
                | MirType::I16
                | MirType::I32
                | MirType::I64
                | MirType::U8
                | MirType::U16
                | MirType::U32
                | MirType::U64
                | MirType::Bool
                | MirType::Unknown
        )
    }

    /// Promote two numeric types to a common type
    fn promote_numeric(&self, lhs: &MirType, rhs: &MirType) -> Result<MirType, TypeError> {
        // If either is unknown, result is I64
        if matches!(lhs, MirType::Unknown) || matches!(rhs, MirType::Unknown) {
            return Ok(MirType::I64);
        }

        // Use the larger type
        let lhs_size = lhs.size();
        let rhs_size = rhs.size();

        // Prefer signed if either is signed
        let is_signed = matches!(lhs, MirType::I8 | MirType::I16 | MirType::I32 | MirType::I64)
            || matches!(rhs, MirType::I8 | MirType::I16 | MirType::I32 | MirType::I64);

        let size = lhs_size.max(rhs_size);

        Ok(if is_signed {
            match size {
                1 => MirType::I8,
                2 => MirType::I16,
                4 => MirType::I32,
                _ => MirType::I64,
            }
        } else {
            match size {
                1 => MirType::U8,
                2 => MirType::U16,
                4 => MirType::U32,
                _ => MirType::U64,
            }
        })
    }

    /// Get a human-readable name for a type (in Nu terms)
    fn type_name(&self, ty: &MirType) -> &'static str {
        match ty {
            MirType::I8 | MirType::I16 | MirType::I32 | MirType::I64 => "integer",
            MirType::U8 | MirType::U16 | MirType::U32 | MirType::U64 => "integer",
            MirType::Bool => "boolean",
            MirType::Ptr { .. } => "pointer",
            MirType::Array { elem, .. } if matches!(**elem, MirType::U8) => "string",
            MirType::Array { .. } => "array",
            MirType::Struct { .. } => "record",
            MirType::MapRef { .. } => "map",
            MirType::Unknown => "unknown",
        }
    }

    /// Set the type for a vreg
    fn set_type(&mut self, vreg: VReg, ty: MirType) {
        self.vreg_types.insert(vreg, ty);
    }

    /// Get the type for a vreg
    pub fn get_type(&self, vreg: VReg) -> Option<&MirType> {
        self.vreg_types.get(&vreg)
    }

    /// Get the full type map
    pub fn types(&self) -> &HashMap<VReg, MirType> {
        &self.vreg_types
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler::mir::{BasicBlock, BlockId, MirFunction, StackSlotId};

    fn make_test_function() -> MirFunction {
        let mut func = MirFunction::new();
        let bb0 = func.alloc_block();
        func.entry = bb0;
        func
    }

    #[test]
    fn test_infer_constant() {
        let mut func = make_test_function();
        let v0 = func.alloc_vreg();

        func.block_mut(BlockId(0)).instructions.push(MirInst::Copy {
            dst: v0,
            src: MirValue::Const(42),
        });
        func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

        let mut ti = TypeInference::new(None);
        let types = ti.infer(&func).unwrap();

        assert_eq!(types.get(&v0), Some(&MirType::I64));
    }

    #[test]
    fn test_infer_ctx_pid() {
        let mut func = make_test_function();
        let v0 = func.alloc_vreg();

        func.block_mut(BlockId(0))
            .instructions
            .push(MirInst::LoadCtxField {
                dst: v0,
                field: CtxField::Pid,
            });
        func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

        let mut ti = TypeInference::new(None);
        let types = ti.infer(&func).unwrap();

        assert_eq!(types.get(&v0), Some(&MirType::U32));
    }

    #[test]
    fn test_infer_ctx_comm() {
        let mut func = make_test_function();
        let v0 = func.alloc_vreg();

        func.block_mut(BlockId(0))
            .instructions
            .push(MirInst::LoadCtxField {
                dst: v0,
                field: CtxField::Comm,
            });
        func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

        let mut ti = TypeInference::new(None);
        let types = ti.infer(&func).unwrap();

        assert_eq!(
            types.get(&v0),
            Some(&MirType::Array {
                elem: Box::new(MirType::U8),
                len: 16
            })
        );
    }

    #[test]
    fn test_infer_binop_add() {
        let mut func = make_test_function();
        let v0 = func.alloc_vreg();
        let v1 = func.alloc_vreg();
        let v2 = func.alloc_vreg();

        let block = func.block_mut(BlockId(0));
        block.instructions.push(MirInst::Copy {
            dst: v0,
            src: MirValue::Const(10),
        });
        block.instructions.push(MirInst::Copy {
            dst: v1,
            src: MirValue::Const(20),
        });
        block.instructions.push(MirInst::BinOp {
            dst: v2,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(v0),
            rhs: MirValue::VReg(v1),
        });
        block.terminator = MirInst::Return { val: None };

        let mut ti = TypeInference::new(None);
        let types = ti.infer(&func).unwrap();

        assert_eq!(types.get(&v2), Some(&MirType::I64));
    }

    #[test]
    fn test_infer_comparison() {
        let mut func = make_test_function();
        let v0 = func.alloc_vreg();
        let v1 = func.alloc_vreg();

        let block = func.block_mut(BlockId(0));
        block.instructions.push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::Pid,
        });
        block.instructions.push(MirInst::BinOp {
            dst: v1,
            op: BinOpKind::Eq,
            lhs: MirValue::VReg(v0),
            rhs: MirValue::Const(1234),
        });
        block.terminator = MirInst::Return { val: None };

        let mut ti = TypeInference::new(None);
        let types = ti.infer(&func).unwrap();

        // Comparison result is bool
        assert_eq!(types.get(&v1), Some(&MirType::Bool));
    }

    #[test]
    fn test_infer_uprobe_arg_is_user_ptr() {
        let mut func = make_test_function();
        let v0 = func.alloc_vreg();

        func.block_mut(BlockId(0))
            .instructions
            .push(MirInst::LoadCtxField {
                dst: v0,
                field: CtxField::Arg(0),
            });
        func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

        let ctx = ProbeContext::new(EbpfProgramType::Uprobe, "test");
        let mut ti = TypeInference::new(Some(ctx));
        let types = ti.infer(&func).unwrap();

        // For uprobe, arg is a user pointer
        match types.get(&v0) {
            Some(MirType::Ptr { address_space, .. }) => {
                assert_eq!(*address_space, AddressSpace::User);
            }
            other => panic!("Expected user pointer, got {:?}", other),
        }
    }

    #[test]
    fn test_infer_kprobe_arg_is_int() {
        let mut func = make_test_function();
        let v0 = func.alloc_vreg();

        func.block_mut(BlockId(0))
            .instructions
            .push(MirInst::LoadCtxField {
                dst: v0,
                field: CtxField::Arg(0),
            });
        func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

        let ctx = ProbeContext::new(EbpfProgramType::Kprobe, "test");
        let mut ti = TypeInference::new(Some(ctx));
        let types = ti.infer(&func).unwrap();

        // For kprobe, arg is i64
        assert_eq!(types.get(&v0), Some(&MirType::I64));
    }

    #[test]
    fn test_infer_map_lookup_returns_ptr() {
        use crate::compiler::mir::{MapKind, MapRef};

        let mut func = make_test_function();
        let v0 = func.alloc_vreg();
        let v1 = func.alloc_vreg();

        let block = func.block_mut(BlockId(0));
        block.instructions.push(MirInst::Copy {
            dst: v0,
            src: MirValue::Const(123),
        });
        block.instructions.push(MirInst::MapLookup {
            dst: v1,
            map: MapRef {
                name: "test_map".to_string(),
                kind: MapKind::Hash,
            },
            key: v0,
        });
        block.terminator = MirInst::Return { val: None };

        let mut ti = TypeInference::new(None);
        let types = ti.infer(&func).unwrap();

        match types.get(&v1) {
            Some(MirType::Ptr { address_space, .. }) => {
                assert_eq!(*address_space, AddressSpace::Map);
            }
            other => panic!("Expected map pointer, got {:?}", other),
        }
    }

    #[test]
    fn test_copy_propagates_type() {
        let mut func = make_test_function();
        let v0 = func.alloc_vreg();
        let v1 = func.alloc_vreg();

        let block = func.block_mut(BlockId(0));
        block.instructions.push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::Timestamp,
        });
        block.instructions.push(MirInst::Copy {
            dst: v1,
            src: MirValue::VReg(v0),
        });
        block.terminator = MirInst::Return { val: None };

        let mut ti = TypeInference::new(None);
        let types = ti.infer(&func).unwrap();

        // Both should be U64 (timestamp type)
        assert_eq!(types.get(&v0), Some(&MirType::U64));
        assert_eq!(types.get(&v1), Some(&MirType::U64));
    }
}
