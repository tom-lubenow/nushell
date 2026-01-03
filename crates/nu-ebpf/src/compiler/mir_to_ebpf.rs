//! MIR to eBPF bytecode lowering
//!
//! This module converts MIR (Mid-Level IR) to eBPF bytecode.
//! It handles:
//! - Virtual register allocation to physical registers
//! - Stack layout and spilling
//! - Control flow (basic block linearization, jump resolution)
//! - BPF helper calls and map operations
//!
//! ## Pipeline
//!
//! 1. Build CFG from MIR
//! 2. Compute liveness information
//! 3. Layout stack slots
//! 4. Compile blocks in reverse post-order
//! 5. Fix up jumps and emit bytecode

use std::collections::HashMap;

use crate::compiler::cfg::{CFG, LivenessInfo};
use crate::compiler::elf::{BpfMapDef, EbpfMap, EventSchema, MapRelocation, ProbeContext};
use crate::compiler::instruction::{opcode, BpfHelper, EbpfInsn, EbpfReg};
use crate::compiler::ir_to_ebpf::pt_regs_offsets;
use crate::compiler::elf::{BpfFieldType, SchemaField};
use crate::compiler::mir::{
    BasicBlock, BinOpKind, BlockId, CtxField, MirFunction, MirInst, MirProgram, MirType, MirValue,
    RecordFieldDef, StackSlotId, StackSlotKind, UnaryOpKind, VReg,
};
use crate::compiler::regalloc::{LinearScanAllocator, RegAllocResult};
use crate::compiler::CompileError;

/// Ring buffer map name
pub const RINGBUF_MAP_NAME: &str = "events";
/// Counter map name
pub const COUNTER_MAP_NAME: &str = "counters";
/// Histogram map name
pub const HISTOGRAM_MAP_NAME: &str = "histogram";
/// Timestamp map name (for timing)
pub const TIMESTAMP_MAP_NAME: &str = "timestamps";

/// Result of MIR to eBPF compilation
pub struct MirCompileResult {
    /// The compiled bytecode
    pub bytecode: Vec<u8>,
    /// Maps needed by the program
    pub maps: Vec<EbpfMap>,
    /// Relocations for map references
    pub relocations: Vec<MapRelocation>,
    /// Optional schema for structured events
    pub event_schema: Option<EventSchema>,
}

/// MIR to eBPF compiler
pub struct MirToEbpfCompiler<'a> {
    /// MIR program to compile
    mir: &'a MirProgram,
    /// Probe context for field offsets
    probe_ctx: Option<&'a ProbeContext>,
    /// eBPF instructions
    instructions: Vec<EbpfInsn>,
    /// Virtual register to physical register mapping
    vreg_to_phys: HashMap<VReg, EbpfReg>,
    /// Virtual registers spilled to stack
    vreg_spills: HashMap<VReg, i16>,
    /// Stack slot offsets
    slot_offsets: HashMap<StackSlotId, i16>,
    /// Current stack offset (grows downward from R10)
    stack_offset: i16,
    /// Block start offsets (instruction index)
    block_offsets: HashMap<BlockId, usize>,
    /// Pending jump fixups (instruction index -> target block)
    pending_jumps: Vec<(usize, BlockId)>,
    /// Map relocations
    relocations: Vec<MapRelocation>,
    /// Needs ring buffer map
    needs_ringbuf: bool,
    /// Needs counter map
    needs_counter_map: bool,
    /// Needs histogram map
    needs_histogram_map: bool,
    /// Needs timestamp map
    needs_timestamp_map: bool,
    /// Event schema for structured output
    event_schema: Option<EventSchema>,
    /// Available physical registers for allocation
    available_regs: Vec<EbpfReg>,
    /// Next LRU register index
    next_lru: usize,
}

impl<'a> MirToEbpfCompiler<'a> {
    /// Create a new compiler
    pub fn new(mir: &'a MirProgram, probe_ctx: Option<&'a ProbeContext>) -> Self {
        Self {
            mir,
            probe_ctx,
            instructions: Vec::new(),
            vreg_to_phys: HashMap::new(),
            vreg_spills: HashMap::new(),
            slot_offsets: HashMap::new(),
            stack_offset: 0,
            block_offsets: HashMap::new(),
            pending_jumps: Vec::new(),
            relocations: Vec::new(),
            needs_ringbuf: false,
            needs_counter_map: false,
            needs_histogram_map: false,
            needs_timestamp_map: false,
            event_schema: None,
            // R6-R8 are callee-saved and available for our use
            available_regs: vec![EbpfReg::R6, EbpfReg::R7, EbpfReg::R8],
            next_lru: 0,
        }
    }

    /// Compile the MIR program to eBPF
    pub fn compile(mut self) -> Result<MirCompileResult, CompileError> {
        // Lay out stack slots first
        self.layout_stack()?;

        // Compile all basic blocks
        let main_func = self.mir.main.clone();
        self.compile_function(&main_func)?;

        // Fix up jumps
        self.fixup_jumps()?;

        // Build bytecode from instructions
        let mut bytecode = Vec::with_capacity(self.instructions.len() * 8);
        for insn in &self.instructions {
            bytecode.extend_from_slice(&insn.encode());
        }

        // Build maps
        let mut maps = Vec::new();
        if self.needs_ringbuf {
            maps.push(EbpfMap {
                name: RINGBUF_MAP_NAME.to_string(),
                def: BpfMapDef::ring_buffer(256 * 1024),
            });
        }
        if self.needs_counter_map {
            maps.push(EbpfMap {
                name: COUNTER_MAP_NAME.to_string(),
                def: BpfMapDef::counter_hash(),
            });
        }
        if self.needs_histogram_map {
            maps.push(EbpfMap {
                name: HISTOGRAM_MAP_NAME.to_string(),
                def: BpfMapDef::counter_hash(), // Same structure as counter: key=bucket, value=count
            });
        }
        if self.needs_timestamp_map {
            maps.push(EbpfMap {
                name: TIMESTAMP_MAP_NAME.to_string(),
                def: BpfMapDef::counter_hash(), // key=tid, value=timestamp
            });
        }

        Ok(MirCompileResult {
            bytecode,
            maps,
            relocations: self.relocations,
            event_schema: self.event_schema,
        })
    }

    /// Layout stack slots and assign offsets
    fn layout_stack(&mut self) -> Result<(), CompileError> {
        let func = &self.mir.main;

        // Sort slots by alignment (largest first) for better packing
        let mut slots: Vec<_> = func.stack_slots.iter().collect();
        slots.sort_by(|a, b| b.align.cmp(&a.align).then(b.size.cmp(&a.size)));

        for slot in slots {
            // Align the offset
            let aligned_size = ((slot.size + slot.align - 1) / slot.align) * slot.align;
            self.stack_offset -= aligned_size as i16;

            // Check for stack overflow
            if self.stack_offset < -512 {
                return Err(CompileError::StackOverflow);
            }

            self.slot_offsets.insert(slot.id, self.stack_offset);
        }

        Ok(())
    }

    /// Compile a MIR function
    fn compile_function(&mut self, func: &MirFunction) -> Result<(), CompileError> {
        // Build CFG and compute analysis information
        let cfg = CFG::build(func);
        let liveness = LivenessInfo::compute(func, &cfg);

        // Run linear scan register allocation
        let mut allocator = LinearScanAllocator::new(self.available_regs.clone());
        let alloc_result = allocator.allocate(func, &cfg, &liveness);

        // Pre-populate vreg assignments from linear scan
        self.apply_register_allocation(&alloc_result)?;

        // Use reverse post-order for block layout
        // This ensures that:
        // 1. Dominators appear before dominated blocks
        // 2. Loop headers appear before loop bodies
        // 3. Better cache locality for typical execution paths
        let block_order: Vec<BlockId> = if cfg.rpo.is_empty() {
            // Fallback to simple ordering if CFG is empty
            func.blocks.iter().map(|b| b.id).collect()
        } else {
            cfg.rpo.clone()
        };

        // Compile each block in CFG order
        for block_id in block_order {
            // Skip unreachable blocks
            if !cfg.reachable_blocks().contains(&block_id) {
                continue;
            }
            let block = func.block(block_id).clone();
            self.compile_block(&block)?;
        }

        Ok(())
    }

    /// Apply register allocation results from linear scan
    fn apply_register_allocation(&mut self, result: &RegAllocResult) -> Result<(), CompileError> {
        // Pre-populate register assignments
        for (&vreg, &phys) in &result.assignments {
            self.vreg_to_phys.insert(vreg, phys);
        }

        // Allocate spill slots for spilled vregs
        for (&vreg, &slot) in &result.spills {
            // Allocate stack space for spill slot
            self.check_stack_space(8)?;
            self.stack_offset -= 8;
            self.vreg_spills.insert(vreg, self.stack_offset);
            // Map the slot ID to our stack offset (for later reference)
            self.slot_offsets.insert(slot, self.stack_offset);
        }

        Ok(())
    }

    /// Compile a basic block
    fn compile_block(&mut self, block: &BasicBlock) -> Result<(), CompileError> {
        // Record block start offset
        self.block_offsets.insert(block.id, self.instructions.len());

        // Compile instructions
        for inst in &block.instructions {
            self.compile_instruction(inst)?;
        }

        // Compile terminator
        self.compile_instruction(&block.terminator)?;

        Ok(())
    }

    /// Compile a single MIR instruction
    fn compile_instruction(&mut self, inst: &MirInst) -> Result<(), CompileError> {
        match inst {
            MirInst::Copy { dst, src } => {
                let dst_reg = self.alloc_reg(*dst)?;
                match src {
                    MirValue::VReg(v) => {
                        let src_reg = self.ensure_reg(*v)?;
                        if dst_reg != src_reg {
                            self.instructions.push(EbpfInsn::mov64_reg(dst_reg, src_reg));
                        }
                    }
                    MirValue::Const(c) => {
                        if *c >= i32::MIN as i64 && *c <= i32::MAX as i64 {
                            self.instructions
                                .push(EbpfInsn::mov64_imm(dst_reg, *c as i32));
                        } else {
                            // Large constant - split into two parts
                            let low = *c as i32;
                            let high = (*c >> 32) as i32;
                            self.instructions.push(EbpfInsn::mov64_imm(dst_reg, low));
                            if high != 0 {
                                self.instructions.push(EbpfInsn::mov64_imm(EbpfReg::R0, high));
                                self.instructions.push(EbpfInsn::lsh64_imm(EbpfReg::R0, 32));
                                self.instructions
                                    .push(EbpfInsn::or64_reg(dst_reg, EbpfReg::R0));
                            }
                        }
                    }
                    MirValue::StackSlot(slot) => {
                        let offset = self.slot_offsets.get(slot).copied().unwrap_or(0);
                        self.instructions
                            .push(EbpfInsn::mov64_reg(dst_reg, EbpfReg::R10));
                        self.instructions
                            .push(EbpfInsn::add64_imm(dst_reg, offset as i32));
                    }
                }
            }

            MirInst::BinOp { dst, op, lhs, rhs } => {
                let dst_reg = self.alloc_reg(*dst)?;

                // Load LHS into dst
                match lhs {
                    MirValue::VReg(v) => {
                        let src = self.ensure_reg(*v)?;
                        if dst_reg != src {
                            self.instructions.push(EbpfInsn::mov64_reg(dst_reg, src));
                        }
                    }
                    MirValue::Const(c) => {
                        self.instructions
                            .push(EbpfInsn::mov64_imm(dst_reg, *c as i32));
                    }
                    MirValue::StackSlot(_) => {
                        return Err(CompileError::UnsupportedInstruction(
                            "Stack slot in binop LHS".into(),
                        ));
                    }
                }

                // Apply operation with RHS
                match rhs {
                    MirValue::VReg(v) => {
                        let rhs_reg = self.ensure_reg(*v)?;
                        self.emit_binop_reg(dst_reg, *op, rhs_reg)?;
                    }
                    MirValue::Const(c) => {
                        self.emit_binop_imm(dst_reg, *op, *c as i32)?;
                    }
                    MirValue::StackSlot(_) => {
                        return Err(CompileError::UnsupportedInstruction(
                            "Stack slot in binop RHS".into(),
                        ));
                    }
                }
            }

            MirInst::UnaryOp { dst, op, src } => {
                let dst_reg = self.alloc_reg(*dst)?;
                match src {
                    MirValue::VReg(v) => {
                        let src_reg = self.ensure_reg(*v)?;
                        if dst_reg != src_reg {
                            self.instructions.push(EbpfInsn::mov64_reg(dst_reg, src_reg));
                        }
                    }
                    MirValue::Const(c) => {
                        self.instructions
                            .push(EbpfInsn::mov64_imm(dst_reg, *c as i32));
                    }
                    MirValue::StackSlot(_) => {
                        return Err(CompileError::UnsupportedInstruction(
                            "Stack slot in unary op".into(),
                        ));
                    }
                }

                match op {
                    UnaryOpKind::Not => {
                        // Logical not: 0 -> 1, non-zero -> 0
                        self.instructions.push(EbpfInsn::xor64_imm(dst_reg, 1));
                        self.instructions.push(EbpfInsn::and64_imm(dst_reg, 1));
                    }
                    UnaryOpKind::BitNot => {
                        self.instructions.push(EbpfInsn::xor64_imm(dst_reg, -1));
                    }
                    UnaryOpKind::Neg => {
                        self.instructions.push(EbpfInsn::neg64(dst_reg));
                    }
                }
            }

            MirInst::LoadCtxField { dst, field } => {
                let dst_reg = self.alloc_reg(*dst)?;
                self.compile_load_ctx_field(dst_reg, field)?;
            }

            MirInst::EmitEvent { data, size } => {
                self.needs_ringbuf = true;
                let data_reg = self.ensure_reg(*data)?;
                self.compile_emit_event(data_reg, *size)?;
            }

            MirInst::EmitRecord { fields } => {
                self.needs_ringbuf = true;
                self.compile_emit_record(fields)?;
            }

            MirInst::MapUpdate { map, key, .. } => {
                if map.name == "counters" {
                    self.needs_counter_map = true;
                }
                let key_reg = self.ensure_reg(*key)?;
                self.compile_map_update(&map.name, key_reg)?;
            }

            MirInst::ReadStr {
                dst,
                ptr,
                user_space,
                max_len,
            } => {
                let ptr_reg = self.ensure_reg(*ptr)?;
                let offset = self.slot_offsets.get(dst).copied().unwrap_or(0);
                self.compile_read_str(offset, ptr_reg, *user_space, *max_len)?;
            }

            MirInst::Jump { target } => {
                let jump_idx = self.instructions.len();
                self.instructions.push(EbpfInsn::jump(0)); // Placeholder
                self.pending_jumps.push((jump_idx, *target));
            }

            MirInst::Branch {
                cond,
                if_true,
                if_false,
            } => {
                let cond_reg = self.ensure_reg(*cond)?;

                // JNE (jump if not equal to 0) to if_true
                let jne_idx = self.instructions.len();
                // JNE dst, imm, offset
                self.instructions.push(EbpfInsn::new(
                    opcode::BPF_JMP | opcode::BPF_JNE | opcode::BPF_K,
                    cond_reg.as_u8(),
                    0,
                    0, // Placeholder
                    0, // Compare against 0
                ));
                self.pending_jumps.push((jne_idx, *if_true));

                // Fall through or jump to if_false
                let jmp_idx = self.instructions.len();
                self.instructions.push(EbpfInsn::jump(0));
                self.pending_jumps.push((jmp_idx, *if_false));
            }

            MirInst::Return { val } => {
                match val {
                    Some(MirValue::VReg(v)) => {
                        let src = self.ensure_reg(*v)?;
                        if src != EbpfReg::R0 {
                            self.instructions.push(EbpfInsn::mov64_reg(EbpfReg::R0, src));
                        }
                    }
                    Some(MirValue::Const(c)) => {
                        self.instructions
                            .push(EbpfInsn::mov64_imm(EbpfReg::R0, *c as i32));
                    }
                    Some(MirValue::StackSlot(_)) => {
                        return Err(CompileError::UnsupportedInstruction(
                            "Stack slot in return".into(),
                        ));
                    }
                    None => {
                        self.instructions.push(EbpfInsn::mov64_imm(EbpfReg::R0, 0));
                    }
                }
                self.instructions.push(EbpfInsn::exit());
            }

            MirInst::Histogram { value } => {
                self.needs_histogram_map = true;
                let value_reg = self.ensure_reg(*value)?;
                self.compile_histogram(value_reg)?;
            }

            MirInst::StartTimer => {
                self.needs_timestamp_map = true;
                self.compile_start_timer()?;
            }

            MirInst::StopTimer { dst } => {
                self.needs_timestamp_map = true;
                let dst_reg = self.alloc_reg(*dst)?;
                self.compile_stop_timer(dst_reg)?;
            }

            // Not yet implemented
            _ => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "MIR instruction {:?} not yet implemented",
                    inst
                )));
            }
        }

        Ok(())
    }

    /// Emit binary operation with register operand
    fn emit_binop_reg(
        &mut self,
        dst: EbpfReg,
        op: BinOpKind,
        rhs: EbpfReg,
    ) -> Result<(), CompileError> {
        match op {
            BinOpKind::Add => self.instructions.push(EbpfInsn::add64_reg(dst, rhs)),
            BinOpKind::Sub => self.instructions.push(EbpfInsn::sub64_reg(dst, rhs)),
            BinOpKind::Mul => self.instructions.push(EbpfInsn::mul64_reg(dst, rhs)),
            BinOpKind::Div => self.instructions.push(EbpfInsn::div64_reg(dst, rhs)),
            BinOpKind::Mod => self.instructions.push(EbpfInsn::mod64_reg(dst, rhs)),
            BinOpKind::And => self.instructions.push(EbpfInsn::and64_reg(dst, rhs)),
            BinOpKind::Or => self.instructions.push(EbpfInsn::or64_reg(dst, rhs)),
            BinOpKind::Xor => self.instructions.push(EbpfInsn::xor64_reg(dst, rhs)),
            BinOpKind::Shl => self.instructions.push(EbpfInsn::lsh64_reg(dst, rhs)),
            BinOpKind::Shr => self.instructions.push(EbpfInsn::rsh64_reg(dst, rhs)),
            // Comparisons - set to 1, conditionally jump over setting to 0
            BinOpKind::Eq
            | BinOpKind::Ne
            | BinOpKind::Lt
            | BinOpKind::Le
            | BinOpKind::Gt
            | BinOpKind::Ge => {
                self.emit_comparison_reg(dst, op, rhs)?;
            }
        }
        Ok(())
    }

    /// Emit binary operation with immediate operand
    fn emit_binop_imm(
        &mut self,
        dst: EbpfReg,
        op: BinOpKind,
        imm: i32,
    ) -> Result<(), CompileError> {
        match op {
            BinOpKind::Add => self.instructions.push(EbpfInsn::add64_imm(dst, imm)),
            BinOpKind::Sub => self.instructions.push(EbpfInsn::add64_imm(dst, -imm)),
            BinOpKind::Mul => self.instructions.push(EbpfInsn::mul64_imm(dst, imm)),
            BinOpKind::Div => self.instructions.push(EbpfInsn::div64_imm(dst, imm)),
            BinOpKind::Mod => self.instructions.push(EbpfInsn::mod64_imm(dst, imm)),
            BinOpKind::And => self.instructions.push(EbpfInsn::and64_imm(dst, imm)),
            BinOpKind::Or => self.instructions.push(EbpfInsn::or64_imm(dst, imm)),
            BinOpKind::Xor => self.instructions.push(EbpfInsn::xor64_imm(dst, imm)),
            BinOpKind::Shl => self.instructions.push(EbpfInsn::lsh64_imm(dst, imm)),
            BinOpKind::Shr => self.instructions.push(EbpfInsn::rsh64_imm(dst, imm)),
            // Comparisons
            BinOpKind::Eq
            | BinOpKind::Ne
            | BinOpKind::Lt
            | BinOpKind::Le
            | BinOpKind::Gt
            | BinOpKind::Ge => {
                self.emit_comparison_imm(dst, op, imm)?;
            }
        }
        Ok(())
    }

    /// Emit comparison with register, result in dst as 0 or 1
    fn emit_comparison_reg(
        &mut self,
        dst: EbpfReg,
        op: BinOpKind,
        rhs: EbpfReg,
    ) -> Result<(), CompileError> {
        // Pattern: set dst to 1, then conditionally jump over setting to 0
        let tmp = EbpfReg::R0;
        self.instructions.push(EbpfInsn::mov64_reg(tmp, dst)); // Save LHS
        self.instructions.push(EbpfInsn::mov64_imm(dst, 1)); // Assume true

        let jump_offset = 1i16; // Skip the next instruction

        // Build conditional jump instruction
        let jmp_opcode = match op {
            BinOpKind::Eq => opcode::BPF_JMP | opcode::BPF_JEQ | opcode::BPF_X,
            BinOpKind::Ne => opcode::BPF_JMP | opcode::BPF_JNE | opcode::BPF_X,
            BinOpKind::Lt => opcode::BPF_JMP | opcode::BPF_JSLT | opcode::BPF_X,
            BinOpKind::Le => opcode::BPF_JMP | opcode::BPF_JSLE | opcode::BPF_X,
            BinOpKind::Gt => opcode::BPF_JMP | opcode::BPF_JSGT | opcode::BPF_X,
            BinOpKind::Ge => opcode::BPF_JMP | opcode::BPF_JSGE | opcode::BPF_X,
            _ => unreachable!(),
        };

        self.instructions.push(EbpfInsn::new(
            jmp_opcode,
            tmp.as_u8(),
            rhs.as_u8(),
            jump_offset,
            0,
        ));

        self.instructions.push(EbpfInsn::mov64_imm(dst, 0));
        Ok(())
    }

    /// Emit comparison with immediate, result in dst as 0 or 1
    fn emit_comparison_imm(
        &mut self,
        dst: EbpfReg,
        op: BinOpKind,
        imm: i32,
    ) -> Result<(), CompileError> {
        // Save original value
        let tmp = EbpfReg::R0;
        self.instructions.push(EbpfInsn::mov64_reg(tmp, dst));
        self.instructions.push(EbpfInsn::mov64_imm(dst, 1)); // Assume true

        let jump_offset = 1i16;

        let jmp_opcode = match op {
            BinOpKind::Eq => opcode::BPF_JMP | opcode::BPF_JEQ | opcode::BPF_K,
            BinOpKind::Ne => opcode::BPF_JMP | opcode::BPF_JNE | opcode::BPF_K,
            BinOpKind::Lt => opcode::BPF_JMP | opcode::BPF_JSLT | opcode::BPF_K,
            BinOpKind::Le => opcode::BPF_JMP | opcode::BPF_JSLE | opcode::BPF_K,
            BinOpKind::Gt => opcode::BPF_JMP | opcode::BPF_JSGT | opcode::BPF_K,
            BinOpKind::Ge => opcode::BPF_JMP | opcode::BPF_JSGE | opcode::BPF_K,
            _ => unreachable!(),
        };

        self.instructions
            .push(EbpfInsn::new(jmp_opcode, tmp.as_u8(), 0, jump_offset, imm));

        self.instructions.push(EbpfInsn::mov64_imm(dst, 0));
        Ok(())
    }

    /// Compile context field load
    fn compile_load_ctx_field(
        &mut self,
        dst: EbpfReg,
        field: &CtxField,
    ) -> Result<(), CompileError> {
        match field {
            CtxField::Pid => {
                // bpf_get_current_pid_tgid() returns (tgid << 32) | pid
                // Lower 32 bits = thread ID (what Linux calls PID)
                self.instructions
                    .push(EbpfInsn::call(BpfHelper::GetCurrentPidTgid));
                self.instructions
                    .push(EbpfInsn::mov64_reg(dst, EbpfReg::R0));
                // Keep lower 32 bits
                self.instructions
                    .push(EbpfInsn::and64_imm(dst, 0x7FFFFFFF));
            }
            CtxField::Tid => {
                // Upper 32 bits = thread group ID (what userspace calls PID)
                self.instructions
                    .push(EbpfInsn::call(BpfHelper::GetCurrentPidTgid));
                self.instructions.push(EbpfInsn::rsh64_imm(EbpfReg::R0, 32));
                self.instructions
                    .push(EbpfInsn::mov64_reg(dst, EbpfReg::R0));
            }
            CtxField::Uid => {
                self.instructions
                    .push(EbpfInsn::call(BpfHelper::GetCurrentUidGid));
                self.instructions
                    .push(EbpfInsn::mov64_reg(dst, EbpfReg::R0));
                self.instructions
                    .push(EbpfInsn::and64_imm(dst, 0x7FFFFFFF));
            }
            CtxField::Gid => {
                self.instructions
                    .push(EbpfInsn::call(BpfHelper::GetCurrentUidGid));
                self.instructions.push(EbpfInsn::rsh64_imm(EbpfReg::R0, 32));
                self.instructions
                    .push(EbpfInsn::mov64_reg(dst, EbpfReg::R0));
            }
            CtxField::Timestamp => {
                self.instructions
                    .push(EbpfInsn::call(BpfHelper::KtimeGetNs));
                self.instructions
                    .push(EbpfInsn::mov64_reg(dst, EbpfReg::R0));
            }
            CtxField::Cpu => {
                // CPU requires bpf_get_smp_processor_id which isn't in our helpers
                // For now, just return 0
                self.instructions.push(EbpfInsn::mov64_imm(dst, 0));
            }
            CtxField::Comm => {
                // Allocate stack space for comm (16 bytes)
                self.check_stack_space(16)?;
                // Stack grows downward - decrement first
                self.stack_offset -= 16;
                let comm_offset = self.stack_offset;

                // bpf_get_current_comm(buf, size)
                self.instructions
                    .push(EbpfInsn::mov64_reg(EbpfReg::R1, EbpfReg::R10));
                self.instructions
                    .push(EbpfInsn::add64_imm(EbpfReg::R1, comm_offset as i32));
                self.instructions.push(EbpfInsn::mov64_imm(EbpfReg::R2, 16));
                self.instructions
                    .push(EbpfInsn::call(BpfHelper::GetCurrentComm));

                // Return pointer to comm on stack
                self.instructions
                    .push(EbpfInsn::mov64_reg(dst, EbpfReg::R10));
                self.instructions
                    .push(EbpfInsn::add64_imm(dst, comm_offset as i32));
            }
            CtxField::Arg(n) => {
                let n = *n as usize;
                if n >= pt_regs_offsets::ARG_OFFSETS.len() {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "Argument index {} out of range",
                        n
                    )));
                }
                let offset = pt_regs_offsets::ARG_OFFSETS[n];
                // R1 contains pointer to pt_regs on entry
                // We need to save it in R9 at start of function for later use
                // For now, assume R9 has the context pointer
                self.instructions
                    .push(EbpfInsn::ldxdw(dst, EbpfReg::R9, offset));
            }
            CtxField::RetVal => {
                if let Some(ctx) = self.probe_ctx {
                    if !ctx.is_return_probe() {
                        return Err(CompileError::RetvalOnNonReturnProbe);
                    }
                }
                let offset = pt_regs_offsets::RETVAL_OFFSET;
                self.instructions
                    .push(EbpfInsn::ldxdw(dst, EbpfReg::R9, offset));
            }
            CtxField::KStack | CtxField::UStack => {
                return Err(CompileError::UnsupportedInstruction(
                    "Stack trace not yet implemented in MIR compiler".into(),
                ));
            }
            CtxField::TracepointField(name) => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "Tracepoint field '{}' not yet implemented in MIR compiler",
                    name
                )));
            }
        }
        Ok(())
    }

    /// Compile emit event to ring buffer
    fn compile_emit_event(&mut self, data_reg: EbpfReg, size: usize) -> Result<(), CompileError> {
        let event_size = if size > 0 { size } else { 8 };
        self.check_stack_space(event_size as i16)?;
        // Stack grows downward - decrement first, then use offset
        self.stack_offset -= event_size as i16;
        let event_offset = self.stack_offset;

        // Store data to stack
        self.instructions
            .push(EbpfInsn::stxdw(EbpfReg::R10, event_offset, data_reg));

        // bpf_ringbuf_output(map, data, size, flags)
        let reloc_offset = self.instructions.len() * 8;
        let [insn1, insn2] = EbpfInsn::ld_map_fd(EbpfReg::R1);
        self.instructions.push(insn1);
        self.instructions.push(insn2);
        self.relocations.push(MapRelocation {
            insn_offset: reloc_offset,
            map_name: RINGBUF_MAP_NAME.to_string(),
        });

        // R2 = data pointer
        self.instructions
            .push(EbpfInsn::mov64_reg(EbpfReg::R2, EbpfReg::R10));
        self.instructions
            .push(EbpfInsn::add64_imm(EbpfReg::R2, event_offset as i32));

        // R3 = size
        self.instructions
            .push(EbpfInsn::mov64_imm(EbpfReg::R3, event_size as i32));

        // R4 = flags
        self.instructions.push(EbpfInsn::mov64_imm(EbpfReg::R4, 0));

        self.instructions
            .push(EbpfInsn::call(BpfHelper::RingbufOutput));

        Ok(())
    }

    /// Compile emit record to ring buffer
    fn compile_emit_record(&mut self, fields: &[RecordFieldDef]) -> Result<(), CompileError> {
        if fields.is_empty() {
            return Ok(());
        }

        // Build schema and calculate total size
        let mut schema_fields = Vec::new();
        let mut offset = 0usize;
        let mut total_size = 0usize;

        for field in fields {
            let (field_type, size) = self.mir_type_to_bpf_field(&field.ty);
            schema_fields.push(SchemaField {
                name: field.name.clone(),
                field_type,
                offset,
            });
            offset += size;
            total_size += size;
        }

        // Store schema
        self.event_schema = Some(EventSchema {
            fields: schema_fields,
            total_size,
        });

        // Allocate contiguous buffer on stack
        self.check_stack_space(total_size as i16)?;
        self.stack_offset -= total_size as i16;
        let buffer_offset = self.stack_offset;

        // Copy each field value to the buffer
        let mut dest_offset = buffer_offset;
        for field in fields {
            let (_, size) = self.mir_type_to_bpf_field(&field.ty);

            // Get the field value into a register
            let field_reg = self.ensure_reg(field.value)?;

            // Store to the buffer
            // For 8-byte values, use stxdw
            if size == 8 {
                self.instructions
                    .push(EbpfInsn::stxdw(EbpfReg::R10, dest_offset, field_reg));
            } else if size == 4 {
                self.instructions
                    .push(EbpfInsn::stxw(EbpfReg::R10, dest_offset, field_reg));
            } else {
                // For larger types (like comm=16), copy in 8-byte chunks
                // The field_reg should be a pointer to the data
                for chunk in 0..(size / 8) {
                    self.instructions.push(EbpfInsn::ldxdw(
                        EbpfReg::R0,
                        field_reg,
                        (chunk * 8) as i16,
                    ));
                    self.instructions.push(EbpfInsn::stxdw(
                        EbpfReg::R10,
                        dest_offset + (chunk * 8) as i16,
                        EbpfReg::R0,
                    ));
                }
            }

            dest_offset += size as i16;
        }

        // Emit the buffer via ring buffer
        // bpf_ringbuf_output(map, data, size, flags)
        let reloc_offset = self.instructions.len() * 8;
        let [insn1, insn2] = EbpfInsn::ld_map_fd(EbpfReg::R1);
        self.instructions.push(insn1);
        self.instructions.push(insn2);
        self.relocations.push(MapRelocation {
            insn_offset: reloc_offset,
            map_name: RINGBUF_MAP_NAME.to_string(),
        });

        // R2 = pointer to buffer
        self.instructions
            .push(EbpfInsn::mov64_reg(EbpfReg::R2, EbpfReg::R10));
        self.instructions
            .push(EbpfInsn::add64_imm(EbpfReg::R2, buffer_offset as i32));

        // R3 = total size
        self.instructions
            .push(EbpfInsn::mov64_imm(EbpfReg::R3, total_size as i32));

        // R4 = flags
        self.instructions.push(EbpfInsn::mov64_imm(EbpfReg::R4, 0));

        self.instructions
            .push(EbpfInsn::call(BpfHelper::RingbufOutput));

        Ok(())
    }

    /// Convert MIR type to BPF field type and size
    /// Note: All sizes are aligned to 8 bytes for eBPF stack alignment requirements
    fn mir_type_to_bpf_field(&self, ty: &MirType) -> (BpfFieldType, usize) {
        match ty {
            MirType::I64 | MirType::U64 => (BpfFieldType::Int, 8),
            // I32 still uses 8 bytes for stack alignment
            MirType::I32 | MirType::U32 => (BpfFieldType::Int, 8),
            MirType::I16 | MirType::U16 => (BpfFieldType::Int, 8),
            MirType::I8 | MirType::U8 | MirType::Bool => (BpfFieldType::Int, 8),
            MirType::Array { elem, len } if matches!(elem.as_ref(), MirType::U8) && *len == 16 => {
                (BpfFieldType::Comm, 16)
            }
            MirType::Array { elem, len } if matches!(elem.as_ref(), MirType::U8) => {
                // Round up to 8-byte alignment
                let aligned_len = (*len + 7) & !7;
                (BpfFieldType::String, aligned_len)
            }
            _ => (BpfFieldType::Int, 8), // Default to 64-bit int
        }
    }

    /// Compile map update (for count operation)
    fn compile_map_update(&mut self, map_name: &str, key_reg: EbpfReg) -> Result<(), CompileError> {
        // For count: lookup key, increment, update
        self.check_stack_space(16)?;
        // Stack grows downward - decrement first
        self.stack_offset -= 16;
        let key_offset = self.stack_offset + 8; // key at higher address
        let val_offset = self.stack_offset;     // value at lower address

        // Store key to stack
        self.instructions
            .push(EbpfInsn::stxdw(EbpfReg::R10, key_offset, key_reg));

        // bpf_map_lookup_elem(map, key) -> value ptr or null
        let reloc_offset = self.instructions.len() * 8;
        let [insn1, insn2] = EbpfInsn::ld_map_fd(EbpfReg::R1);
        self.instructions.push(insn1);
        self.instructions.push(insn2);
        self.relocations.push(MapRelocation {
            insn_offset: reloc_offset,
            map_name: map_name.to_string(),
        });

        self.instructions
            .push(EbpfInsn::mov64_reg(EbpfReg::R2, EbpfReg::R10));
        self.instructions
            .push(EbpfInsn::add64_imm(EbpfReg::R2, key_offset as i32));
        self.instructions
            .push(EbpfInsn::call(BpfHelper::MapLookupElem));

        // If null, initialize to 0; else load and increment
        let jmp_to_init = self.instructions.len();
        self.instructions
            .push(EbpfInsn::jeq_imm(EbpfReg::R0, 0, 0)); // Placeholder

        // Load current value, increment
        self.instructions
            .push(EbpfInsn::ldxdw(EbpfReg::R3, EbpfReg::R0, 0));
        self.instructions.push(EbpfInsn::add64_imm(EbpfReg::R3, 1));
        let jmp_to_update = self.instructions.len();
        self.instructions.push(EbpfInsn::jump(0)); // Skip init

        // init: value = 1
        let init_idx = self.instructions.len();
        self.instructions[jmp_to_init] =
            EbpfInsn::jeq_imm(EbpfReg::R0, 0, (init_idx - jmp_to_init - 1) as i16);
        self.instructions.push(EbpfInsn::mov64_imm(EbpfReg::R3, 1));

        // update:
        let update_idx = self.instructions.len();
        self.instructions[jmp_to_update] =
            EbpfInsn::jump((update_idx - jmp_to_update - 1) as i16);

        // Store new value to stack
        self.instructions
            .push(EbpfInsn::stxdw(EbpfReg::R10, val_offset, EbpfReg::R3));

        // bpf_map_update_elem(map, key, value, flags)
        let reloc_offset = self.instructions.len() * 8;
        let [insn1, insn2] = EbpfInsn::ld_map_fd(EbpfReg::R1);
        self.instructions.push(insn1);
        self.instructions.push(insn2);
        self.relocations.push(MapRelocation {
            insn_offset: reloc_offset,
            map_name: map_name.to_string(),
        });

        self.instructions
            .push(EbpfInsn::mov64_reg(EbpfReg::R2, EbpfReg::R10));
        self.instructions
            .push(EbpfInsn::add64_imm(EbpfReg::R2, key_offset as i32));
        self.instructions
            .push(EbpfInsn::mov64_reg(EbpfReg::R3, EbpfReg::R10));
        self.instructions
            .push(EbpfInsn::add64_imm(EbpfReg::R3, val_offset as i32));
        self.instructions.push(EbpfInsn::mov64_imm(EbpfReg::R4, 0)); // BPF_ANY
        self.instructions
            .push(EbpfInsn::call(BpfHelper::MapUpdateElem));

        Ok(())
    }

    /// Compile read string from user/kernel memory
    fn compile_read_str(
        &mut self,
        dst_offset: i16,
        ptr_reg: EbpfReg,
        user_space: bool,
        max_len: usize,
    ) -> Result<(), CompileError> {
        // bpf_probe_read_{user,kernel}_str(dst, size, src)
        self.instructions
            .push(EbpfInsn::mov64_reg(EbpfReg::R1, EbpfReg::R10));
        self.instructions
            .push(EbpfInsn::add64_imm(EbpfReg::R1, dst_offset as i32));
        self.instructions
            .push(EbpfInsn::mov64_imm(EbpfReg::R2, max_len as i32));
        self.instructions
            .push(EbpfInsn::mov64_reg(EbpfReg::R3, ptr_reg));

        let helper = if user_space {
            BpfHelper::ProbeReadUserStr
        } else {
            BpfHelper::ProbeReadKernelStr
        };
        self.instructions.push(EbpfInsn::call(helper));

        Ok(())
    }

    /// Check if we have enough stack space
    fn check_stack_space(&self, needed: i16) -> Result<(), CompileError> {
        if self.stack_offset - needed < -512 {
            Err(CompileError::StackOverflow)
        } else {
            Ok(())
        }
    }

    /// Fix up pending jumps after all blocks are compiled
    fn fixup_jumps(&mut self) -> Result<(), CompileError> {
        for (insn_idx, target_block) in &self.pending_jumps {
            let target_offset = self
                .block_offsets
                .get(target_block)
                .copied()
                .ok_or_else(|| {
                    CompileError::UnsupportedInstruction(format!(
                        "Jump target block {:?} not found",
                        target_block
                    ))
                })?;

            // Calculate relative offset (target - source - 1)
            let rel_offset = (target_offset as i64 - *insn_idx as i64 - 1) as i16;

            // Update the jump instruction's offset field
            self.instructions[*insn_idx].offset = rel_offset;
        }
        Ok(())
    }

    // === Register Allocation (Simple LRU) ===

    /// Allocate a physical register for a virtual register
    fn alloc_reg(&mut self, vreg: VReg) -> Result<EbpfReg, CompileError> {
        if let Some(&phys) = self.vreg_to_phys.get(&vreg) {
            return Ok(phys);
        }

        let phys = self.available_regs[self.next_lru % self.available_regs.len()];
        self.next_lru += 1;

        // Spill if needed
        let to_spill: Option<VReg> = self
            .vreg_to_phys
            .iter()
            .find(|(_, p)| **p == phys)
            .map(|(v, _)| *v);

        if let Some(old_vreg) = to_spill {
            self.spill_vreg(old_vreg, phys)?;
            self.vreg_to_phys.remove(&old_vreg);
        }

        self.vreg_to_phys.insert(vreg, phys);
        Ok(phys)
    }

    /// Ensure a virtual register is in a physical register
    fn ensure_reg(&mut self, vreg: VReg) -> Result<EbpfReg, CompileError> {
        if let Some(&phys) = self.vreg_to_phys.get(&vreg) {
            return Ok(phys);
        }

        if let Some(&offset) = self.vreg_spills.get(&vreg) {
            let phys = self.alloc_reg(vreg)?;
            self.instructions
                .push(EbpfInsn::ldxdw(phys, EbpfReg::R10, offset));
            return Ok(phys);
        }

        self.alloc_reg(vreg)
    }

    /// Spill a virtual register to stack
    fn spill_vreg(&mut self, vreg: VReg, phys: EbpfReg) -> Result<(), CompileError> {
        let offset = if let Some(&off) = self.vreg_spills.get(&vreg) {
            off
        } else {
            self.check_stack_space(8)?;
            self.stack_offset -= 8;
            let off = self.stack_offset;
            self.vreg_spills.insert(vreg, off);
            off
        };

        self.instructions
            .push(EbpfInsn::stxdw(EbpfReg::R10, offset, phys));
        Ok(())
    }

    // === Histogram and Timing ===

    /// Compile histogram aggregation
    /// Computes log2 bucket of value and increments counter in histogram map
    fn compile_histogram(&mut self, value_reg: EbpfReg) -> Result<(), CompileError> {
        // Allocate stack for key (bucket) and value (count)
        self.check_stack_space(16)?;
        let key_offset = self.stack_offset - 8;
        let value_offset = self.stack_offset - 16;
        self.stack_offset -= 16;

        // Compute log2 bucket using binary search
        // Save value to R0 for manipulation, bucket accumulator in R1
        self.instructions.push(EbpfInsn::mov64_reg(EbpfReg::R0, value_reg));
        self.instructions.push(EbpfInsn::mov64_imm(EbpfReg::R1, 0));

        // If value <= 0, bucket = 0
        // JLE R0, 0, skip_log2 (offset will be filled in later)
        let skip_log2_idx = self.instructions.len();
        self.instructions.push(EbpfInsn::new(
            opcode::BPF_JMP | opcode::BPF_JSLE | opcode::BPF_K,
            EbpfReg::R0.as_u8(), 0, 0, 0, // offset placeholder
        ));

        // Binary search for highest bit
        // Check >= 2^32
        self.emit_log2_check(32)?;
        self.emit_log2_check(16)?;
        self.emit_log2_check(8)?;
        self.emit_log2_check(4)?;
        self.emit_log2_check(2)?;
        self.emit_log2_check(1)?;

        // Fix up skip_log2 jump to skip past log2 computation
        let skip_log2_offset = (self.instructions.len() - skip_log2_idx - 1) as i16;
        self.instructions[skip_log2_idx].offset = skip_log2_offset;

        // Store bucket (R1) to stack
        self.instructions.push(EbpfInsn::stxdw(EbpfReg::R10, key_offset, EbpfReg::R1));

        // Map lookup
        let lookup_reloc = self.instructions.len() * 8;
        let [insn1, insn2] = EbpfInsn::ld_map_fd(EbpfReg::R1);
        self.instructions.push(insn1);
        self.instructions.push(insn2);
        self.relocations.push(MapRelocation {
            insn_offset: lookup_reloc,
            map_name: HISTOGRAM_MAP_NAME.to_string(),
        });

        self.instructions.push(EbpfInsn::mov64_reg(EbpfReg::R2, EbpfReg::R10));
        self.instructions.push(EbpfInsn::add64_imm(EbpfReg::R2, key_offset as i32));
        self.instructions.push(EbpfInsn::call(BpfHelper::MapLookupElem));

        // If NULL, jump to init
        let init_idx = self.instructions.len();
        self.instructions.push(EbpfInsn::new(
            opcode::BPF_JMP | opcode::BPF_JEQ | opcode::BPF_K,
            EbpfReg::R0.as_u8(), 0, 0, 0,
        ));

        // Exists - increment in place
        self.instructions.push(EbpfInsn::ldxdw(EbpfReg::R1, EbpfReg::R0, 0));
        self.instructions.push(EbpfInsn::add64_imm(EbpfReg::R1, 1));
        self.instructions.push(EbpfInsn::stxdw(EbpfReg::R0, 0, EbpfReg::R1));

        // Jump to done
        let done_jmp_idx = self.instructions.len();
        self.instructions.push(EbpfInsn::jump(0));

        // Init path
        let init_offset = (self.instructions.len() - init_idx - 1) as i16;
        self.instructions[init_idx].offset = init_offset;

        // Store 1 to value
        self.instructions.push(EbpfInsn::mov64_imm(EbpfReg::R1, 1));
        self.instructions.push(EbpfInsn::stxdw(EbpfReg::R10, value_offset, EbpfReg::R1));

        // Map update
        let update_reloc = self.instructions.len() * 8;
        let [insn1, insn2] = EbpfInsn::ld_map_fd(EbpfReg::R1);
        self.instructions.push(insn1);
        self.instructions.push(insn2);
        self.relocations.push(MapRelocation {
            insn_offset: update_reloc,
            map_name: HISTOGRAM_MAP_NAME.to_string(),
        });

        self.instructions.push(EbpfInsn::mov64_reg(EbpfReg::R2, EbpfReg::R10));
        self.instructions.push(EbpfInsn::add64_imm(EbpfReg::R2, key_offset as i32));
        self.instructions.push(EbpfInsn::mov64_reg(EbpfReg::R3, EbpfReg::R10));
        self.instructions.push(EbpfInsn::add64_imm(EbpfReg::R3, value_offset as i32));
        self.instructions.push(EbpfInsn::mov64_imm(EbpfReg::R4, 0)); // BPF_ANY
        self.instructions.push(EbpfInsn::call(BpfHelper::MapUpdateElem));

        // Done
        let done_offset = (self.instructions.len() - done_jmp_idx - 1) as i16;
        self.instructions[done_jmp_idx].offset = done_offset;

        Ok(())
    }

    /// Helper for log2 computation - check if value >= 2^bits
    fn emit_log2_check(&mut self, bits: i32) -> Result<(), CompileError> {
        if bits >= 32 {
            // Need 64-bit compare
            self.instructions.push(EbpfInsn::mov64_imm(EbpfReg::R2, 1));
            self.instructions.push(EbpfInsn::lsh64_imm(EbpfReg::R2, bits));
        }
        // JLT R0, 2^bits, skip (2 instructions)
        self.instructions.push(EbpfInsn::new(
            opcode::BPF_JMP | opcode::BPF_JLT | opcode::BPF_K,
            EbpfReg::R0.as_u8(), 0, 2, 1 << bits.min(31),
        ));
        self.instructions.push(EbpfInsn::add64_imm(EbpfReg::R1, bits));
        self.instructions.push(EbpfInsn::rsh64_imm(EbpfReg::R0, bits));
        Ok(())
    }

    /// Compile start-timer: store current ktime keyed by TID
    fn compile_start_timer(&mut self) -> Result<(), CompileError> {
        // Allocate stack for key (pid_tgid) and value (timestamp)
        self.check_stack_space(16)?;
        let key_offset = self.stack_offset - 8;
        let value_offset = self.stack_offset - 16;
        self.stack_offset -= 16;

        // Get current pid_tgid as key
        self.instructions.push(EbpfInsn::call(BpfHelper::GetCurrentPidTgid));
        self.instructions.push(EbpfInsn::stxdw(EbpfReg::R10, key_offset, EbpfReg::R0));

        // Get current time
        self.instructions.push(EbpfInsn::call(BpfHelper::KtimeGetNs));
        self.instructions.push(EbpfInsn::stxdw(EbpfReg::R10, value_offset, EbpfReg::R0));

        // Map update
        let update_reloc = self.instructions.len() * 8;
        let [insn1, insn2] = EbpfInsn::ld_map_fd(EbpfReg::R1);
        self.instructions.push(insn1);
        self.instructions.push(insn2);
        self.relocations.push(MapRelocation {
            insn_offset: update_reloc,
            map_name: TIMESTAMP_MAP_NAME.to_string(),
        });

        self.instructions.push(EbpfInsn::mov64_reg(EbpfReg::R2, EbpfReg::R10));
        self.instructions.push(EbpfInsn::add64_imm(EbpfReg::R2, key_offset as i32));
        self.instructions.push(EbpfInsn::mov64_reg(EbpfReg::R3, EbpfReg::R10));
        self.instructions.push(EbpfInsn::add64_imm(EbpfReg::R3, value_offset as i32));
        self.instructions.push(EbpfInsn::mov64_imm(EbpfReg::R4, 0)); // BPF_ANY
        self.instructions.push(EbpfInsn::call(BpfHelper::MapUpdateElem));

        Ok(())
    }

    /// Compile stop-timer: lookup start time, compute delta, delete entry
    fn compile_stop_timer(&mut self, dst_reg: EbpfReg) -> Result<(), CompileError> {
        // Allocate stack for key (pid_tgid)
        self.check_stack_space(8)?;
        let key_offset = self.stack_offset - 8;
        self.stack_offset -= 8;

        // Get current pid_tgid as key
        self.instructions.push(EbpfInsn::call(BpfHelper::GetCurrentPidTgid));
        self.instructions.push(EbpfInsn::stxdw(EbpfReg::R10, key_offset, EbpfReg::R0));

        // Map lookup
        let lookup_reloc = self.instructions.len() * 8;
        let [insn1, insn2] = EbpfInsn::ld_map_fd(EbpfReg::R1);
        self.instructions.push(insn1);
        self.instructions.push(insn2);
        self.relocations.push(MapRelocation {
            insn_offset: lookup_reloc,
            map_name: TIMESTAMP_MAP_NAME.to_string(),
        });

        self.instructions.push(EbpfInsn::mov64_reg(EbpfReg::R2, EbpfReg::R10));
        self.instructions.push(EbpfInsn::add64_imm(EbpfReg::R2, key_offset as i32));
        self.instructions.push(EbpfInsn::call(BpfHelper::MapLookupElem));

        // If NULL, return 0
        let no_timer_idx = self.instructions.len();
        self.instructions.push(EbpfInsn::new(
            opcode::BPF_JMP | opcode::BPF_JEQ | opcode::BPF_K,
            EbpfReg::R0.as_u8(), 0, 0, 0,
        ));

        // Load start timestamp to R6 (callee-saved)
        self.instructions.push(EbpfInsn::ldxdw(EbpfReg::R6, EbpfReg::R0, 0));

        // Get current time
        self.instructions.push(EbpfInsn::call(BpfHelper::KtimeGetNs));

        // Compute delta = current - start
        self.instructions.push(EbpfInsn::sub64_reg(EbpfReg::R0, EbpfReg::R6));

        // Save delta to dst_reg
        if dst_reg != EbpfReg::R0 {
            self.instructions.push(EbpfInsn::mov64_reg(dst_reg, EbpfReg::R0));
        }

        // Delete map entry
        let delete_reloc = self.instructions.len() * 8;
        let [insn1, insn2] = EbpfInsn::ld_map_fd(EbpfReg::R1);
        self.instructions.push(insn1);
        self.instructions.push(insn2);
        self.relocations.push(MapRelocation {
            insn_offset: delete_reloc,
            map_name: TIMESTAMP_MAP_NAME.to_string(),
        });

        self.instructions.push(EbpfInsn::mov64_reg(EbpfReg::R2, EbpfReg::R10));
        self.instructions.push(EbpfInsn::add64_imm(EbpfReg::R2, key_offset as i32));
        self.instructions.push(EbpfInsn::call(BpfHelper::MapDeleteElem));

        // Jump to done
        let done_jmp_idx = self.instructions.len();
        self.instructions.push(EbpfInsn::jump(0));

        // No timer path - set dst to 0
        let no_timer_offset = (self.instructions.len() - no_timer_idx - 1) as i16;
        self.instructions[no_timer_idx].offset = no_timer_offset;
        self.instructions.push(EbpfInsn::mov64_imm(dst_reg, 0));

        // Done
        let done_offset = (self.instructions.len() - done_jmp_idx - 1) as i16;
        self.instructions[done_jmp_idx].offset = done_offset;

        Ok(())
    }
}

/// Compile a MIR program to eBPF
pub fn compile_mir_to_ebpf(
    mir: &MirProgram,
    probe_ctx: Option<&ProbeContext>,
) -> Result<MirCompileResult, CompileError> {
    let compiler = MirToEbpfCompiler::new(mir, probe_ctx);
    compiler.compile()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler::ir_to_mir::lower_ir_to_mir;
    use crate::compiler::IrToEbpfCompiler;
    use nu_protocol::ast::{Math, Operator};
    use nu_protocol::ir::{IrBlock, Instruction, Literal};
    use nu_protocol::RegId;
    use std::sync::Arc;

    fn make_ir_block(instructions: Vec<Instruction>) -> IrBlock {
        IrBlock {
            instructions,
            spans: vec![],
            data: Arc::from([]),
            ast: vec![],
            comments: vec![],
            register_count: 10,
            file_count: 0,
        }
    }

    /// Test that both compilers produce valid bytecode for return zero
    #[test]
    fn test_parity_return_zero() {
        let ir = make_ir_block(vec![
            Instruction::LoadLiteral {
                dst: RegId::new(0),
                lit: Literal::Int(0),
            },
            Instruction::Return { src: RegId::new(0) },
        ]);

        // Old compiler
        let old_result = IrToEbpfCompiler::compile_no_calls(&ir).unwrap();
        assert!(!old_result.is_empty(), "Old compiler produced empty bytecode");

        // New MIR compiler
        let mir_program = lower_ir_to_mir(&ir, None, None, &[], None).unwrap();
        let mir_result = compile_mir_to_ebpf(&mir_program, None).unwrap();
        assert!(
            !mir_result.bytecode.is_empty(),
            "MIR compiler produced empty bytecode"
        );

        // Both should produce eBPF bytecode that's a multiple of 8 bytes
        assert_eq!(
            old_result.len() % 8,
            0,
            "Old compiler bytecode should be aligned to 8 bytes"
        );
        assert_eq!(
            mir_result.bytecode.len() % 8,
            0,
            "MIR compiler bytecode should be aligned to 8 bytes"
        );
    }

    /// Test that both compilers produce valid bytecode for addition
    #[test]
    fn test_parity_add() {
        let ir = make_ir_block(vec![
            Instruction::LoadLiteral {
                dst: RegId::new(0),
                lit: Literal::Int(1),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(1),
                lit: Literal::Int(2),
            },
            Instruction::BinaryOp {
                lhs_dst: RegId::new(0),
                op: Operator::Math(Math::Add),
                rhs: RegId::new(1),
            },
            Instruction::Return { src: RegId::new(0) },
        ]);

        // Old compiler
        let old_result = IrToEbpfCompiler::compile_no_calls(&ir).unwrap();
        assert!(!old_result.is_empty(), "Old compiler produced empty bytecode");

        // New MIR compiler
        let mir_program = lower_ir_to_mir(&ir, None, None, &[], None).unwrap();
        let mir_result = compile_mir_to_ebpf(&mir_program, None).unwrap();
        assert!(
            !mir_result.bytecode.is_empty(),
            "MIR compiler produced empty bytecode"
        );
    }

    /// Test that old compiler handles branching (MIR branch test is separate)
    #[test]
    fn test_parity_branch() {
        let ir = make_ir_block(vec![
            Instruction::LoadLiteral {
                dst: RegId::new(0),
                lit: Literal::Bool(true),
            },
            Instruction::BranchIf {
                cond: RegId::new(0),
                index: 3, // Jump to Return
            },
            Instruction::LoadLiteral {
                dst: RegId::new(1),
                lit: Literal::Int(0),
            },
            Instruction::Return { src: RegId::new(0) },
        ]);

        // Old compiler - verify it handles branching
        let old_result = IrToEbpfCompiler::compile_no_calls(&ir).unwrap();
        assert!(!old_result.is_empty(), "Old compiler produced empty bytecode");

        // MIR compiler branching is tested separately with proper block construction
    }

    /// Test multiplication
    #[test]
    fn test_parity_multiply() {
        let ir = make_ir_block(vec![
            Instruction::LoadLiteral {
                dst: RegId::new(0),
                lit: Literal::Int(5),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(1),
                lit: Literal::Int(3),
            },
            Instruction::BinaryOp {
                lhs_dst: RegId::new(0),
                op: Operator::Math(Math::Multiply),
                rhs: RegId::new(1),
            },
            Instruction::Return { src: RegId::new(0) },
        ]);

        // Old compiler
        let old_result = IrToEbpfCompiler::compile_no_calls(&ir).unwrap();
        assert!(!old_result.is_empty(), "Old compiler produced empty bytecode");

        // New MIR compiler
        let mir_program = lower_ir_to_mir(&ir, None, None, &[], None).unwrap();
        let mir_result = compile_mir_to_ebpf(&mir_program, None).unwrap();
        assert!(
            !mir_result.bytecode.is_empty(),
            "MIR compiler produced empty bytecode"
        );
    }

    /// Test MIR function creation directly
    #[test]
    fn test_mir_direct_compile() {
        use crate::compiler::mir::*;

        let mut func = MirFunction::new();

        // Create entry block
        let mut entry_block = BasicBlock::new(BlockId(0));

        // Simple: mov r0, 42; exit
        entry_block.instructions.push(MirInst::Copy {
            dst: VReg(0),
            src: MirValue::Const(42),
        });
        entry_block.terminator = MirInst::Return {
            val: Some(MirValue::VReg(VReg(0))),
        };

        func.blocks.push(entry_block);
        func.vreg_count = 1;

        let program = MirProgram {
            main: func,
            subfunctions: vec![],
        };

        let result = compile_mir_to_ebpf(&program, None).unwrap();
        assert!(
            !result.bytecode.is_empty(),
            "Direct MIR compile produced empty bytecode"
        );
    }

    /// Test MIR branching directly
    #[test]
    fn test_mir_branch_compile() {
        use crate::compiler::mir::*;

        let mut func = MirFunction::new();

        // Entry block: load condition, branch
        let mut entry = BasicBlock::new(BlockId(0));
        entry.instructions.push(MirInst::Copy {
            dst: VReg(0),
            src: MirValue::Const(1), // true
        });
        entry.terminator = MirInst::Branch {
            cond: VReg(0),
            if_true: BlockId(1),
            if_false: BlockId(2),
        };

        // True block: return 1
        let mut true_block = BasicBlock::new(BlockId(1));
        true_block.instructions.push(MirInst::Copy {
            dst: VReg(1),
            src: MirValue::Const(1),
        });
        true_block.terminator = MirInst::Return {
            val: Some(MirValue::VReg(VReg(1))),
        };

        // False block: return 0
        let mut false_block = BasicBlock::new(BlockId(2));
        false_block.instructions.push(MirInst::Copy {
            dst: VReg(2),
            src: MirValue::Const(0),
        });
        false_block.terminator = MirInst::Return {
            val: Some(MirValue::VReg(VReg(2))),
        };

        func.blocks.push(entry);
        func.blocks.push(true_block);
        func.blocks.push(false_block);
        func.vreg_count = 3;

        let program = MirProgram {
            main: func,
            subfunctions: vec![],
        };

        let result = compile_mir_to_ebpf(&program, None).unwrap();
        assert!(
            !result.bytecode.is_empty(),
            "MIR branch compile produced empty bytecode"
        );
    }
}
