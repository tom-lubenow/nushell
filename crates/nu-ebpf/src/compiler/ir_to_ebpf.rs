//! IR to eBPF compiler
//!
//! Compiles Nushell's IR (IrBlock) to eBPF bytecode.

use std::collections::HashMap;

use nu_protocol::ast::{Bits, Comparison, Math, Operator};
use nu_protocol::engine::EngineState;
use nu_protocol::ir::{Instruction, IrBlock, Literal};
use nu_protocol::{DeclId, RegId, VarId};

use super::CompileError;
use super::elf::{BpfFieldType, BpfMapDef, EbpfMap, EventSchema, MapRelocation};
use super::helpers::{
    AggregationHelpers, DataHelpers, FilterHelpers, OutputHelpers, TimingHelpers,
};
use super::instruction::{BpfHelper, EbpfBuilder, EbpfInsn, EbpfReg, opcode};
use super::register_alloc::{AllocAction, RegAction, RegisterAllocator, ValueKey};

/// Result of compiling IR to eBPF
pub struct CompileResult {
    /// The compiled bytecode
    pub bytecode: Vec<u8>,
    /// Maps needed by the program
    pub maps: Vec<EbpfMap>,
    /// Relocations for map references
    pub relocations: Vec<MapRelocation>,
    /// Optional schema for structured events
    pub event_schema: Option<EventSchema>,
}

/// Name of the perf event array map for output
pub(crate) const PERF_MAP_NAME: &str = "events";

/// Name of the counter hash map for bpf-count
pub(crate) const COUNTER_MAP_NAME: &str = "counters";

/// Name of the timestamp hash map for bpf-start-timer/bpf-stop-timer
pub(crate) const TIMESTAMP_MAP_NAME: &str = "timestamps";

/// Name of the histogram hash map for bpf-histogram
pub(crate) const HISTOGRAM_MAP_NAME: &str = "histogram";

/// Maximum eBPF stack size in bytes (kernel limit)
/// Stack grows downward from R10, so this is the most negative offset allowed
const BPF_STACK_LIMIT: i16 = -512;

/// Architecture-specific pt_regs offsets for function arguments
///
/// These are the byte offsets into struct pt_regs where each function
/// argument register is stored.
#[cfg(target_arch = "x86_64")]
pub(crate) mod pt_regs_offsets {
    /// Offsets for arguments 0-5 (rdi, rsi, rdx, rcx, r8, r9)
    pub const ARG_OFFSETS: [i16; 6] = [
        112, // arg0: rdi
        104, // arg1: rsi
        96,  // arg2: rdx
        88,  // arg3: rcx
        72,  // arg4: r8
        64,  // arg5: r9
    ];
    /// Offset for return value (rax)
    pub const RETVAL_OFFSET: i16 = 80;
}

#[cfg(target_arch = "aarch64")]
pub(crate) mod pt_regs_offsets {
    /// Offsets for arguments 0-7 (x0-x7, each 8 bytes)
    pub const ARG_OFFSETS: [i16; 8] = [
        0,  // arg0: x0
        8,  // arg1: x1
        16, // arg2: x2
        24, // arg3: x3
        32, // arg4: x4
        40, // arg5: x5
        48, // arg6: x6
        56, // arg7: x7
    ];
    /// Offset for return value (x0)
    pub const RETVAL_OFFSET: i16 = 0;
}

// Fallback for unsupported architectures (compilation will fail at runtime)
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub(crate) mod pt_regs_offsets {
    pub const ARG_OFFSETS: [i16; 6] = [0; 6];
    pub const RETVAL_OFFSET: i16 = 0;
}


/// Pending jump that needs to be fixed up (for IR-level branches)
struct PendingJump {
    /// Index in builder where the jump instruction is
    ebpf_insn_idx: usize,
    /// Target IR instruction index
    target_ir_idx: usize,
}

/// Pending internal jump that needs to be fixed up (for intra-function jumps)
struct PendingInternalJump {
    /// Index in builder where the jump instruction is
    ebpf_insn_idx: usize,
    /// Label ID this jump targets
    target_label: usize,
}

/// Tracks a field being built in a record
#[derive(Debug, Clone)]
pub(crate) struct RecordFieldBuilder {
    /// Field name
    pub name: String,
    /// Stack offset where the field value is stored (relative to R10)
    pub stack_offset: i16,
    /// Type of the field (determined from how the value was computed)
    pub field_type: BpfFieldType,
}

/// Tracks a record being built
#[derive(Debug, Clone, Default)]
pub(crate) struct RecordBuilder {
    /// Fields in the order they were inserted
    pub fields: Vec<RecordFieldBuilder>,
    /// Base stack offset for this record (relative to R10)
    pub base_offset: i16,
}

/// Compiles Nushell IR to eBPF bytecode
pub struct IrToEbpfCompiler<'a> {
    ir_block: &'a IrBlock,
    engine_state: &'a EngineState,
    builder: EbpfBuilder,
    reg_alloc: RegisterAllocator,
    /// Maps IR instruction index -> eBPF instruction index
    ir_to_ebpf: HashMap<usize, usize>,
    /// Pending jumps to fix up
    pending_jumps: Vec<PendingJump>,
    /// Whether the program needs a perf event map for output
    needs_perf_map: bool,
    /// Whether the program needs a counter hash map
    needs_counter_map: bool,
    /// Whether the program needs a timestamp hash map for latency tracking
    needs_timestamp_map: bool,
    /// Whether the program needs a histogram hash map
    needs_histogram_map: bool,
    /// Relocations for map references
    relocations: Vec<MapRelocation>,
    /// Current stack offset for temporary storage (grows negative from R10)
    stack_offset: i16,
    /// We need to save R1 (context) at the start if we use bpf-emit
    ctx_saved: bool,
    /// Pushed positional arguments for the next call (register IDs)
    pushed_args: Vec<RegId>,
    /// Track literal integer values loaded into registers (for compile-time constants)
    literal_values: HashMap<u32, i64>,
    /// Track literal string values loaded into registers (for field names)
    literal_strings: HashMap<u32, String>,
    /// Track records being built (RegId -> RecordBuilder)
    record_builders: HashMap<u32, RecordBuilder>,
    /// Track the type of value produced by each register (for schema inference)
    register_types: HashMap<u32, BpfFieldType>,
    /// The event schema if structured events are used
    event_schema: Option<EventSchema>,
    /// Pending internal jumps to fix up (for intra-function control flow)
    pending_internal_jumps: Vec<PendingInternalJump>,
    /// Resolved label positions (label ID -> eBPF instruction index)
    label_positions: HashMap<usize, usize>,
    /// Next available label ID
    next_label: usize,
}

impl<'a> IrToEbpfCompiler<'a> {
    /// Compile an IrBlock to eBPF bytecode (simple version, ignores maps)
    pub fn compile(
        ir_block: &'a IrBlock,
        engine_state: &'a EngineState,
    ) -> Result<Vec<u8>, CompileError> {
        let result = Self::compile_full(ir_block, engine_state)?;
        Ok(result.bytecode)
    }

    /// Compile an IrBlock to eBPF bytecode with full result including maps
    pub fn compile_full(
        ir_block: &'a IrBlock,
        engine_state: &'a EngineState,
    ) -> Result<CompileResult, CompileError> {
        Self::compile_inner(ir_block, Some(engine_state))
    }

    /// Compile without engine state (for tests, will fail on Call instructions)
    #[cfg(test)]
    pub fn compile_no_calls(ir_block: &'a IrBlock) -> Result<Vec<u8>, CompileError> {
        let result = Self::compile_inner(ir_block, None)?;
        Ok(result.bytecode)
    }

    fn compile_inner(
        ir_block: &'a IrBlock,
        engine_state: Option<&'a EngineState>,
    ) -> Result<CompileResult, CompileError> {
        // Create a dummy engine state for when we don't have one
        // This will only be accessed if there's a Call instruction
        static DUMMY: std::sync::OnceLock<EngineState> = std::sync::OnceLock::new();
        let dummy_state = DUMMY.get_or_init(EngineState::new);
        let engine_state = engine_state.unwrap_or(dummy_state);

        let mut compiler = IrToEbpfCompiler {
            ir_block,
            engine_state,
            builder: EbpfBuilder::new(),
            reg_alloc: RegisterAllocator::new(),
            ir_to_ebpf: HashMap::new(),
            pending_jumps: Vec::new(),
            needs_perf_map: false,
            needs_counter_map: false,
            needs_timestamp_map: false,
            needs_histogram_map: false,
            relocations: Vec::new(),
            stack_offset: -8, // Start at -8 from R10
            ctx_saved: false,
            pushed_args: Vec::new(),
            literal_values: HashMap::new(),
            literal_strings: HashMap::new(),
            record_builders: HashMap::new(),
            register_types: HashMap::new(),
            event_schema: None,
            pending_internal_jumps: Vec::new(),
            label_positions: HashMap::new(),
            next_label: 0,
        };

        // Save the context pointer (R1) to R9 at the start
        // This is needed for bpf_perf_event_output which requires the context
        // R1 gets clobbered by helper calls, so we save it in a callee-saved register
        compiler
            .builder
            .push(EbpfInsn::mov64_reg(EbpfReg::R9, EbpfReg::R1));
        compiler.ctx_saved = true;

        // Compile each instruction, tracking IR->eBPF index mapping
        for (idx, instr) in ir_block.instructions.iter().enumerate() {
            // Record the eBPF instruction index before compiling this IR instruction
            compiler.ir_to_ebpf.insert(idx, compiler.builder.len());
            compiler.compile_instruction(instr, idx)?;
        }
        // Record end position for jumps targeting past the last instruction
        compiler
            .ir_to_ebpf
            .insert(ir_block.instructions.len(), compiler.builder.len());

        // Fix up pending jumps (IR-level and internal)
        compiler.fixup_jumps()?;
        compiler.fixup_internal_jumps()?;

        // Ensure we have an exit instruction
        if compiler.builder.is_empty() {
            // Empty program - just return 0
            compiler.builder.push(EbpfInsn::mov64_imm(EbpfReg::R0, 0));
            compiler.builder.push(EbpfInsn::exit());
        }

        // Build the result
        let mut maps = Vec::new();
        if compiler.needs_perf_map {
            maps.push(EbpfMap {
                name: PERF_MAP_NAME.to_string(),
                def: BpfMapDef::perf_event_array(),
            });
        }
        if compiler.needs_counter_map {
            maps.push(EbpfMap {
                name: COUNTER_MAP_NAME.to_string(),
                def: BpfMapDef::counter_hash(),
            });
        }
        if compiler.needs_timestamp_map {
            maps.push(EbpfMap {
                name: TIMESTAMP_MAP_NAME.to_string(),
                def: BpfMapDef::timestamp_hash(),
            });
        }
        if compiler.needs_histogram_map {
            maps.push(EbpfMap {
                name: HISTOGRAM_MAP_NAME.to_string(),
                def: BpfMapDef::histogram_hash(),
            });
        }

        Ok(CompileResult {
            bytecode: compiler.builder.build(),
            maps,
            relocations: compiler.relocations,
            event_schema: compiler.event_schema,
        })
    }

    /// Fix up pending jump instructions with correct offsets
    fn fixup_jumps(&mut self) -> Result<(), CompileError> {
        for jump in &self.pending_jumps {
            let target_ebpf_idx = self.ir_to_ebpf.get(&jump.target_ir_idx).ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "Invalid jump target: IR instruction {}",
                    jump.target_ir_idx
                ))
            })?;

            // eBPF jump offset is relative to the NEXT instruction
            // offset = target - (current + 1)
            let offset = (*target_ebpf_idx as i32) - (jump.ebpf_insn_idx as i32) - 1;

            if offset < i16::MIN as i32 || offset > i16::MAX as i32 {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "Jump offset {} out of range",
                    offset
                )));
            }

            self.builder.set_offset(jump.ebpf_insn_idx, offset as i16);
        }
        Ok(())
    }

    /// Fix up all pending internal jumps
    fn fixup_internal_jumps(&mut self) -> Result<(), CompileError> {
        for jump in &self.pending_internal_jumps {
            let target_idx = self
                .label_positions
                .get(&jump.target_label)
                .ok_or_else(|| {
                    CompileError::UnsupportedInstruction(format!(
                        "Unresolved label {}",
                        jump.target_label
                    ))
                })?;

            // eBPF jump offset is relative to the NEXT instruction
            let offset = (*target_idx as i32) - (jump.ebpf_insn_idx as i32) - 1;

            if offset < i16::MIN as i32 || offset > i16::MAX as i32 {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "Internal jump offset {} out of range",
                    offset
                )));
            }

            self.builder.set_offset(jump.ebpf_insn_idx, offset as i16);
        }
        self.pending_internal_jumps.clear();
        self.label_positions.clear();
        Ok(())
    }

    // ==================== Register Allocation Helpers ====================
    //
    // These methods handle spilling registers to stack when we run out,
    // and reloading spilled values when they're needed again.

    /// Ensure a Nushell variable's value is in an eBPF register (reload if spilled)
    fn ensure_var(&mut self, var_id: VarId) -> Result<EbpfReg, CompileError> {
        // Check if the value is spilled and needs reload
        if let Some(stack_offset) = self.reg_alloc.var_needs_reload(var_id) {
            // Need to reload - first get a register (may cause another spill)
            let target_reg = self.alloc_reg_for_write_internal(ValueKey::Var(var_id.get()))?;
            // Emit the load instruction
            self.builder
                .push(EbpfInsn::ldxdw(target_reg, EbpfReg::R10, stack_offset));
            self.reg_alloc
                .complete_reload(ValueKey::Var(var_id.get()), target_reg);
            return Ok(target_reg);
        }

        // Value is already in a register
        match self.reg_alloc.get_var(var_id)? {
            RegAction::Ready(r) => Ok(r),
            RegAction::Reload { .. } => unreachable!("Already handled above"),
        }
    }

    /// Get a register for writing to a Nushell variable (may spill another value)
    fn alloc_var(&mut self, var_id: VarId) -> Result<EbpfReg, CompileError> {
        self.alloc_reg_for_write_internal(ValueKey::Var(var_id.get()))
    }

    /// Internal helper to allocate a register for writing, handling spills
    fn alloc_reg_for_write_internal(&mut self, key: ValueKey) -> Result<EbpfReg, CompileError> {
        let action = match key {
            ValueKey::Reg(id) => self.reg_alloc.get_or_alloc(RegId::new(id))?,
            ValueKey::Var(id) => self.reg_alloc.get_or_alloc_var(VarId::new(id))?,
        };

        match action {
            AllocAction::Free(reg) => Ok(reg),
            AllocAction::Spill {
                reg, victim_key, ..
            } => {
                // Need to spill the victim to stack
                let spill_offset = self.alloc_stack_internal(8)?;
                // Emit the store instruction
                self.builder
                    .push(EbpfInsn::stxdw(EbpfReg::R10, spill_offset, reg));
                // Complete the spill in the allocator
                self.reg_alloc
                    .complete_spill(victim_key, reg, spill_offset, key);
                Ok(reg)
            }
        }
    }

    // ==================== Accessor Methods for Helper Modules ====================
    //
    // These methods expose internal state to the helper modules while keeping
    // the fields private. This allows helpers to be in separate files.

    /// Get mutable access to the instruction builder
    pub(crate) fn builder(&mut self) -> &mut EbpfBuilder {
        &mut self.builder
    }

    /// Set that the program needs a perf event map
    pub(crate) fn set_needs_perf_map(&mut self, value: bool) {
        self.needs_perf_map = value;
    }

    /// Set that the program needs a counter map
    pub(crate) fn set_needs_counter_map(&mut self, value: bool) {
        self.needs_counter_map = value;
    }

    /// Set that the program needs a timestamp map
    pub(crate) fn set_needs_timestamp_map(&mut self, value: bool) {
        self.needs_timestamp_map = value;
    }

    /// Set that the program needs a histogram map
    pub(crate) fn set_needs_histogram_map(&mut self, value: bool) {
        self.needs_histogram_map = value;
    }

    /// Add a map relocation
    pub(crate) fn add_relocation(&mut self, relocation: MapRelocation) {
        self.relocations.push(relocation);
    }

    /// Get the current stack offset
    pub(crate) fn current_stack_offset(&self) -> i16 {
        self.stack_offset
    }

    /// Advance the stack offset (for manual allocation)
    pub(crate) fn advance_stack_offset(&mut self, amount: i16) {
        self.stack_offset -= amount;
    }

    /// Pop a pushed argument
    pub(crate) fn pop_pushed_arg(&mut self) -> Option<RegId> {
        self.pushed_args.pop()
    }

    /// Get a literal value for a register
    pub(crate) fn get_literal_value(&self, reg: RegId) -> Option<i64> {
        self.literal_values.get(&reg.get()).copied()
    }

    /// Set the type of a register
    pub(crate) fn set_register_type(&mut self, reg: RegId, field_type: BpfFieldType) {
        self.register_types.insert(reg.get(), field_type);
    }

    /// Take the record builder for a register (removes it)
    pub(crate) fn take_record_builder(&mut self, reg: RegId) -> Option<RecordBuilder> {
        self.record_builders.remove(&reg.get())
    }

    /// Set the event schema
    pub(crate) fn set_event_schema(&mut self, schema: Option<EventSchema>) {
        self.event_schema = schema;
    }

    /// Emit a 64-bit immediate load (uses two instruction slots) - exposed for helpers
    pub(crate) fn emit_load_64bit_imm(&mut self, dst: EbpfReg, val: i64) {
        // LD_DW_IMM uses two 8-byte slots
        // First slot: opcode + lower 32 bits in imm
        // Second slot: upper 32 bits in imm
        let lower = val as i32;
        let upper = (val >> 32) as i32;

        self.builder
            .push(EbpfInsn::new(opcode::LD_DW_IMM, dst.as_u8(), 0, 0, lower));
        // Second instruction slot (pseudo-instruction)
        self.builder.push(EbpfInsn::new(0, 0, 0, 0, upper));
    }

    /// Create a new label and return its ID - exposed for helpers
    pub(crate) fn create_label(&mut self) -> usize {
        let label = self.next_label;
        self.next_label += 1;
        label
    }

    /// Mark the current position as the target of a label - exposed for helpers
    pub(crate) fn bind_label(&mut self, label: usize) {
        self.label_positions.insert(label, self.builder.len());
    }

    /// Emit a conditional jump to a label (offset will be fixed up later) - exposed for helpers
    pub(crate) fn emit_jump_if_zero_to_label(&mut self, reg: EbpfReg, label: usize) {
        let insn_idx = self.builder.len();
        self.builder.push(EbpfInsn::jeq_imm(reg, 0, 0)); // placeholder offset
        self.pending_internal_jumps.push(PendingInternalJump {
            ebpf_insn_idx: insn_idx,
            target_label: label,
        });
    }

    /// Emit a conditional jump if value <= 0 (signed) to a label - exposed for helpers
    pub(crate) fn emit_jump_if_le_zero_to_label(&mut self, reg: EbpfReg, label: usize) {
        let insn_idx = self.builder.len();
        self.builder.push(EbpfInsn::new(
            opcode::BPF_JMP | opcode::BPF_JSLE | opcode::BPF_K,
            reg.as_u8(),
            0,
            0, // placeholder offset
            0,
        ));
        self.pending_internal_jumps.push(PendingInternalJump {
            ebpf_insn_idx: insn_idx,
            target_label: label,
        });
    }

    /// Emit an unconditional jump to a label - exposed for helpers
    pub(crate) fn emit_jump_to_label(&mut self, label: usize) {
        let insn_idx = self.builder.len();
        self.builder.push(EbpfInsn::jump(0)); // placeholder offset
        self.pending_internal_jumps.push(PendingInternalJump {
            ebpf_insn_idx: insn_idx,
            target_label: label,
        });
    }

    // Make register allocation methods pub(crate) for helpers
    pub(crate) fn ensure_reg(&mut self, reg: RegId) -> Result<EbpfReg, CompileError> {
        self.ensure_reg_internal(reg)
    }

    pub(crate) fn alloc_reg(&mut self, reg: RegId) -> Result<EbpfReg, CompileError> {
        self.alloc_reg_for_write_internal(ValueKey::Reg(reg.get()))
    }

    pub(crate) fn alloc_stack(&mut self, size: i16) -> Result<i16, CompileError> {
        self.alloc_stack_internal(size)
    }

    pub(crate) fn check_stack_space(&self, needed: i16) -> Result<(), CompileError> {
        self.check_stack_space_internal(needed)
    }

    // Renamed internal methods to avoid conflicts
    fn ensure_reg_internal(&mut self, reg: RegId) -> Result<EbpfReg, CompileError> {
        // Check if the value is spilled and needs reload
        if let Some(stack_offset) = self.reg_alloc.needs_reload(reg) {
            // Need to reload - first get a register (may cause another spill)
            let target_reg = self.alloc_reg_for_write_internal(ValueKey::Reg(reg.get()))?;
            // Emit the load instruction
            self.builder
                .push(EbpfInsn::ldxdw(target_reg, EbpfReg::R10, stack_offset));
            self.reg_alloc
                .complete_reload(ValueKey::Reg(reg.get()), target_reg);
            return Ok(target_reg);
        }

        // Value is already in a register
        match self.reg_alloc.get(reg)? {
            RegAction::Ready(r) => Ok(r),
            RegAction::Reload { .. } => unreachable!("Already handled above"),
        }
    }

    fn alloc_stack_internal(&mut self, size: i16) -> Result<i16, CompileError> {
        let new_offset = self.stack_offset - size;
        if new_offset < BPF_STACK_LIMIT {
            return Err(CompileError::StackOverflow);
        }
        self.stack_offset = new_offset;
        Ok(new_offset)
    }

    fn check_stack_space_internal(&self, needed: i16) -> Result<(), CompileError> {
        if self.stack_offset - needed < BPF_STACK_LIMIT {
            return Err(CompileError::StackOverflow);
        }
        Ok(())
    }

    fn compile_instruction(
        &mut self,
        instr: &Instruction,
        _idx: usize,
    ) -> Result<(), CompileError> {
        match instr {
            Instruction::LoadLiteral { dst, lit } => self.compile_load_literal(*dst, lit),
            Instruction::Move { dst, src } => self.compile_move(*dst, *src),
            Instruction::Clone { dst, src } => {
                // Clone is same as Move for our purposes (we don't track lifetimes)
                self.compile_move(*dst, *src)
            }
            Instruction::BinaryOp { lhs_dst, op, rhs } => {
                self.compile_binary_op(*lhs_dst, op, *rhs)
            }
            Instruction::Return { src } => self.compile_return(*src),
            Instruction::LoadVariable { dst, var_id } => self.compile_load_variable(*dst, *var_id),
            Instruction::StoreVariable { var_id, src } => {
                self.compile_store_variable(*var_id, *src)
            }
            Instruction::DropVariable { .. } => {
                // No-op in eBPF - we don't need to clean up
                Ok(())
            }
            Instruction::Not { src_dst } => self.compile_not(*src_dst),
            Instruction::BranchIf { cond, index } => self.compile_branch_if(*cond, *index as usize),
            Instruction::Jump { index } => self.compile_jump(*index as usize),
            Instruction::Call { decl_id, src_dst } => self.compile_call(*decl_id, *src_dst),
            // Instructions we can safely ignore for simple closures
            Instruction::Span { .. } => Ok(()),
            Instruction::PushPositional { src } => {
                // Track pushed argument for filter commands
                self.pushed_args.push(*src);
                Ok(())
            }
            Instruction::RedirectOut { .. } => Ok(()),
            Instruction::RedirectErr { .. } => Ok(()),
            Instruction::Drop { .. } => Ok(()),
            Instruction::Drain { .. } => Ok(()),
            Instruction::DrainIfEnd { .. } => Ok(()),
            Instruction::Collect { .. } => Ok(()),
            Instruction::RecordInsert { src_dst, key, val } => {
                self.compile_record_insert(*src_dst, *key, *val)
            }
            // Unsupported instructions
            other => Err(CompileError::UnsupportedInstruction(format!("{:?}", other))),
        }
    }

    fn compile_load_literal(&mut self, dst: RegId, lit: &Literal) -> Result<(), CompileError> {
        let ebpf_dst = self.alloc_reg(dst)?;

        match lit {
            Literal::Int(val) => {
                // Track the literal value for commands that need compile-time constants
                self.literal_values.insert(dst.get(), *val);

                // Check if value fits in i32 immediate
                if *val >= i32::MIN as i64 && *val <= i32::MAX as i64 {
                    self.builder
                        .push(EbpfInsn::mov64_imm(ebpf_dst, *val as i32));
                } else {
                    // For 64-bit values, we need LD_DW_IMM (two instruction slots)
                    self.emit_load_64bit_imm(ebpf_dst, *val);
                }
                Ok(())
            }
            Literal::Bool(b) => {
                self.builder
                    .push(EbpfInsn::mov64_imm(ebpf_dst, if *b { 1 } else { 0 }));
                Ok(())
            }
            Literal::Nothing => {
                // Nothing is represented as 0
                self.builder.push(EbpfInsn::mov64_imm(ebpf_dst, 0));
                Ok(())
            }
            Literal::String(data_slice) => {
                // Get the string data from the IrBlock's data buffer
                let start = data_slice.start as usize;
                let end = start + data_slice.len as usize;
                let string_bytes = &self.ir_block.data[start..end];

                // Track the string value for field names in records
                if let Ok(s) = std::str::from_utf8(string_bytes) {
                    self.literal_strings.insert(dst.get(), s.to_string());
                }

                // Convert first 8 bytes of string to i64 for comparison
                // This matches how bpf-comm encodes process names
                let mut arr = [0u8; 8];
                let len = string_bytes.len().min(8);
                arr[..len].copy_from_slice(&string_bytes[..len]);
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
                    base_offset: self.stack_offset, // Will be updated as fields are added
                };
                self.record_builders.insert(dst.get(), record_builder);
                // Records in eBPF are represented as 0 (a placeholder)
                self.builder.push(EbpfInsn::mov64_imm(ebpf_dst, 0));
                Ok(())
            }
            _ => Err(CompileError::UnsupportedLiteral),
        }
    }

    fn compile_move(&mut self, dst: RegId, src: RegId) -> Result<(), CompileError> {
        let ebpf_src = self.ensure_reg(src)?;
        let ebpf_dst = self.alloc_reg(dst)?;

        if ebpf_src.as_u8() != ebpf_dst.as_u8() {
            self.builder.push(EbpfInsn::mov64_reg(ebpf_dst, ebpf_src));
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
                    self.builder.push(EbpfInsn::add64_reg(ebpf_lhs, ebpf_rhs));
                }
                Math::Subtract => {
                    self.builder.push(EbpfInsn::sub64_reg(ebpf_lhs, ebpf_rhs));
                }
                Math::Multiply => {
                    self.builder.push(EbpfInsn::mul64_reg(ebpf_lhs, ebpf_rhs));
                }
                Math::Divide | Math::FloorDivide => {
                    self.builder.push(EbpfInsn::div64_reg(ebpf_lhs, ebpf_rhs));
                }
                Math::Modulo => {
                    self.builder.push(EbpfInsn::mod64_reg(ebpf_lhs, ebpf_rhs));
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
                    self.builder.push(EbpfInsn::or64_reg(ebpf_lhs, ebpf_rhs));
                }
                Bits::BitAnd => {
                    self.builder.push(EbpfInsn::and64_reg(ebpf_lhs, ebpf_rhs));
                }
                Bits::BitXor => {
                    self.builder.push(EbpfInsn::xor64_reg(ebpf_lhs, ebpf_rhs));
                }
                Bits::ShiftLeft => {
                    self.builder.push(EbpfInsn::lsh64_reg(ebpf_lhs, ebpf_rhs));
                }
                Bits::ShiftRight => {
                    self.builder.push(EbpfInsn::rsh64_reg(ebpf_lhs, ebpf_rhs));
                }
            },
            // Comparison operations - result is 0 or 1
            Operator::Comparison(cmp) => {
                self.compile_comparison(ebpf_lhs, cmp, ebpf_rhs)?;
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
        self.builder.push(EbpfInsn::mov64_reg(temp, lhs));
        self.builder.push(EbpfInsn::mov64_imm(lhs, 0)); // Assume false

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
        self.builder.push(EbpfInsn::new(
            jump_opcode,
            temp.as_u8(),
            rhs.as_u8(),
            1, // Skip 1 instruction
            0,
        ));

        // If we get here, condition was false, skip setting to 1
        self.builder.push(EbpfInsn::new(
            opcode::BPF_JMP | opcode::BPF_JA,
            0,
            0,
            1, // Skip 1 instruction
            0,
        ));

        // Set lhs = 1 (condition was true)
        self.builder.push(EbpfInsn::mov64_imm(lhs, 1));

        Ok(())
    }

    fn compile_return(&mut self, src: RegId) -> Result<(), CompileError> {
        let ebpf_src = self.ensure_reg(src)?;

        // Move result to R0 (return register) if not already there
        if ebpf_src.as_u8() != EbpfReg::R0.as_u8() {
            self.builder
                .push(EbpfInsn::mov64_reg(EbpfReg::R0, ebpf_src));
        }

        self.builder.push(EbpfInsn::exit());
        Ok(())
    }

    fn compile_store_variable(&mut self, var_id: VarId, src: RegId) -> Result<(), CompileError> {
        let ebpf_src = self.ensure_reg(src)?;
        let ebpf_var = self.alloc_var(var_id)?;

        // Copy the value to the variable's register
        if ebpf_src.as_u8() != ebpf_var.as_u8() {
            self.builder.push(EbpfInsn::mov64_reg(ebpf_var, ebpf_src));
        }
        Ok(())
    }

    fn compile_load_variable(&mut self, dst: RegId, var_id: VarId) -> Result<(), CompileError> {
        let ebpf_var = self.ensure_var(var_id)?;
        let ebpf_dst = self.alloc_reg(dst)?;

        // Copy from variable's register to destination
        if ebpf_var.as_u8() != ebpf_dst.as_u8() {
            self.builder.push(EbpfInsn::mov64_reg(ebpf_dst, ebpf_var));
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
        self.builder.push(EbpfInsn::jeq_imm(ebpf_reg, 0, 2));
        self.builder.push(EbpfInsn::mov64_imm(ebpf_reg, 0));
        self.builder.push(EbpfInsn::jump(1));
        self.builder.push(EbpfInsn::mov64_imm(ebpf_reg, 1));

        Ok(())
    }

    /// Compile conditional branch (branch if cond is truthy)
    fn compile_branch_if(&mut self, cond: RegId, target_ir_idx: usize) -> Result<(), CompileError> {
        let ebpf_cond = self.ensure_reg(cond)?;

        // Branch if cond != 0
        // We'll use JNE with imm=0, but eBPF JNE with imm requires BPF_K
        // Actually we need to compare against 0 - if non-zero, jump
        // Use: jeq cond, 0, +1; ja target
        // If cond == 0, skip the jump. Otherwise, jump.
        // But we want to jump if truthy, so:
        // jne cond, 0, target (jump if cond != 0)

        // eBPF doesn't have JNE with immediate in all verifiers, use JEQ to skip
        // Actually it does: BPF_JMP | BPF_JNE | BPF_K
        let jump_idx = self.builder.len();
        self.builder.push(EbpfInsn::new(
            opcode::BPF_JMP | opcode::BPF_JNE | opcode::BPF_K,
            ebpf_cond.as_u8(),
            0,
            0, // Placeholder offset - will be fixed up
            0, // Compare against 0
        ));

        // Record this jump for fixup
        self.pending_jumps.push(PendingJump {
            ebpf_insn_idx: jump_idx,
            target_ir_idx,
        });

        Ok(())
    }

    /// Compile unconditional jump
    fn compile_jump(&mut self, target_ir_idx: usize) -> Result<(), CompileError> {
        let jump_idx = self.builder.len();
        self.builder.push(EbpfInsn::jump(0)); // Placeholder offset

        // Record this jump for fixup
        self.pending_jumps.push(PendingJump {
            ebpf_insn_idx: jump_idx,
            target_ir_idx,
        });

        Ok(())
    }

    /// Compile a command call - maps known commands to BPF helpers
    ///
    /// This dispatches to the appropriate helper trait method based on command name.
    fn compile_call(&mut self, decl_id: DeclId, src_dst: RegId) -> Result<(), CompileError> {
        // Look up the command name
        let decl = self.engine_state.get_decl(decl_id);
        let cmd_name = decl.name();

        // Map known commands to BPF helpers (via extension traits)
        match cmd_name {
            // Data helpers (DataHelpers trait)
            "bpf-pid" | "bpf pid" => DataHelpers::compile_bpf_pid(self, src_dst),
            "bpf-tgid" | "bpf tgid" => DataHelpers::compile_bpf_tgid(self, src_dst),
            "bpf-uid" | "bpf uid" => DataHelpers::compile_bpf_uid(self, src_dst),
            "bpf-ktime" | "bpf ktime" => DataHelpers::compile_bpf_ktime(self, src_dst),
            "bpf-comm" | "bpf comm" => DataHelpers::compile_bpf_comm(self, src_dst),
            "bpf-arg" | "bpf arg" => DataHelpers::compile_bpf_arg(self, src_dst),
            "bpf-retval" | "bpf retval" => DataHelpers::compile_bpf_retval(self, src_dst),

            // Output helpers (OutputHelpers trait)
            "bpf-emit" | "bpf emit" => OutputHelpers::compile_bpf_emit(self, src_dst),
            "bpf-emit-comm" | "bpf emit-comm" => OutputHelpers::compile_bpf_emit_comm(self, src_dst),
            "bpf-read-str" | "bpf read-str" => {
                OutputHelpers::compile_bpf_read_str(self, src_dst, false)
            }
            "bpf-read-user-str" | "bpf read-user-str" => {
                OutputHelpers::compile_bpf_read_str(self, src_dst, true)
            }

            // Aggregation helpers (AggregationHelpers trait)
            "bpf-count" | "bpf count" => AggregationHelpers::compile_bpf_count(self, src_dst),
            "bpf-histogram" | "bpf histogram" => {
                AggregationHelpers::compile_bpf_histogram(self, src_dst)
            }

            // Timing helpers (TimingHelpers trait)
            "bpf-start-timer" | "bpf start-timer" => {
                TimingHelpers::compile_bpf_start_timer(self, src_dst)
            }
            "bpf-stop-timer" | "bpf stop-timer" => {
                TimingHelpers::compile_bpf_stop_timer(self, src_dst)
            }

            // Filter helpers (FilterHelpers trait)
            "bpf-filter-pid" | "bpf filter-pid" => FilterHelpers::compile_bpf_filter_pid(self),
            "bpf-filter-comm" | "bpf filter-comm" => FilterHelpers::compile_bpf_filter_comm(self),

            _ => Err(CompileError::UnsupportedInstruction(format!(
                "Call to unsupported command: {}",
                cmd_name
            ))),
        }
    }

    /// Compile RecordInsert: add a field to a record being built
    ///
    /// This immediately stores the field value to the stack to preserve it.
    fn compile_record_insert(
        &mut self,
        src_dst: RegId,
        key: RegId,
        val: RegId,
    ) -> Result<(), CompileError> {
        // Get the field name from the key register's literal string
        let field_name = self
            .literal_strings
            .get(&key.get())
            .cloned()
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "Record field name must be a literal string".into(),
                )
            })?;

        // Determine the field type from the value register
        let field_type = self
            .register_types
            .get(&val.get())
            .copied()
            .unwrap_or(BpfFieldType::Int);
        let field_size = field_type.size() as i16;

        // Get the eBPF register containing the value
        // Use alloc_reg in case the value comes from a literal that wasn't separately allocated
        let ebpf_val = self.alloc_reg(val)?;

        // Allocate stack space for this field and store immediately
        self.check_stack_space(field_size)?;
        let field_stack_offset = self.stack_offset - field_size;
        self.stack_offset -= field_size;

        // Store the value to the stack based on field type
        match field_type {
            BpfFieldType::Int => {
                self.builder
                    .push(EbpfInsn::stxdw(EbpfReg::R10, field_stack_offset, ebpf_val));
            }
            BpfFieldType::Comm => {
                // Store 8-byte value we have (first 8 bytes of comm)
                self.builder
                    .push(EbpfInsn::stxdw(EbpfReg::R10, field_stack_offset, ebpf_val));
                // Zero-fill remaining 8 bytes
                self.builder.push(EbpfInsn::mov64_imm(EbpfReg::R0, 0));
                self.builder.push(EbpfInsn::stxdw(
                    EbpfReg::R10,
                    field_stack_offset + 8,
                    EbpfReg::R0,
                ));
            }
            BpfFieldType::String => {
                // Store 8-byte value we have
                self.builder
                    .push(EbpfInsn::stxdw(EbpfReg::R10, field_stack_offset, ebpf_val));
                // Zero-fill remaining bytes (simplified)
                self.builder.push(EbpfInsn::mov64_imm(EbpfReg::R0, 0));
                for i in 1..16 {
                    self.builder.push(EbpfInsn::stxdw(
                        EbpfReg::R10,
                        field_stack_offset + (i * 8),
                        EbpfReg::R0,
                    ));
                }
            }
        }

        // Get or create the record builder for the destination register
        let record = self
            .record_builders
            .entry(src_dst.get())
            .or_insert_with(|| RecordBuilder {
                fields: Vec::new(),
                base_offset: field_stack_offset, // First field determines base
            });

        // Update base_offset if this is the first field
        if record.fields.is_empty() {
            record.base_offset = field_stack_offset;
        }

        // Add the field to the record
        record.fields.push(RecordFieldBuilder {
            name: field_name,
            stack_offset: field_stack_offset,
            field_type,
        });

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nu_protocol::ir::IrBlock;
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

    #[test]
    fn test_compile_return_zero() {
        let ir = make_ir_block(vec![
            Instruction::LoadLiteral {
                dst: RegId::new(0),
                lit: Literal::Int(0),
            },
            Instruction::Return { src: RegId::new(0) },
        ]);

        let bytecode = IrToEbpfCompiler::compile_no_calls(&ir).unwrap();
        // Should have: mov r6, 0; mov r0, r6; exit
        assert!(!bytecode.is_empty());
    }

    #[test]
    fn test_compile_add() {
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

        let bytecode = IrToEbpfCompiler::compile_no_calls(&ir).unwrap();
        assert!(!bytecode.is_empty());
    }
}
