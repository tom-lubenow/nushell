//! IR to eBPF compiler
//!
//! Compiles Nushell's IR (IrBlock) to eBPF bytecode.

use std::collections::HashMap;

use nu_protocol::ast::{Block, CellPath, PathMember};
use nu_protocol::engine::EngineState;
use nu_protocol::ir::{Instruction, IrBlock};
use nu_protocol::{DeclId, RegId, VarId};

use super::CompileError;
use super::elf::{BpfFieldType, BpfMapDef, EbpfMap, EventSchema, MapRelocation, ProbeContext};
use super::helpers::{AggregationHelpers, FilterHelpers, OutputHelpers, TimingHelpers};
use super::instruction::{BpfHelper, EbpfBuilder, EbpfInsn, EbpfReg, opcode};
use super::ir_ops::IrOps;
use super::register_alloc::{AllocAction, RegAction, RegisterAllocator, ValueKey};
use crate::kernel_btf::KernelBtf;

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

/// Name of the ring buffer map for output
pub(crate) const RINGBUF_MAP_NAME: &str = "events";

/// Name of the counter hash map for bpf-count (integer keys)
pub(crate) const COUNTER_MAP_NAME: &str = "counters";

/// Name of the string counter hash map for bpf-count (string keys like $ctx.comm)
pub(crate) const STRING_COUNTER_MAP_NAME: &str = "str_counters";

/// Name of the timestamp hash map for bpf-start-timer/bpf-stop-timer
pub(crate) const TIMESTAMP_MAP_NAME: &str = "timestamps";

/// Name of the histogram hash map for bpf-histogram
pub(crate) const HISTOGRAM_MAP_NAME: &str = "histogram";

/// Name of the kernel stack trace map
pub(crate) const KSTACK_MAP_NAME: &str = "kstacks";

/// Name of the user stack trace map
pub(crate) const USTACK_MAP_NAME: &str = "ustacks";

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

/// Tracks a string stored on the stack
///
/// Used for string types that don't fit in a register (comm, string literals, read-str results).
/// The register associated with this string holds a pointer to the stack location.
#[derive(Debug, Clone, Copy)]
pub(crate) struct StackString {
    /// Stack offset where the string is stored (relative to R10, negative)
    pub offset: i16,
    /// Size of the string in bytes (actual content, may be less than allocated)
    pub size: usize,
}

/// Tracks an iterator for bounded loops
///
/// Created from `Literal::Range` when all bounds are compile-time known integers.
/// Used by `Iterate` instruction to generate bounded eBPF loops.
#[derive(Debug, Clone, Copy)]
pub(crate) struct BoundedIterator {
    /// Current value (start) stored on stack
    pub current_offset: i16,
    /// End value (exclusive for half-open, inclusive for closed)
    pub end_value: i64,
    /// Step value
    pub step: i64,
    /// Whether the range is inclusive (..=) or exclusive (..)
    pub inclusive: bool,
}

/// Centralized metadata for a Nushell register
///
/// This consolidates all per-register state into a single struct to ensure
/// proper invalidation when registers are reused. When a register is written to,
/// all its metadata is cleared to prevent stale data bugs.
#[derive(Debug, Clone, Default)]
pub(crate) struct RegisterMetadata {
    /// Compile-time integer value (for constants used in Range bounds, etc.)
    pub literal_value: Option<i64>,
    /// Compile-time string value (for field names in records)
    pub literal_string: Option<String>,
    /// Record being built in this register
    pub record_builder: Option<RecordBuilder>,
    /// Type of value in this register (Int, Comm, String)
    pub field_type: Option<BpfFieldType>,
    /// Stack-based string info (for comm, string literals)
    pub stack_string: Option<StackString>,
    /// Whether this register holds the context parameter
    pub is_context: bool,
    /// Cell path literal (for field access like $ctx.pid)
    pub cell_path: Option<CellPath>,
    /// Bounded iterator info (for loop compilation)
    pub bounded_iterator: Option<BoundedIterator>,
    /// Loop header eBPF instruction index (for jump-back target)
    pub loop_header: Option<usize>,
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
    /// Whether the program needs a ring buffer map for output
    needs_ringbuf: bool,
    /// Whether the program needs a counter hash map (integer keys)
    needs_counter_map: bool,
    /// Whether the program needs a string counter hash map (for $ctx.comm keys)
    needs_string_counter_map: bool,
    /// Whether the program needs a timestamp hash map for latency tracking
    needs_timestamp_map: bool,
    /// Whether the program needs a histogram hash map
    needs_histogram_map: bool,
    /// Whether the program needs a kernel stack trace map
    needs_kstack_map: bool,
    /// Whether the program needs a user stack trace map
    needs_ustack_map: bool,
    /// Relocations for map references
    relocations: Vec<MapRelocation>,
    /// Current stack offset for temporary storage (grows negative from R10)
    stack_offset: i16,
    /// We need to save R1 (context) at the start if we use bpf-emit
    ctx_saved: bool,
    /// Pushed positional arguments for the next call (register IDs)
    pushed_args: Vec<RegId>,
    /// Centralized per-register metadata (literal values, types, strings, etc.)
    /// All metadata is invalidated when a register is written to, preventing stale data bugs.
    register_metadata: HashMap<u32, RegisterMetadata>,
    /// The event schema if structured events are used
    event_schema: Option<EventSchema>,
    /// Pending internal jumps to fix up (for intra-function control flow)
    pending_internal_jumps: Vec<PendingInternalJump>,
    /// Resolved label positions (label ID -> eBPF instruction index)
    label_positions: HashMap<usize, usize>,
    /// Next available label ID
    next_label: usize,
    /// The VarId of the closure's context parameter (if any)
    /// When a closure like `{|ctx| $ctx.pid }` is compiled, this tracks which VarId is `ctx`
    context_param_var_id: Option<VarId>,
    /// Captured variable values from the closure (for compile-time constant inlining)
    /// When a closure captures a variable like `let pid = 1234; {|| $pid }`,
    /// we can inline the value as a constant in the eBPF bytecode.
    captured_values: HashMap<usize, i64>,
    /// Probe context providing information about where this program will be attached
    /// Used for auto-detecting userspace vs kernel memory reads, validating retval access, etc.
    probe_context: ProbeContext,
    /// Track stack offsets for user variables (VarId -> stack offset)
    /// Variables are stored on stack to avoid register allocation issues with loops
    var_stack_offsets: HashMap<usize, i16>,
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
    ///
    /// Uses a default probe context (kprobe). For proper probe-aware compilation,
    /// use `compile_with_context` instead.
    pub fn compile_full(
        ir_block: &'a IrBlock,
        engine_state: &'a EngineState,
    ) -> Result<CompileResult, CompileError> {
        Self::compile_inner(
            ir_block,
            Some(engine_state),
            None,
            &[],
            ProbeContext::default_for_tests(),
        )
    }

    /// Compile an IrBlock with full context including probe information
    ///
    /// This is the recommended entry point that supports:
    /// - Closure context parameters (`{|ctx| $ctx.pid }`)
    /// - Captured variables from outer scope
    /// - Probe-aware compilation (auto-detect userspace vs kernel reads, validate retval)
    pub fn compile_with_context(
        ir_block: &'a IrBlock,
        engine_state: &'a EngineState,
        block: &Block,
        captures: &[(VarId, nu_protocol::Value)],
        probe_context: ProbeContext,
    ) -> Result<CompileResult, CompileError> {
        Self::compile_inner(
            ir_block,
            Some(engine_state),
            Some(block),
            captures,
            probe_context,
        )
    }

    /// Compile without engine state (for tests, will fail on Call instructions)
    #[cfg(test)]
    pub fn compile_no_calls(ir_block: &'a IrBlock) -> Result<Vec<u8>, CompileError> {
        let result =
            Self::compile_inner(ir_block, None, None, &[], ProbeContext::default_for_tests())?;
        Ok(result.bytecode)
    }

    fn compile_inner(
        ir_block: &'a IrBlock,
        engine_state: Option<&'a EngineState>,
        block: Option<&Block>,
        captures: &[(VarId, nu_protocol::Value)],
        probe_context: ProbeContext,
    ) -> Result<CompileResult, CompileError> {
        // Create a dummy engine state for when we don't have one
        // This will only be accessed if there's a Call instruction
        static DUMMY: std::sync::OnceLock<EngineState> = std::sync::OnceLock::new();
        let dummy_state = DUMMY.get_or_init(EngineState::new);
        let engine_state = engine_state.unwrap_or(dummy_state);

        // Extract the context parameter VarId from the block's signature
        // For closures like `{|ctx| $ctx.pid }`, this is the VarId of `ctx`
        let context_param_var_id = block.and_then(|b| {
            b.signature
                .required_positional
                .first()
                .and_then(|arg| arg.var_id)
        });

        // Extract integer values from captures for compile-time constant inlining
        let mut captured_values = HashMap::new();
        for (var_id, value) in captures {
            if let nu_protocol::Value::Int { val, .. } = value {
                captured_values.insert(var_id.get(), *val);
            }
        }

        let mut compiler = IrToEbpfCompiler {
            ir_block,
            engine_state,
            builder: EbpfBuilder::new(),
            reg_alloc: RegisterAllocator::new(),
            ir_to_ebpf: HashMap::new(),
            pending_jumps: Vec::new(),
            needs_ringbuf: false,
            needs_counter_map: false,
            needs_string_counter_map: false,
            needs_timestamp_map: false,
            needs_histogram_map: false,
            needs_kstack_map: false,
            needs_ustack_map: false,
            relocations: Vec::new(),
            stack_offset: -8, // Start at -8 from R10
            ctx_saved: false,
            pushed_args: Vec::new(),
            register_metadata: HashMap::new(),
            event_schema: None,
            pending_internal_jumps: Vec::new(),
            label_positions: HashMap::new(),
            next_label: 0,
            context_param_var_id,
            captured_values,
            probe_context,
            var_stack_offsets: HashMap::new(),
        };

        // Save the context pointer (R1) to R9 at the start
        // This is needed for bpf_perf_event_output which requires the context
        // R1 gets clobbered by helper calls, so we save it in a callee-saved register
        compiler
            .builder
            .push(EbpfInsn::mov64_reg(EbpfReg::R9, EbpfReg::R1));
        compiler.ctx_saved = true;

        // Pre-initialize callee-saved registers R6-R8 to 0
        // This ensures all registers have known values on all execution paths,
        // which is required by the BPF verifier. Without this, short-circuit
        // evaluation (like `or`) can leave registers uninitialized on some paths.
        compiler.builder.push(EbpfInsn::mov64_imm(EbpfReg::R6, 0));
        compiler.builder.push(EbpfInsn::mov64_imm(EbpfReg::R7, 0));
        compiler.builder.push(EbpfInsn::mov64_imm(EbpfReg::R8, 0));

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
        if compiler.needs_ringbuf {
            // 256KB ring buffer (must be power of 2)
            maps.push(EbpfMap {
                name: RINGBUF_MAP_NAME.to_string(),
                def: BpfMapDef::ring_buffer(256 * 1024),
            });
        }
        if compiler.needs_counter_map {
            maps.push(EbpfMap {
                name: COUNTER_MAP_NAME.to_string(),
                def: BpfMapDef::counter_hash(),
            });
        }
        if compiler.needs_string_counter_map {
            maps.push(EbpfMap {
                name: STRING_COUNTER_MAP_NAME.to_string(),
                def: BpfMapDef::string_counter_hash(),
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
        if compiler.needs_kstack_map {
            maps.push(EbpfMap {
                name: KSTACK_MAP_NAME.to_string(),
                def: BpfMapDef::stack_trace_map(),
            });
        }
        if compiler.needs_ustack_map {
            maps.push(EbpfMap {
                name: USTACK_MAP_NAME.to_string(),
                def: BpfMapDef::stack_trace_map(),
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
    //
    // Note: Variables are stored on stack (via var_stack_offsets), not in
    // eBPF registers. Only Nushell IR registers use the register allocator.

    /// Internal helper to allocate a register for writing, handling spills
    fn alloc_reg_for_write_internal(&mut self, reg: RegId) -> Result<EbpfReg, CompileError> {
        let action = self.reg_alloc.get_or_alloc(reg)?;

        match action {
            AllocAction::Free(ebpf_reg) => Ok(ebpf_reg),
            AllocAction::Spill {
                reg: ebpf_reg,
                victim_key,
            } => {
                // Need to spill the victim to stack
                let spill_offset = self.alloc_stack_internal(8)?;
                // Emit the store instruction
                self.builder
                    .push(EbpfInsn::stxdw(EbpfReg::R10, spill_offset, ebpf_reg));
                // Complete the spill in the allocator
                self.reg_alloc.complete_spill(
                    victim_key,
                    ebpf_reg,
                    spill_offset,
                    ValueKey::Reg(reg.get()),
                );
                Ok(ebpf_reg)
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

    /// Set that the program needs a ring buffer map
    pub(crate) fn set_needs_ringbuf(&mut self, value: bool) {
        self.needs_ringbuf = value;
    }

    /// Set that the program needs a counter map (integer keys)
    pub(crate) fn set_needs_counter_map(&mut self, value: bool) {
        self.needs_counter_map = value;
    }

    /// Set that the program needs a string counter map (for $ctx.comm keys)
    pub(crate) fn set_needs_string_counter_map(&mut self, value: bool) {
        self.needs_string_counter_map = value;
    }

    /// Set that the program needs a timestamp map
    pub(crate) fn set_needs_timestamp_map(&mut self, value: bool) {
        self.needs_timestamp_map = value;
    }

    /// Set that the program needs a histogram map
    pub(crate) fn set_needs_histogram_map(&mut self, value: bool) {
        self.needs_histogram_map = value;
    }

    /// Set that the program needs a kernel stack trace map
    pub(crate) fn set_needs_kstack_map(&mut self, value: bool) {
        self.needs_kstack_map = value;
    }

    /// Set that the program needs a user stack trace map
    pub(crate) fn set_needs_ustack_map(&mut self, value: bool) {
        self.needs_ustack_map = value;
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

    // ==================== Register Metadata Management ====================
    //
    // Centralized metadata management to prevent stale data bugs when registers
    // are reused. All metadata is stored in a single HashMap and invalidated
    // together when a register is written to.

    /// Invalidate all metadata for a register
    ///
    /// Called when a register is about to be written to, to ensure no stale
    /// metadata from previous uses affects compilation. This prevents bugs like
    /// nested loops inheriting incorrect step values from outer loop registers.
    pub(crate) fn invalidate_register(&mut self, reg: RegId) {
        self.register_metadata.remove(&reg.get());
    }

    /// Get or create metadata for a register
    fn get_or_create_metadata(&mut self, reg: RegId) -> &mut RegisterMetadata {
        self.register_metadata
            .entry(reg.get())
            .or_insert_with(RegisterMetadata::default)
    }

    /// Set the type of a register
    pub(crate) fn set_register_type(&mut self, reg: RegId, field_type: BpfFieldType) {
        self.get_or_create_metadata(reg).field_type = Some(field_type);
    }

    /// Take the record builder for a register (removes it from metadata)
    pub(crate) fn take_record_builder(&mut self, reg: RegId) -> Option<RecordBuilder> {
        self.register_metadata
            .get_mut(&reg.get())
            .and_then(|m| m.record_builder.take())
    }

    /// Set the event schema
    pub(crate) fn set_event_schema(&mut self, schema: Option<EventSchema>) {
        self.event_schema = schema;
    }

    /// Set a literal value for a register
    pub(crate) fn set_literal_value(&mut self, reg: RegId, value: i64) {
        self.get_or_create_metadata(reg).literal_value = Some(value);
    }

    /// Set a literal string for a register
    pub(crate) fn set_literal_string(&mut self, reg: RegId, value: String) {
        self.get_or_create_metadata(reg).literal_string = Some(value);
    }

    /// Set a literal cell path for a register
    pub(crate) fn set_literal_cell_path(&mut self, reg: RegId, path: CellPath) {
        self.get_or_create_metadata(reg).cell_path = Some(path);
    }

    /// Get a literal cell path for a register
    pub(crate) fn get_literal_cell_path(&self, reg: RegId) -> Option<&CellPath> {
        self.register_metadata
            .get(&reg.get())
            .and_then(|m| m.cell_path.as_ref())
    }

    /// Get a captured variable value (from closure captures)
    ///
    /// This allows inlining captured integer variables as compile-time constants.
    /// For example, `let pid = 1234; {|| $pid }` will return Some(1234) for $pid's VarId.
    pub(crate) fn get_captured_value(&self, var_id: VarId) -> Option<i64> {
        self.captured_values.get(&var_id.get()).copied()
    }

    /// Get a literal value for a register (if set)
    pub(crate) fn get_literal_value(&self, reg: RegId) -> Option<i64> {
        self.register_metadata
            .get(&reg.get())
            .and_then(|m| m.literal_value)
    }

    /// Set a bounded iterator for a stream register
    pub(crate) fn set_bounded_iterator(&mut self, reg: RegId, iter: BoundedIterator) {
        self.get_or_create_metadata(reg).bounded_iterator = Some(iter);
    }

    /// Get a bounded iterator for a stream register
    pub(crate) fn get_bounded_iterator(&self, reg: RegId) -> Option<BoundedIterator> {
        self.register_metadata
            .get(&reg.get())
            .and_then(|m| m.bounded_iterator)
    }

    /// Set the loop header position for a stream register
    pub(crate) fn set_loop_header(&mut self, reg: RegId, ebpf_idx: usize) {
        self.get_or_create_metadata(reg).loop_header = Some(ebpf_idx);
    }

    /// Get the loop header position for a stream register
    pub(crate) fn get_loop_header(&self, reg: RegId) -> Option<usize> {
        self.register_metadata
            .get(&reg.get())
            .and_then(|m| m.loop_header)
    }

    /// Get or allocate a stack slot for a user variable
    /// Variables are stored on stack to ensure they persist across loop iterations
    pub(crate) fn get_or_alloc_var_stack(&mut self, var_id: VarId) -> Result<i16, CompileError> {
        if let Some(&offset) = self.var_stack_offsets.get(&var_id.get()) {
            return Ok(offset);
        }
        let offset = self.alloc_stack(8)?;
        self.var_stack_offsets.insert(var_id.get(), offset);
        Ok(offset)
    }

    /// Get the stack offset for a user variable (if already allocated)
    pub(crate) fn get_var_stack(&self, var_id: VarId) -> Option<i16> {
        self.var_stack_offsets.get(&var_id.get()).copied()
    }

    /// Check if a VarId is the context parameter
    pub(crate) fn is_context_param(&self, var_id: VarId) -> bool {
        self.context_param_var_id == Some(var_id)
    }

    /// Mark a register as containing the context variable
    pub(crate) fn set_context_register(&mut self, reg: RegId, is_context: bool) {
        self.get_or_create_metadata(reg).is_context = is_context;
    }

    /// Check if a register contains the context variable
    pub(crate) fn is_context_register(&self, reg: RegId) -> bool {
        self.register_metadata
            .get(&reg.get())
            .map(|m| m.is_context)
            .unwrap_or(false)
    }

    /// Get a slice of the IR block's data buffer
    pub(crate) fn get_data_slice(&self, start: usize, len: usize) -> &[u8] {
        &self.ir_block.data[start..start + len]
    }

    /// Set a record builder for a register
    pub(crate) fn set_record_builder(&mut self, reg: RegId, builder: RecordBuilder) {
        self.get_or_create_metadata(reg).record_builder = Some(builder);
    }

    /// Track a stack-based string for a register
    pub(crate) fn set_stack_string(&mut self, reg: RegId, stack_str: StackString) {
        self.get_or_create_metadata(reg).stack_string = Some(stack_str);
    }

    /// Get the stack string info for a register (if it's a stack-based string)
    pub(crate) fn get_stack_string(&self, reg: RegId) -> Option<StackString> {
        self.register_metadata
            .get(&reg.get())
            .and_then(|m| m.stack_string)
    }

    /// Get the literal string for a register (if set)
    pub(crate) fn get_literal_string(&self, reg: RegId) -> Option<&String> {
        self.register_metadata
            .get(&reg.get())
            .and_then(|m| m.literal_string.as_ref())
    }

    /// Get the field type for a register (if set)
    pub(crate) fn get_register_type(&self, reg: RegId) -> Option<BpfFieldType> {
        self.register_metadata
            .get(&reg.get())
            .and_then(|m| m.field_type)
    }

    /// Store a string literal on the stack and return the StackString info
    ///
    /// The string is stored with a null terminator and 8-byte alignment.
    /// The size includes the null terminator for proper comparison semantics:
    /// - "nginx" stored as "nginx\0" (6 bytes) will only match "nginx\0..."
    /// - "nginx" will NOT match "nginxmaster" because byte 6 differs ('\0' vs 'm')
    pub(crate) fn store_string_literal_on_stack(
        &mut self,
        bytes: &[u8],
        dst_reg: EbpfReg,
    ) -> Result<StackString, CompileError> {
        // Include null terminator in the size for proper comparison
        let size_with_null = bytes.len() + 1;

        // Round up to 8-byte alignment for proper memory access
        let padded_size = ((size_with_null + 7) / 8) * 8;
        let padded_size_i16 = padded_size as i16;

        self.check_stack_space(padded_size_i16)?;
        let stack_offset = self.current_stack_offset() - padded_size_i16;
        self.advance_stack_offset(padded_size_i16);

        // Store the string bytes + null terminator, padded with zeros
        let mut padded = vec![0u8; padded_size];
        padded[..bytes.len()].copy_from_slice(bytes);
        // padded[bytes.len()] is already 0 (null terminator)
        // remaining bytes are already 0 (padding)

        for (i, chunk) in padded.chunks(8).enumerate() {
            let val = i64::from_le_bytes(chunk.try_into().unwrap());
            let chunk_offset = stack_offset + (i * 8) as i16;

            // Use 64-bit immediate load then store
            self.emit_load_64bit_imm(EbpfReg::R0, val);
            self.builder
                .push(EbpfInsn::stxdw(EbpfReg::R10, chunk_offset, EbpfReg::R0));
        }

        // Store pointer to the string in destination register
        self.builder
            .push(EbpfInsn::mov64_reg(dst_reg, EbpfReg::R10));
        self.builder
            .push(EbpfInsn::add64_imm(dst_reg, stack_offset as i32));

        Ok(StackString {
            offset: stack_offset,
            size: size_with_null, // Includes null terminator
        })
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
        self.alloc_reg_for_write_internal(reg)
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
            let target_reg = self.alloc_reg_for_write_internal(reg)?;
            // Emit the load instruction
            self.builder
                .push(EbpfInsn::ldxdw(target_reg, EbpfReg::R10, stack_offset));
            self.reg_alloc
                .complete_reload(ValueKey::Reg(reg.get()), target_reg);
            return Ok(target_reg);
        }

        // Value is already in a register
        let RegAction::Ready(r) = self.reg_alloc.get(reg)?;
        Ok(r)
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
            // IR operations (IrOps trait)
            Instruction::LoadLiteral { dst, lit } => IrOps::compile_load_literal(self, *dst, lit),
            Instruction::Move { dst, src } => IrOps::compile_move(self, *dst, *src),
            Instruction::Clone { dst, src } => {
                // Clone is same as Move for our purposes (we don't track lifetimes)
                IrOps::compile_move(self, *dst, *src)
            }
            Instruction::BinaryOp { lhs_dst, op, rhs } => {
                IrOps::compile_binary_op(self, *lhs_dst, op, *rhs)
            }
            Instruction::Return { src } => IrOps::compile_return(self, *src),
            Instruction::LoadVariable { dst, var_id } => {
                IrOps::compile_load_variable(self, *dst, *var_id)
            }
            Instruction::StoreVariable { var_id, src } => {
                IrOps::compile_store_variable(self, *var_id, *src)
            }
            Instruction::DropVariable { .. } => {
                // No-op in eBPF - we don't need to clean up
                Ok(())
            }
            Instruction::Not { src_dst } => IrOps::compile_not(self, *src_dst),

            // Control flow (local methods)
            Instruction::BranchIf { cond, index } => self.compile_branch_if(*cond, *index as usize),
            Instruction::Jump { index } => self.compile_jump(*index as usize),
            Instruction::Match {
                pattern,
                src,
                index,
            } => self.compile_match(pattern, *src, *index as usize),

            // Iteration (bounded loops)
            Instruction::Iterate {
                dst,
                stream,
                end_index,
            } => self.compile_iterate(*dst, *stream, *end_index as usize),

            // Command calls (dispatches to helper traits)
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

            // Records
            Instruction::RecordInsert { src_dst, key, val } => {
                self.compile_record_insert(*src_dst, *key, *val)
            }

            // Cell path access (for context parameter field access like $ctx.pid)
            Instruction::FollowCellPath { src_dst, path } => {
                self.compile_follow_cell_path(*src_dst, *path)
            }

            // Unsupported instructions
            other => Err(CompileError::UnsupportedInstruction(format!("{:?}", other))),
        }
    }

    /// Compile conditional branch (branch if cond is truthy)
    ///
    /// This implements proper conditional jumps for if/else expressions.
    /// The semantics are: if cond is truthy (non-zero), jump to target_ir_idx.
    ///
    /// Note: Nushell's IR uses `not` before `branch-if`, so:
    /// - cond == 0 means the ORIGINAL condition was TRUE (continue to if-body)
    /// - cond != 0 means the ORIGINAL condition was FALSE (jump to else/end)
    fn compile_branch_if(&mut self, cond: RegId, target_ir_idx: usize) -> Result<(), CompileError> {
        let ebpf_cond = self.ensure_reg(cond)?;

        // Nushell's `if` IR pattern is:
        //   compare -> not -> branch-if
        // So branch-if's cond is the INVERTED comparison result:
        // - cond == 0: original condition TRUE, don't jump (execute if-body)
        // - cond != 0: original condition FALSE, jump to target (else/end)
        //
        // We emit: JNE cond, 0, target (jump if cond != 0)

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

    /// Compile pattern match (for short-circuit boolean evaluation)
    ///
    /// This is used by `and` and `or` operators for short-circuit evaluation:
    /// - `and`: generates `match (false), src, target` - jump if src is false
    /// - `or`: generates `match (true), src, target` - jump if src is true
    fn compile_match(
        &mut self,
        pattern: &nu_protocol::ast::Pattern,
        src: RegId,
        target_ir_idx: usize,
    ) -> Result<(), CompileError> {
        use nu_protocol::ast::Pattern;

        let ebpf_src = self.ensure_reg(src)?;

        match pattern {
            Pattern::Value(value) => {
                if let nu_protocol::Value::Bool { val, .. } = value {
                    // For boolean short-circuit:
                    // - match (false), src, target: if src == 0, jump to target
                    // - match (true), src, target: if src != 0, jump to target
                    let jump_idx = self.builder.len();

                    if *val {
                        // Pattern is `true` - jump if src != 0
                        self.builder.push(EbpfInsn::new(
                            opcode::BPF_JMP | opcode::BPF_JNE | opcode::BPF_K,
                            ebpf_src.as_u8(),
                            0,
                            0, // Placeholder offset
                            0, // Compare against 0
                        ));
                    } else {
                        // Pattern is `false` - jump if src == 0
                        self.builder.push(EbpfInsn::new(
                            opcode::BPF_JMP | opcode::BPF_JEQ | opcode::BPF_K,
                            ebpf_src.as_u8(),
                            0,
                            0, // Placeholder offset
                            0, // Compare against 0
                        ));
                    }

                    // Record this jump for fixup
                    self.pending_jumps.push(PendingJump {
                        ebpf_insn_idx: jump_idx,
                        target_ir_idx,
                    });

                    Ok(())
                } else {
                    Err(CompileError::UnsupportedInstruction(format!(
                        "Match with non-boolean pattern value: {:?}",
                        value
                    )))
                }
            }
            _ => Err(CompileError::UnsupportedInstruction(format!(
                "Match with unsupported pattern type: {:?}",
                pattern
            ))),
        }
    }

    /// Compile Iterate instruction for bounded loops
    ///
    /// Implements eBPF bounded loops for ranges with compile-time known bounds.
    /// eBPF verifier requires bounded loops (kernel 5.3+), so we generate:
    ///
    /// ```text
    /// loop_header:
    ///   load current from stack
    ///   if current >= end (or > for inclusive): jump to end_index
    ///   store current to dst register
    ///   increment current on stack
    ///   ... loop body (following instructions) ...
    ///   jump back to loop_header (via Nushell's Jump instruction)
    /// end:
    /// ```
    fn compile_iterate(
        &mut self,
        dst: RegId,
        stream: RegId,
        end_index: usize,
    ) -> Result<(), CompileError> {
        // Get the bounded iterator info (set by compile_load_literal for Range)
        let iter = self.get_bounded_iterator(stream).ok_or_else(|| {
            CompileError::UnsupportedInstruction(
                "Iterate requires a compile-time known range (e.g., 1..10). \
                 Dynamic iterators are not supported in eBPF."
                    .into(),
            )
        })?;

        // Check if this is the first time we're executing this Iterate instruction
        // (vs a subsequent iteration via jump back)
        if self.get_loop_header(stream).is_none() {
            // First iteration - record the loop header position
            self.set_loop_header(stream, self.builder.len());
        }

        // Allocate destination register for the loop variable
        let ebpf_dst = self.alloc_reg(dst)?;

        // Load current value from stack
        self.builder
            .push(EbpfInsn::ldxdw(ebpf_dst, EbpfReg::R10, iter.current_offset));

        // Compare against end value and jump to end_index if done
        // For step > 0: current >= end (exclusive) or current > end (inclusive)
        // For step < 0: current <= end (exclusive) or current < end (inclusive)
        let end_val = iter.end_value;

        // Load end value into R0 for comparison
        if end_val >= i32::MIN as i64 && end_val <= i32::MAX as i64 {
            self.builder
                .push(EbpfInsn::mov64_imm(EbpfReg::R0, end_val as i32));
        } else {
            self.emit_load_64bit_imm(EbpfReg::R0, end_val);
        }

        // Emit jump to end_index if loop is complete
        // The jump offset will be fixed up later
        let jump_idx = self.builder.len();
        if iter.step > 0 {
            if iter.inclusive {
                // For 1..=10: continue while current <= end, so jump when current > end
                // JGT: jump if dst > R0
                self.builder.push(EbpfInsn::new(
                    opcode::BPF_JMP | opcode::BPF_JSGT | opcode::BPF_X,
                    ebpf_dst.as_u8(),
                    EbpfReg::R0.as_u8(),
                    0, // Placeholder offset
                    0,
                ));
            } else {
                // For 1..10: continue while current < end, so jump when current >= end
                // JSGE: jump if dst >= R0 (signed)
                self.builder.push(EbpfInsn::new(
                    opcode::BPF_JMP | opcode::BPF_JSGE | opcode::BPF_X,
                    ebpf_dst.as_u8(),
                    EbpfReg::R0.as_u8(),
                    0, // Placeholder offset
                    0,
                ));
            }
        } else {
            // Negative step (counting down)
            if iter.inclusive {
                // For 10..=1 step -1: continue while current >= end, so jump when current < end
                self.builder.push(EbpfInsn::new(
                    opcode::BPF_JMP | opcode::BPF_JSLT | opcode::BPF_X,
                    ebpf_dst.as_u8(),
                    EbpfReg::R0.as_u8(),
                    0, // Placeholder offset
                    0,
                ));
            } else {
                // For 10..1 step -1: continue while current > end, so jump when current <= end
                self.builder.push(EbpfInsn::new(
                    opcode::BPF_JMP | opcode::BPF_JSLE | opcode::BPF_X,
                    ebpf_dst.as_u8(),
                    EbpfReg::R0.as_u8(),
                    0, // Placeholder offset
                    0,
                ));
            }
        }

        // Record this jump for fixup
        self.pending_jumps.push(PendingJump {
            ebpf_insn_idx: jump_idx,
            target_ir_idx: end_index,
        });

        // Increment current value on stack for next iteration
        // current += step
        let step = iter.step;
        if step >= i32::MIN as i64 && step <= i32::MAX as i64 {
            self.builder
                .push(EbpfInsn::add64_imm(ebpf_dst, step as i32));
        } else {
            // 64-bit step (rare)
            self.emit_load_64bit_imm(EbpfReg::R0, step);
            self.builder
                .push(EbpfInsn::add64_reg(ebpf_dst, EbpfReg::R0));
        }
        self.builder
            .push(EbpfInsn::stxdw(EbpfReg::R10, iter.current_offset, ebpf_dst));

        // Restore current value for loop body (undo the increment)
        // The loop variable should hold the current value, not the next
        if step >= i32::MIN as i64 && step <= i32::MAX as i64 {
            self.builder
                .push(EbpfInsn::add64_imm(ebpf_dst, -(step as i32)));
        } else {
            self.emit_load_64bit_imm(EbpfReg::R0, -step);
            self.builder
                .push(EbpfInsn::add64_reg(ebpf_dst, EbpfReg::R0));
        }

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
        // Use context parameter syntax for data access: {|ctx| $ctx.pid }
        // Use if expressions for filtering: {|ctx| if $ctx.pid == 1234 { ... } }
        match cmd_name {
            // Output helpers
            "emit" => OutputHelpers::compile_bpf_emit(self, src_dst),
            "read-str" => OutputHelpers::compile_bpf_read_str(self, src_dst, true),
            "read-kernel-str" => OutputHelpers::compile_bpf_read_str(self, src_dst, false),

            // Filter helper
            "filter" => FilterHelpers::compile_bpf_filter(self, src_dst),

            // Aggregation helpers
            "count" => AggregationHelpers::compile_bpf_count(self, src_dst),
            "histogram" => AggregationHelpers::compile_bpf_histogram(self, src_dst),

            // Timing helpers
            "start-timer" => TimingHelpers::compile_bpf_start_timer(self, src_dst),
            "stop-timer" => TimingHelpers::compile_bpf_stop_timer(self, src_dst),

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
        let field_name = self.get_literal_string(key).cloned().ok_or_else(|| {
            CompileError::UnsupportedInstruction(
                "Record field name must be a literal string".into(),
            )
        })?;

        // Determine the field type from the value register
        let field_type = self.get_register_type(val).unwrap_or(BpfFieldType::Int);
        let field_size = field_type.size() as i16;

        // Get the eBPF register containing the value
        // Use ensure_reg to read the existing value (not alloc_reg which is for writing)
        let ebpf_val = self.ensure_reg(val)?;

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
                // Comm is a stack-based string - copy 16 bytes from source to destination
                if let Some(stack_str) = self.get_stack_string(val) {
                    let src_offset = stack_str.offset;
                    // Copy first 8 bytes
                    self.builder
                        .push(EbpfInsn::ldxdw(EbpfReg::R0, EbpfReg::R10, src_offset));
                    self.builder.push(EbpfInsn::stxdw(
                        EbpfReg::R10,
                        field_stack_offset,
                        EbpfReg::R0,
                    ));
                    // Copy second 8 bytes
                    self.builder
                        .push(EbpfInsn::ldxdw(EbpfReg::R0, EbpfReg::R10, src_offset + 8));
                    self.builder.push(EbpfInsn::stxdw(
                        EbpfReg::R10,
                        field_stack_offset + 8,
                        EbpfReg::R0,
                    ));
                } else {
                    // Fallback: treat as 8-byte value (shouldn't happen with proper tracking)
                    self.builder
                        .push(EbpfInsn::stxdw(EbpfReg::R10, field_stack_offset, ebpf_val));
                    self.builder.push(EbpfInsn::mov64_imm(EbpfReg::R0, 0));
                    self.builder.push(EbpfInsn::stxdw(
                        EbpfReg::R10,
                        field_stack_offset + 8,
                        EbpfReg::R0,
                    ));
                }
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
        // We need to work with the metadata through the accessor pattern
        let metadata = self.get_or_create_metadata(src_dst);
        if metadata.record_builder.is_none() {
            metadata.record_builder = Some(RecordBuilder {
                fields: Vec::new(),
                base_offset: field_stack_offset, // First field determines base
            });
        }
        let record = metadata.record_builder.as_mut().unwrap();

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

    /// Compile FollowCellPath - access a field on a value
    ///
    /// For context parameter access like `$ctx.pid`, this maps field names
    /// to the appropriate BPF helper calls or context struct offsets.
    fn compile_follow_cell_path(
        &mut self,
        src_dst: RegId,
        path_reg: RegId,
    ) -> Result<(), CompileError> {
        // Check if this is accessing a field on the context parameter
        if !self.is_context_register(src_dst) {
            return Err(CompileError::UnsupportedInstruction(
                "FollowCellPath on non-context value not supported".into(),
            ));
        }

        // Get the cell path to find the field name
        let cell_path = self
            .get_literal_cell_path(path_reg)
            .cloned()
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction("Cell path literal not found".into())
            })?;

        // We only support single-level field access like $ctx.pid
        if cell_path.members.len() != 1 {
            return Err(CompileError::UnsupportedInstruction(format!(
                "Multi-level cell path not supported: {} members",
                cell_path.members.len()
            )));
        }

        // Extract the field name
        let field_name = match &cell_path.members[0] {
            PathMember::String { val, .. } => val.as_str(),
            PathMember::Int { .. } => {
                return Err(CompileError::UnsupportedInstruction(
                    "Integer index on context not supported".into(),
                ));
            }
        };

        // For tracepoints, use the tracepoint context layout
        if self.probe_context.is_tracepoint() {
            return self.compile_tracepoint_field_access(src_dst, field_name);
        }

        // For kprobes/uprobes, use pt_regs-based access
        self.compile_kprobe_field_access(src_dst, field_name)
    }

    /// Compile field access for tracepoints using tracepoint context layout
    fn compile_tracepoint_field_access(
        &mut self,
        src_dst: RegId,
        field_name: &str,
    ) -> Result<(), CompileError> {
        let ebpf_dst = self.alloc_reg(src_dst)?;

        // Universal fields work on all probe types
        match field_name {
            "pid" | "tgid" | "uid" | "gid" | "comm" | "ktime" => {
                return self.compile_universal_field(src_dst, ebpf_dst, field_name);
            }
            _ => {}
        }

        // Get tracepoint context from KernelBtf
        let (category, name) = self.probe_context.tracepoint_parts().ok_or_else(|| {
            CompileError::TracepointContextError {
                category: "unknown".into(),
                name: self.probe_context.target.clone(),
                reason: "Invalid tracepoint format. Expected 'category/name'".into(),
            }
        })?;

        let btf = KernelBtf::get();
        let ctx = btf.get_tracepoint_context(category, name).map_err(|e| {
            CompileError::TracepointContextError {
                category: category.into(),
                name: name.into(),
                reason: e.to_string(),
            }
        })?;

        // Look up the field in the tracepoint context
        let field_info =
            ctx.get_field(field_name)
                .ok_or_else(|| CompileError::TracepointFieldNotFound {
                    field: field_name.into(),
                    available: ctx.field_names().join(", "),
                })?;

        // Load the field from the context struct
        // R9 contains the saved context pointer (tracepoint context struct)
        let offset = field_info.offset as i16;

        // Choose load instruction based on field size
        match field_info.size {
            1 => {
                self.builder()
                    .push(EbpfInsn::ldxb(ebpf_dst, EbpfReg::R9, offset));
            }
            2 => {
                self.builder()
                    .push(EbpfInsn::ldxh(ebpf_dst, EbpfReg::R9, offset));
            }
            4 => {
                self.builder()
                    .push(EbpfInsn::ldxw(ebpf_dst, EbpfReg::R9, offset));
            }
            _ => {
                // Default to 64-bit load for 8+ byte fields
                self.builder()
                    .push(EbpfInsn::ldxdw(ebpf_dst, EbpfReg::R9, offset));
            }
        }

        self.set_register_type(src_dst, BpfFieldType::Int);
        self.set_context_register(src_dst, false);

        Ok(())
    }

    /// Compile field access for kprobes/uprobes using pt_regs
    fn compile_kprobe_field_access(
        &mut self,
        src_dst: RegId,
        field_name: &str,
    ) -> Result<(), CompileError> {
        let ebpf_dst = self.alloc_reg(src_dst)?;

        match field_name {
            // Universal fields (work via BPF helpers)
            "pid" | "tgid" | "uid" | "gid" | "comm" | "ktime" | "kstack" | "ustack" => {
                self.compile_universal_field(src_dst, ebpf_dst, field_name)?;
            }
            // Function arguments (arg0-arg5 for x86_64, arg0-arg7 for aarch64)
            name if name.starts_with("arg") => {
                let arg_idx: usize = name[3..].parse().map_err(|_| {
                    CompileError::UnsupportedInstruction(format!("Invalid argument: {name}"))
                })?;

                if arg_idx >= pt_regs_offsets::ARG_OFFSETS.len() {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "Argument index {arg_idx} out of range"
                    )));
                }

                let offset = pt_regs_offsets::ARG_OFFSETS[arg_idx];
                // R9 contains the saved context pointer (pt_regs)
                self.builder()
                    .push(EbpfInsn::ldxdw(ebpf_dst, EbpfReg::R9, offset));
                self.set_register_type(src_dst, BpfFieldType::Int);
            }
            "retval" => {
                // Return value (for kretprobe/uretprobe only)
                if !self.probe_context.is_return_probe() {
                    return Err(CompileError::RetvalOnNonReturnProbe);
                }
                let offset = pt_regs_offsets::RETVAL_OFFSET;
                self.builder()
                    .push(EbpfInsn::ldxdw(ebpf_dst, EbpfReg::R9, offset));
                self.set_register_type(src_dst, BpfFieldType::Int);
            }
            _ => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "Unknown context field: {field_name}. Supported: pid, tgid, uid, gid, comm, ktime, kstack, ustack, arg0-arg5, retval"
                )));
            }
        }

        // The register no longer holds "context" - it now holds the field value
        self.set_context_register(src_dst, false);

        Ok(())
    }

    /// Compile bpf_get_stackid() call to get kernel or user stack trace ID
    ///
    /// This calls bpf_get_stackid(ctx, map, flags) which returns a stack ID
    /// that can be used to look up the actual stack trace from the map.
    fn compile_get_stackid(
        &mut self,
        src_dst: RegId,
        ebpf_dst: EbpfReg,
        user_stack: bool,
    ) -> Result<(), CompileError> {
        let map_name = if user_stack {
            USTACK_MAP_NAME
        } else {
            KSTACK_MAP_NAME
        };
        // BPF_F_USER_STACK = 256, use 0 for kernel stack
        let flags: i32 = if user_stack { 256 } else { 0 };

        // R1 = ctx (restore from R9 where we saved it at program start)
        self.builder()
            .push(EbpfInsn::mov64_reg(EbpfReg::R1, EbpfReg::R9));

        // R2 = map fd (will be relocated by loader)
        let reloc_offset = self.builder().len() * 8;
        let [insn1, insn2] = EbpfInsn::ld_map_fd(EbpfReg::R2);
        self.builder().push(insn1);
        self.builder().push(insn2);
        self.add_relocation(MapRelocation {
            insn_offset: reloc_offset,
            map_name: map_name.to_string(),
        });

        // R3 = flags
        self.builder().push(EbpfInsn::mov64_imm(EbpfReg::R3, flags));

        // Call bpf_get_stackid
        self.builder().push(EbpfInsn::call(BpfHelper::GetStackId));

        // Result (stack ID or negative error) is in R0, move to destination
        self.builder()
            .push(EbpfInsn::mov64_reg(ebpf_dst, EbpfReg::R0));
        self.set_register_type(src_dst, BpfFieldType::Int);

        Ok(())
    }

    /// Compile universal context fields that work on all probe types
    ///
    /// These use BPF helper functions rather than reading from context struct.
    fn compile_universal_field(
        &mut self,
        src_dst: RegId,
        ebpf_dst: EbpfReg,
        field_name: &str,
    ) -> Result<(), CompileError> {
        match field_name {
            "pid" => {
                // bpf_get_current_pid_tgid() returns (tgid << 32) | pid
                // Lower 32 bits = thread ID (what Linux calls PID)
                self.builder()
                    .push(EbpfInsn::call(BpfHelper::GetCurrentPidTgid));
                // Mask to get lower 32 bits
                self.builder()
                    .push(EbpfInsn::mov64_reg(ebpf_dst, EbpfReg::R0));
                self.builder()
                    .push(EbpfInsn::and64_imm(ebpf_dst, 0x7FFFFFFF));
                self.set_register_type(src_dst, BpfFieldType::Int);
            }
            "tgid" => {
                // Upper 32 bits = thread group ID (what userspace calls PID)
                self.builder()
                    .push(EbpfInsn::call(BpfHelper::GetCurrentPidTgid));
                self.builder().push(EbpfInsn::rsh64_imm(EbpfReg::R0, 32));
                self.builder()
                    .push(EbpfInsn::mov64_reg(ebpf_dst, EbpfReg::R0));
                self.set_register_type(src_dst, BpfFieldType::Int);
            }
            "uid" => {
                // bpf_get_current_uid_gid() returns (gid << 32) | uid
                self.builder()
                    .push(EbpfInsn::call(BpfHelper::GetCurrentUidGid));
                self.builder()
                    .push(EbpfInsn::mov64_reg(ebpf_dst, EbpfReg::R0));
                self.builder()
                    .push(EbpfInsn::and64_imm(ebpf_dst, 0x7FFFFFFF));
                self.set_register_type(src_dst, BpfFieldType::Int);
            }
            "gid" => {
                self.builder()
                    .push(EbpfInsn::call(BpfHelper::GetCurrentUidGid));
                self.builder().push(EbpfInsn::rsh64_imm(EbpfReg::R0, 32));
                self.builder()
                    .push(EbpfInsn::mov64_reg(ebpf_dst, EbpfReg::R0));
                self.set_register_type(src_dst, BpfFieldType::Int);
            }
            "comm" => {
                // Get full 16-byte command name as a stack-based string
                self.check_stack_space(16)?;
                let stack_offset = self.current_stack_offset() - 16;
                self.advance_stack_offset(16);

                // bpf_get_current_comm(buf, size) - fills 16 bytes on stack
                self.builder()
                    .push(EbpfInsn::mov64_reg(EbpfReg::R1, EbpfReg::R10));
                self.builder()
                    .push(EbpfInsn::add64_imm(EbpfReg::R1, stack_offset as i32));
                self.builder().push(EbpfInsn::mov64_imm(EbpfReg::R2, 16));
                self.builder()
                    .push(EbpfInsn::call(BpfHelper::GetCurrentComm));

                // Store stack pointer in register (for emit to use)
                self.builder()
                    .push(EbpfInsn::mov64_reg(ebpf_dst, EbpfReg::R10));
                self.builder()
                    .push(EbpfInsn::add64_imm(ebpf_dst, stack_offset as i32));

                // Track that this register points to a stack string
                self.set_stack_string(
                    src_dst,
                    StackString {
                        offset: stack_offset,
                        size: 16,
                    },
                );
                self.set_register_type(src_dst, BpfFieldType::Comm);
            }
            "ktime" => {
                // bpf_ktime_get_ns() returns nanoseconds since boot
                self.builder().push(EbpfInsn::call(BpfHelper::KtimeGetNs));
                self.builder()
                    .push(EbpfInsn::mov64_reg(ebpf_dst, EbpfReg::R0));
                self.set_register_type(src_dst, BpfFieldType::Int);
            }
            "kstack" => {
                // Get kernel stack trace ID
                self.set_needs_kstack_map(true);
                self.compile_get_stackid(src_dst, ebpf_dst, false)?;
            }
            "ustack" => {
                // Get user stack trace ID
                self.set_needs_ustack_map(true);
                self.compile_get_stackid(src_dst, ebpf_dst, true)?;
            }
            _ => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "Unknown universal field: {field_name}"
                )));
            }
        }

        self.set_context_register(src_dst, false);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nu_protocol::ast::{Comparison, Math, Operator};
    use nu_protocol::ir::{DataSlice, IrBlock, Literal};
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

    fn make_ir_block_with_data(instructions: Vec<Instruction>, data: Vec<u8>) -> IrBlock {
        IrBlock {
            instructions,
            spans: vec![],
            data: Arc::from(data),
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

    #[test]
    fn test_compile_string_comparison_equal() {
        // Create data buffer with two strings: "nginx" at offset 0, "nginx" at offset 5
        let data = b"nginxnginx".to_vec();

        let ir = make_ir_block_with_data(
            vec![
                // Load first string "nginx"
                Instruction::LoadLiteral {
                    dst: RegId::new(0),
                    lit: Literal::String(DataSlice { start: 0, len: 5 }),
                },
                // Load second string "nginx"
                Instruction::LoadLiteral {
                    dst: RegId::new(1),
                    lit: Literal::String(DataSlice { start: 5, len: 5 }),
                },
                // Compare them
                Instruction::BinaryOp {
                    lhs_dst: RegId::new(0),
                    op: Operator::Comparison(Comparison::Equal),
                    rhs: RegId::new(1),
                },
                Instruction::Return { src: RegId::new(0) },
            ],
            data,
        );

        let bytecode = IrToEbpfCompiler::compile_no_calls(&ir).unwrap();
        // Should have bytecode for:
        // - Store first string on stack
        // - Store second string on stack
        // - Compare them chunk by chunk
        // - Return result
        assert!(!bytecode.is_empty());
        // String comparison generates more instructions than simple int comparison
        // Each string needs: 64-bit load + store per chunk + pointer setup
        // Comparison needs: load chunks + compare + jumps
        assert!(
            bytecode.len() > 100,
            "Expected substantial bytecode for string comparison"
        );
    }

    #[test]
    fn test_compile_string_comparison_not_equal() {
        // Create data buffer with two different strings
        let data = b"nginxapache".to_vec();

        let ir = make_ir_block_with_data(
            vec![
                Instruction::LoadLiteral {
                    dst: RegId::new(0),
                    lit: Literal::String(DataSlice { start: 0, len: 5 }),
                },
                Instruction::LoadLiteral {
                    dst: RegId::new(1),
                    lit: Literal::String(DataSlice { start: 5, len: 6 }),
                },
                Instruction::BinaryOp {
                    lhs_dst: RegId::new(0),
                    op: Operator::Comparison(Comparison::NotEqual),
                    rhs: RegId::new(1),
                },
                Instruction::Return { src: RegId::new(0) },
            ],
            data,
        );

        let bytecode = IrToEbpfCompiler::compile_no_calls(&ir).unwrap();
        assert!(!bytecode.is_empty());
    }

    #[test]
    fn test_compile_string_comparison_different_lengths() {
        // Test comparing strings of different lengths
        // "nginx" (5 bytes + null = 6) vs "ng" (2 bytes + null = 3)
        // Should compare 3 bytes (shorter), and "ngi" != "ng\0"
        let data = b"nginxng".to_vec();

        let ir = make_ir_block_with_data(
            vec![
                Instruction::LoadLiteral {
                    dst: RegId::new(0),
                    lit: Literal::String(DataSlice { start: 0, len: 5 }),
                },
                Instruction::LoadLiteral {
                    dst: RegId::new(1),
                    lit: Literal::String(DataSlice { start: 5, len: 2 }),
                },
                Instruction::BinaryOp {
                    lhs_dst: RegId::new(0),
                    op: Operator::Comparison(Comparison::Equal),
                    rhs: RegId::new(1),
                },
                Instruction::Return { src: RegId::new(0) },
            ],
            data,
        );

        let bytecode = IrToEbpfCompiler::compile_no_calls(&ir).unwrap();
        assert!(!bytecode.is_empty());
    }

    #[test]
    fn test_compile_bounded_loop_basic() {
        use nu_protocol::ast::RangeInclusion;

        // Test basic for loop: for i in 1..5 { ... }
        // This compiles to:
        // 0: load-literal %1 = 1 (start)
        // 1: load-literal %2 = 1 (step)
        // 2: load-literal %3 = 5 (end)
        // 3: load-literal %4 = Range(start=%1, step=%2, end=%3)
        // 4: iterate %0, %4, end_index=7
        // 5: ... loop body ...
        // 6: jump 4
        // 7: return
        let ir = make_ir_block(vec![
            // Load start
            Instruction::LoadLiteral {
                dst: RegId::new(1),
                lit: Literal::Int(1),
            },
            // Load step
            Instruction::LoadLiteral {
                dst: RegId::new(2),
                lit: Literal::Int(1),
            },
            // Load end
            Instruction::LoadLiteral {
                dst: RegId::new(3),
                lit: Literal::Int(5),
            },
            // Load range
            Instruction::LoadLiteral {
                dst: RegId::new(4),
                lit: Literal::Range {
                    start: RegId::new(1),
                    step: RegId::new(2),
                    end: RegId::new(3),
                    inclusion: RangeInclusion::RightExclusive,
                },
            },
            // Iterate
            Instruction::Iterate {
                dst: RegId::new(0),
                stream: RegId::new(4),
                end_index: 7,
            },
            // Loop body - just add to accumulator (simplified)
            Instruction::LoadLiteral {
                dst: RegId::new(5),
                lit: Literal::Int(0),
            },
            // Jump back to iterate
            Instruction::Jump { index: 4 },
            // Return
            Instruction::LoadLiteral {
                dst: RegId::new(0),
                lit: Literal::Int(0),
            },
            Instruction::Return { src: RegId::new(0) },
        ]);

        let bytecode = IrToEbpfCompiler::compile_no_calls(&ir).unwrap();
        // Should generate bounded loop bytecode
        assert!(!bytecode.is_empty());
        // Loop generates multiple instructions: load, compare, jump, increment, store, etc.
        assert!(
            bytecode.len() > 80,
            "Expected loop bytecode to be substantial"
        );
    }

    #[test]
    fn test_compile_bounded_loop_inclusive() {
        use nu_protocol::ast::RangeInclusion;

        // Test inclusive range: for i in 1..=3 { ... }
        let ir = make_ir_block(vec![
            Instruction::LoadLiteral {
                dst: RegId::new(1),
                lit: Literal::Int(1),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(2),
                lit: Literal::Int(1),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(3),
                lit: Literal::Int(3),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(4),
                lit: Literal::Range {
                    start: RegId::new(1),
                    step: RegId::new(2),
                    end: RegId::new(3),
                    inclusion: RangeInclusion::Inclusive,
                },
            },
            Instruction::Iterate {
                dst: RegId::new(0),
                stream: RegId::new(4),
                end_index: 6,
            },
            Instruction::Jump { index: 4 },
            Instruction::LoadLiteral {
                dst: RegId::new(0),
                lit: Literal::Int(0),
            },
            Instruction::Return { src: RegId::new(0) },
        ]);

        let bytecode = IrToEbpfCompiler::compile_no_calls(&ir).unwrap();
        assert!(!bytecode.is_empty());
    }

    #[test]
    fn test_compile_bounded_loop_negative_step() {
        use nu_protocol::ast::RangeInclusion;

        // Test counting down: for i in 5..1 step -1
        let ir = make_ir_block(vec![
            Instruction::LoadLiteral {
                dst: RegId::new(1),
                lit: Literal::Int(5),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(2),
                lit: Literal::Int(-1),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(3),
                lit: Literal::Int(1),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(4),
                lit: Literal::Range {
                    start: RegId::new(1),
                    step: RegId::new(2),
                    end: RegId::new(3),
                    inclusion: RangeInclusion::RightExclusive,
                },
            },
            Instruction::Iterate {
                dst: RegId::new(0),
                stream: RegId::new(4),
                end_index: 6,
            },
            Instruction::Jump { index: 4 },
            Instruction::LoadLiteral {
                dst: RegId::new(0),
                lit: Literal::Int(0),
            },
            Instruction::Return { src: RegId::new(0) },
        ]);

        let bytecode = IrToEbpfCompiler::compile_no_calls(&ir).unwrap();
        assert!(!bytecode.is_empty());
    }
}
