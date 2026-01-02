# Kernel BTF Parsing Architecture

This document scopes out the architecture for integrating kernel BTF (BPF Type Format) parsing into nu-ebpf, enabling advanced features like automatic pointer type detection, tracepoint support, and struct field traversal.

## Background

### Current State

1. **BTF Generation** (`btf.rs`): We generate BTF metadata to describe our eBPF maps to the kernel loader. This is *output* BTF - describing our types.

2. **Aya Loader**: Uses kernel BTF for CO-RE relocations when loading programs. Aya already reads `/sys/kernel/btf/vmlinux` internally.

3. **ProbeContext**: Passes probe type and target through the compiler, enabling probe-aware compilation (e.g., validating `retval` access).

### What's Missing

We don't *query* kernel BTF ourselves. We can't:
- Look up function signatures to detect `__user` pointers
- Get tracepoint context struct layouts
- Traverse kernel struct definitions
- Validate probe targets exist

## Features Enabled by Kernel BTF

### Tier 1: Essential for Good UX

#### 1.1 Tracepoint Support (HIGH PRIORITY)
**Problem**: Tracepoints don't use `pt_regs`. They have structured contexts like `trace_event_raw_sys_enter`.

**BTF Need**: Look up `trace_event_raw_<name>` struct to get field offsets.

**Example**:
```nushell
# User writes:
ebpf attach -s 'tracepoint:syscalls/sys_enter_openat' {|ctx| $ctx.args[0] | emit }

# Compiler needs to know:
# - trace_event_raw_sys_enter_openat layout
# - args field offset within that struct
# - args is an array of longs
```

#### 1.2 Function Validation
**Problem**: Attaching to a non-existent function gives cryptic kernel errors.

**BTF Need**: Check function exists in BTF before attempting attach.

**Example**:
```nushell
# User makes typo:
ebpf attach 'kprobe:sys_claone' {|ctx| $ctx.pid | emit }
# ERROR: Function 'sys_claone' not found. Did you mean 'sys_clone'?
```

### Tier 2: Nice-to-Have Quality Improvements

#### 2.1 Auto-detect `__user` Pointers
**Problem**: Users must choose between `read-str` (userspace) and `read-kernel-str` (kernel).

**BTF Need**: Look up function signature, check parameter type annotations.

**Example**:
```nushell
# For do_sys_openat2, arg1 is `const char __user *filename`
# Compiler auto-selects bpf_probe_read_user_str
ebpf attach 'kprobe:do_sys_openat2' {|ctx| $ctx.arg1 | read-str }
```

**Reality Check**: The `__user` annotation is a type tag in BTF. Aya provides `TypeTag` for this. We'd need to:
1. Look up function by name
2. Get its FuncProto
3. For each parameter, check if it's a pointer with `__user` tag

#### 2.2 Argument Name Access
**Problem**: Users must use `$ctx.arg0`, `$ctx.arg1`, etc.

**BTF Need**: Look up function signature to get parameter names.

**Example**:
```nushell
# Instead of:
{|ctx| $ctx.arg1 | read-str }
# User could write:
{|ctx| $ctx.filename | read-str }
```

### Tier 3: Advanced Features (Future)

#### 3.1 Struct Field Traversal
**Problem**: Can't dereference struct pointers.

**BTF Need**: Full struct definitions with field offsets.

**Example**:
```nushell
# Access nested struct fields:
{|ctx| $ctx.arg0.f_path.dentry.d_name.name | read-kernel-str }
```

**Complexity**: This requires:
- Parsing struct definitions
- Tracking pointer types
- Emitting proper read sequences (probe_read for each pointer chase)
- Handling CO-RE relocations for portability

#### 3.2 kfunc Calls
**Problem**: Limited to BPF helper functions.

**BTF Need**: kfunc signatures to generate proper calls.

**Example**:
```nushell
# Call kernel functions directly:
{|ctx| kfunc:bpf_get_current_cgroup_id() | emit }
```

#### 3.3 Full CO-RE Support
**Problem**: Programs may not work across kernel versions.

**BTF Need**: Generate `.BTF.ext` with field relocations.

**Note**: Aya already handles CO-RE relocations at load time. Full support would mean generating the relocation entries ourselves.

## Proposed Architecture

### Overview

```
┌────────────────────────────────────────────────────────┐
│                    KernelBtf Service                   │
│  (Singleton, lazy-loaded, caches common lookups)       │
├────────────────────────────────────────────────────────┤
│                                                        │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │  Functions   │  │ Tracepoints  │  │   Structs    │ │
│  │    Index     │  │    Index     │  │    Cache     │ │
│  └──────────────┘  └──────────────┘  └──────────────┘ │
│                                                        │
│  ┌─────────────────────────────────────────────────┐  │
│  │              aya_obj::btf::Btf                   │  │
│  │         (loaded from /sys/kernel/btf/vmlinux)   │  │
│  └─────────────────────────────────────────────────┘  │
│                                                        │
└────────────────────────────────────────────────────────┘
                           │
                           ▼
          ┌────────────────────────────────┐
          │         Query API              │
          ├────────────────────────────────┤
          │ • get_function_signature()     │
          │ • get_tracepoint_context()     │
          │ • get_struct_layout()          │
          │ • resolve_type()               │
          │ • function_exists()            │
          │ • suggest_similar()            │
          └────────────────────────────────┘
                           │
                           ▼
          ┌────────────────────────────────┐
          │       IrToEbpfCompiler         │
          │  (uses BTF during compilation) │
          └────────────────────────────────┘
```

### Module Structure

```
crates/nu-ebpf/src/
├── kernel_btf/              # NEW: Kernel BTF parsing
│   ├── mod.rs               # KernelBtf service
│   ├── function.rs          # Function signature queries
│   ├── tracepoint.rs        # Tracepoint context queries
│   ├── structs.rs           # Struct layout queries
│   └── types.rs             # Type resolution & annotations
├── compiler/
│   ├── ir_to_ebpf.rs        # Uses KernelBtf for type info
│   └── ...
└── ...
```

### Core Types

```rust
/// Service for querying kernel BTF information
pub struct KernelBtf {
    /// The parsed kernel BTF (loaded from /sys/kernel/btf/vmlinux)
    btf: aya_obj::btf::Btf,
    /// Cached function type IDs by name
    function_cache: HashMap<String, Option<FunctionInfo>>,
    /// Cached tracepoint contexts
    tracepoint_cache: HashMap<String, Option<TracepointContext>>,
}

/// Information about a kernel function
pub struct FunctionInfo {
    /// Function name
    pub name: String,
    /// Parameter information
    pub params: Vec<ParameterInfo>,
    /// Return type
    pub return_type: TypeInfo,
}

/// Information about a function parameter
pub struct ParameterInfo {
    /// Parameter name (if available)
    pub name: Option<String>,
    /// Parameter type
    pub type_info: TypeInfo,
    /// Is this a __user pointer?
    pub is_user_pointer: bool,
}

/// Information about a type
pub enum TypeInfo {
    /// Integer type (with size and signedness)
    Int { size: usize, signed: bool },
    /// Pointer to another type
    Ptr { target: Box<TypeInfo>, is_user: bool },
    /// Struct type
    Struct { name: String, fields: Vec<FieldInfo> },
    /// Array type
    Array { element: Box<TypeInfo>, len: usize },
    /// Unknown/opaque type
    Unknown,
}

/// Information about a struct field
pub struct FieldInfo {
    /// Field name
    pub name: String,
    /// Field type
    pub type_info: TypeInfo,
    /// Offset in bytes
    pub offset: usize,
    /// Size in bytes
    pub size: usize,
}

/// Tracepoint context layout
pub struct TracepointContext {
    /// The raw event struct name (e.g., "trace_event_raw_sys_enter")
    pub struct_name: String,
    /// Available fields
    pub fields: Vec<FieldInfo>,
}
```

### Query API

```rust
impl KernelBtf {
    /// Get the global kernel BTF instance
    /// Returns None if BTF is not available (old kernel, not mounted, etc.)
    pub fn get() -> Option<&'static KernelBtf>;

    /// Check if a function exists in the kernel
    pub fn function_exists(&self, name: &str) -> bool;

    /// Get function signature information
    pub fn get_function(&self, name: &str) -> Option<&FunctionInfo>;

    /// Suggest similar function names (for typo correction)
    pub fn suggest_similar_functions(&self, name: &str, max: usize) -> Vec<String>;

    /// Get tracepoint context layout
    pub fn get_tracepoint_context(&self, category: &str, name: &str) -> Option<&TracepointContext>;

    /// Resolve a struct by name
    pub fn get_struct(&self, name: &str) -> Option<StructInfo>;

    /// Check if a parameter is a __user pointer
    pub fn is_user_pointer(&self, func: &str, param_index: usize) -> Option<bool>;
}
```

### Integration Points

#### 1. ProbeContext Enhancement

```rust
pub struct ProbeContext {
    pub probe_type: EbpfProgramType,
    pub target: String,
    /// Function/tracepoint info from kernel BTF (if available)
    pub btf_info: Option<ProbeTargetInfo>,
}

pub enum ProbeTargetInfo {
    Function(FunctionInfo),
    Tracepoint(TracepointContext),
}
```

#### 2. Compiler Integration

```rust
// In compile_context_field_access:
fn compile_ctx_field(&mut self, field: &str) -> Result<(), CompileError> {
    match self.probe_context.probe_type {
        EbpfProgramType::Kprobe | EbpfProgramType::Kretprobe => {
            // Current pt_regs-based access
            self.compile_pt_regs_field(field)
        }
        EbpfProgramType::Tracepoint => {
            // Use BTF to get field offset from tracepoint context
            let ctx = self.probe_context.btf_info
                .as_ref()
                .and_then(|i| match i {
                    ProbeTargetInfo::Tracepoint(t) => Some(t),
                    _ => None,
                })
                .ok_or(CompileError::NoBtfForTracepoint)?;

            let field_info = ctx.fields.iter()
                .find(|f| f.name == field)
                .ok_or(CompileError::UnknownTracepointField(field.into()))?;

            self.compile_ctx_field_at_offset(field_info.offset, &field_info.type_info)
        }
        // ...
    }
}
```

#### 3. read-str Auto-Detection

```rust
// In compile_read_str:
fn compile_read_str(&mut self, src_dst: RegId) -> Result<(), CompileError> {
    // If we have BTF info, try to determine if this is a user pointer
    let use_user_read = if let Some(ref btf) = KernelBtf::get() {
        // Check if the value came from a function argument
        if let Some((func_name, arg_idx)) = self.get_source_arg_info(src_dst) {
            btf.is_user_pointer(&func_name, arg_idx).unwrap_or(true)
        } else {
            // Default to user read (safer, most common case)
            true
        }
    } else {
        // No BTF available, default to user read
        true
    };

    if use_user_read {
        self.emit_bpf_probe_read_user_str(src_dst)
    } else {
        self.emit_bpf_probe_read_kernel_str(src_dst)
    }
}
```

### Error Handling

```rust
pub enum BtfError {
    /// BTF not available on this system
    NotAvailable,
    /// Failed to parse kernel BTF
    ParseError(String),
    /// Type not found
    TypeNotFound(String),
    /// Function not found (with suggestions)
    FunctionNotFound { name: String, suggestions: Vec<String> },
}
```

### Graceful Degradation

The system should work even when kernel BTF is unavailable:

1. **No BTF available**: Fall back to current behavior
   - Tracepoints: Return error explaining BTF is required
   - read-str: Default to user read
   - Function validation: Skip validation

2. **BTF parsing fails**: Log warning, continue without BTF

3. **Type not in BTF**: Fall back to defaults, warn user

## Implementation Plan

### Phase 1: Foundation (Tracepoint Support)
1. Create `kernel_btf/` module structure
2. Implement `KernelBtf::get()` with lazy loading
3. Implement `get_tracepoint_context()`
4. Update compiler to use tracepoint context layouts
5. Add tracepoint examples and tests

### Phase 2: Function Validation
1. Implement `function_exists()` and `suggest_similar_functions()`
2. Validate kprobe/kretprobe targets before attach
3. Improve error messages with suggestions

### Phase 3: read-str Auto-Detection
1. Implement `get_function()` and `is_user_pointer()`
2. Track value provenance in compiler (which arg did this come from)
3. Auto-select user/kernel read based on BTF type tags

### Phase 4: Struct Traversal (Future)
1. Implement full struct resolution
2. Add syntax for field traversal (`$ctx.arg0.field`)
3. Generate proper pointer chasing code

## Dependencies

Current:
- `aya` - Already in workspace, includes `aya-obj`

No new dependencies needed - `aya-obj::btf::Btf` provides:
- `Btf::from_sys_fs()` - Load kernel BTF
- `id_by_type_name_kind()` - Look up types by name
- `FuncProto`, `Struct`, `BtfParam`, etc. - Type representations

## Testing Strategy

1. **Unit tests**: Mock BTF data for deterministic testing
2. **Integration tests**: Use real kernel BTF (Linux-only, may need root)
3. **Graceful degradation tests**: Verify behavior when BTF unavailable

## Open Questions

1. **Caching strategy**: How aggressively to cache lookups?
   - Recommendation: Cache everything - kernel BTF doesn't change at runtime

2. **Module BTF**: Should we support `/sys/kernel/btf/<module>` for kernel module functions?
   - Recommendation: Start with vmlinux only, add module support if needed

3. **Cross-kernel compatibility**: How to handle missing types?
   - Recommendation: Graceful fallback with clear warnings

## Appendix: Aya BTF Types

Key types from `aya_obj::btf`:

```rust
// Main BTF container
pub struct Btf { ... }

// Type lookup
impl Btf {
    pub fn id_by_type_name_kind(&self, name: &str, kind: BtfKind) -> Result<u32, BtfError>;
}

// Type kinds
pub enum BtfKind {
    Int, Ptr, Array, Struct, Union, Enum, Fwd, Typedef,
    Volatile, Const, Restrict, Func, FuncProto, Var, DataSec,
    Float, DeclTag, TypeTag, Enum64,
}

// Function prototype
pub struct FuncProto {
    pub return_type: u32,
    pub params: Vec<BtfParam>,
}

// Function parameter
pub struct BtfParam {
    pub name_offset: u32,
    pub btf_type: u32,
}

// Struct definition
pub struct Struct {
    pub name_offset: u32,
    pub members: Vec<BtfMember>,
}

// Struct member
pub struct BtfMember {
    pub name_offset: u32,
    pub btf_type: u32,
    pub offset: u32,  // in bits
}
```
