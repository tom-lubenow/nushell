# Event Field Access Implementation Plan

## Overview

Event field access (`$ctx.field`) is essential for eBPF programs to access kernel data structures. This requires BTF (BPF Type Format) integration to know the structure layouts.

## Current Challenge

When we write `$ctx.filename` in a kprobe for `do_sys_open`, we need to:
1. Know that the probe context has access to specific arguments
2. Know the types of those arguments
3. Generate appropriate eBPF code to safely access them

## Proposed Implementation Approach

### Phase 1: Basic Field Access Parsing

First, let's implement the parser support for field access syntax:

```rust
// In parser.rs
// Support for $variable.field syntax
$ctx.filename
$event.size
$ctx.daddr
```

### Phase 2: Probe-Specific Context Mapping

Different probe types have different contexts:

1. **kprobe**: Access to function arguments
   - `sys_open`: filename, flags, mode
   - `sys_read`: fd, buf, count
   - `tcp_connect`: sk, uaddr, addr_len

2. **tracepoint**: Access to tracepoint fields
   - Defined by the tracepoint format

3. **uprobe**: Access to user-space function arguments

### Phase 3: Type Information Integration

We have several options:

#### Option A: Hard-coded Common Structures (MVP)
Start with a predefined set of common probe contexts:

```rust
// Define known probe contexts
enum ProbeContext {
    SysOpen { filename: String, flags: u32, mode: u32 },
    SysRead { fd: u32, buf: *const u8, count: usize },
    TcpConnect { sk: *const SockStruct, daddr: u32, dport: u16 },
    // ... more common probes
}
```

#### Option B: BTF Integration (Full Solution)
Use the kernel's BTF to dynamically discover structures:

```rust
// Use aya's BTF support
let btf = Btf::from_sys_fs()?;
let func_proto = btf.func_proto("do_sys_open")?;
// Extract argument types and generate appropriate access code
```

#### Option C: User-Provided Hints
Allow users to specify the context structure:

```nushell
# User provides type hints
bpf-kprobe "my_custom_func" --args "filename:str,size:u64" { |ctx|
    if $ctx.size > 1024 {
        print $ctx.filename
    }
}
```

## Recommended Implementation Path

### Step 1: Parser Support (Quick Win)
- Add parsing for `$variable.field` syntax
- Create AST nodes for field access expressions

### Step 2: Hard-coded Contexts (MVP)
- Implement a registry of common kernel functions and their argument types
- Generate appropriate eBPF code for known contexts
- This covers 80% of use cases quickly

### Step 3: BTF Integration (Complete Solution)
- Use Aya's BTF support to dynamically discover types
- Fall back to hard-coded contexts when BTF isn't available
- Allow user overrides for custom functions

### Step 4: Safety and Verification
- Add bounds checking for string access
- Ensure null pointer checks
- Validate field access against known types

## Code Generation Example

For `$ctx.filename` in `do_sys_open`:

```rust
// Nushell code
bpf-kprobe "do_sys_open" { |ctx|
    if str_contains($ctx.filename, "secret") {
        emit("sensitive")
    }
}

// Generated eBPF code
#[kprobe(name = "probe_do_sys_open")]
pub fn probe_do_sys_open(ctx: ProbeContext) -> u32 {
    // Get filename from first argument
    let filename_ptr: *const u8 = ctx.arg(0).ok()?;
    
    // Safe string read with bounds
    let mut filename = [0u8; 256];
    unsafe {
        bpf_probe_read_user_str_bytes(
            filename_ptr,
            &mut filename
        ).ok()?;
    }
    
    // Check if contains "secret"
    if contains_bytes(&filename, b"secret") {
        // Emit event
        // ...
    }
    
    0
}
```

## Technical Considerations

1. **Safety**: All pointer dereferences must use `bpf_probe_read_*` helpers
2. **Bounds**: String reads must have maximum bounds
3. **Null checks**: All pointers must be checked before use
4. **Type matching**: Field types must match eBPF constraints

## Testing Strategy

1. Unit tests for parser with field access
2. Integration tests with mock probe contexts
3. Linux-specific tests with real BTF data
4. Example programs for common use cases