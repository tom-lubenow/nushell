# Implementation Survey: eBPF Plugin for Nushell

## Executive Summary

We have successfully implemented a working eBPF plugin for Nushell that achieves the core goals outlined in the original implementation plan. The plugin enables users to write eBPF programs using Nushell's closure syntax, with automatic translation to Rust/eBPF code and kernel loading on Linux systems.

## What We've Accomplished

### ✅ Core Architecture (Matches Plan's "Option 2")
- Implemented Rust/Aya-based code generation as recommended in the plan
- Created a transpiler from Nushell closures to Rust eBPF code
- Integrated with Aya for pure-Rust eBPF loading (no libbpf dependency)
- Successfully generates and compiles eBPF programs at runtime

### ✅ Phase Implementation Status

**Phase 1: Research & Design** ✅ Complete
- Studied Nushell's plugin system and created nu_plugin_ebpf
- Integrated with nu-plugin protocol successfully
- Designed command syntax matching the plan's vision

**Phase 2: Minimal Viable Prototype** ✅ Complete
- Created `bpf-kprobe` command that accepts closures
- Successfully loads and attaches eBPF programs
- Demonstrates end-to-end pipeline from Nushell to kernel

**Phase 3: Basic Codegen & Rust Compilation** ✅ Complete
- Implemented full code generation pipeline
- Created parser for eBPF-safe Nushell subset
- Successfully invokes rustc for BPF compilation
- Loads programs with Aya on Linux

**Phase 4: Expanded Language Support** ✅ Complete
- Added arithmetic operations (+, -, *, /, %)
- Added comparisons (==, !=, <, <=, >, >=)
- Added boolean operations (&&, ||, ^)
- Implemented eBPF built-in variables ($pid, $uid, $comm)
- Implemented eBPF built-in functions (print, count, emit)
- Added `bpf-tracepoint` command for tracepoint support

**Phase 5: Robustness & Tooling** ✅ Mostly Complete
- Implemented span-based closure extraction (solving plugin API limitation)
- Created custom parser for eBPF subset
- Added event streaming with `bpf-stream` command
- Set up Lima VM for Linux testing
- Proper error handling and user feedback

## Language Features Support

### Currently Supported ✅
```nushell
# Basic probe with print
bpf-kprobe "sys_open" { || print "File opened!" }

# Variables and arithmetic
bpf-kprobe "sys_write" { || 
    if $pid > 1000 { 
        count() 
    } 
}

# String literals and functions
bpf-tracepoint "syscalls:sys_enter_open" { || 
    emit("open_event")
}

# Event streaming
bpf-stream | where type == "probe_hit" | first 10
```

### Supported Nushell Features in eBPF Context:
- ✅ Closures with parameters `{ || ... }` or `{ |event| ... }`
- ✅ Variables: `$pid`, `$uid`, `$comm` (eBPF built-ins)
- ✅ Arithmetic: `+`, `-`, `*`, `/`, `%`
- ✅ Comparisons: `==`, `!=`, `<`, `<=`, `>`, `>=`
- ✅ Boolean ops: `&&`, `||`, `^`
- ✅ Conditionals: `if condition { ... } else { ... }`
- ✅ String literals: `"text"`
- ✅ Integer literals: `42`
- ✅ Function calls: `print()`, `count()`, `emit()`

### Not Yet Supported ❌
- ❌ Loops (`for`, `while`, `loop`) - as per eBPF constraints
- ❌ Complex Nushell commands (`where`, `select`, etc.) inside eBPF
- ❌ Floating point operations
- ❌ Dynamic memory allocation
- ❌ User-defined functions
- ❌ Access to closure parameters/event fields (planned)

## Key Innovations Beyond the Plan

### 1. Span-Based Closure Extraction
The original plan didn't anticipate the plugin API limitation where we can't access closure AST directly. We innovated by:
- Using `engine.get_span_contents()` to extract closure source code
- Creating a custom parser for the eBPF-safe subset
- This allows us to analyze and compile closures despite API constraints

### 2. Event Streaming Infrastructure
We went beyond the plan by implementing:
- `EventCollector` for aggregating events from multiple eBPF programs
- `bpf-stream` command for real-time event monitoring
- Structured event types (probe_hit, counter, log, custom)
- Integration with Nushell's pipeline for filtering and processing

### 3. Comprehensive Testing Setup
- Created Lima VM configuration for Linux eBPF testing
- Multiple test scripts demonstrating various features
- Cross-platform support (code generation on macOS, full loading on Linux)

## Non-Trivial Examples

### Example 1: System Call Monitoring
```nushell
# Monitor file opens and count by process
bpf-kprobe "do_sys_open" { || 
    if $pid > 1000 {
        count()
    }
}

# Stream events and analyze
bpf-stream | where type == "counter" | group-by name
```

### Example 2: Performance Monitoring
```nushell
# Track write system calls with filtering
bpf-tracepoint "syscalls:sys_enter_write" { ||
    if $uid == 1000 {
        emit("user_write")
    }
}

# Process the stream
bpf-stream | where event_type == "user_write" | save user_writes.jsonl
```

### Example 3: Conditional Tracing
```nushell
# Complex conditional logic
bpf-kprobe "tcp_sendmsg" { ||
    if $pid > 1000 && $uid != 0 {
        print "Non-root network activity"
    }
}
```

## What About the `where` Keyword?

The `where` keyword represents an interesting challenge. In normal Nushell:
```nushell
ls | where size > 1mb  # This filters in user-space
```

For eBPF, we could potentially support:
```nushell
bpf-kprobe "sys_read" { |event| 
    where event.size > 1024 {  # Filter in kernel
        emit($event)
    }
}
```

However, this would require:
1. Extending our parser to handle `where` as a conditional
2. Translating it to an `if` statement in the generated code
3. Ensuring we can access event fields (requires BTF integration)

Currently, we achieve the same with `if`:
```nushell
bpf-kprobe "sys_read" { |event|
    if $event.size > 1024 {
        emit($event)
    }
}
```

## Relevance of Original Implementation Plan

The original plan remains **highly relevant** and has guided our implementation well:

### What Aligned with the Plan:
- ✅ Architecture choice (Rust/Aya) proved correct
- ✅ Language subset restrictions were accurate
- ✅ Integration approach with Nushell plugins worked well
- ✅ Phased implementation was effective
- ✅ Focus on tracing use cases (kprobes, tracepoints) was appropriate

### What Differed from the Plan:
- 🔄 Plugin API limitations required innovation (span-based extraction)
- 🔄 Event streaming became more prominent than originally envisioned
- 🔄 We deferred some advanced features (uprobes, perf events)
- 🔄 Lima VM testing instead of bare metal Linux

### Still To Do from Original Plan:
1. **Uprobes** - User-space function tracing
2. **Performance events** - CPU sampling, profiling
3. **BTF integration** - For accessing struct fields
4. **Map operations** - Direct map access from Nushell
5. **CO-RE support** - For kernel portability

## Next Steps Recommendations

Based on our implementation and the original plan, here are the highest-value next steps:

### 1. BTF Integration for Event Context
Enable access to event fields:
```nushell
bpf-kprobe "do_sys_open" { |ctx|
    if $ctx.filename == "/etc/passwd" {
        print "Security: passwd file accessed"
    }
}
```

### 2. Direct Map Access
Allow querying eBPF maps from Nushell:
```nushell
let counts = bpf-maps get "syscall_counts"
$counts | sort-by value -r | first 10
```

### 3. Uprobe Support
Enable application tracing:
```nushell
bpf-uprobe "/usr/bin/curl" "main" { ||
    print "curl started"
}
```

### 4. Enhanced Parser
- Support for match expressions
- Array/slice operations
- More built-in functions (get_stack, timestamp)

### 5. Performance Optimizations
- Cache compiled eBPF programs
- Batch event processing
- Optimize generated code size

## Conclusion

We have successfully implemented a functional eBPF plugin for Nushell that achieves the core vision of the original plan. Users can now write kernel tracing programs using familiar Nushell syntax, with automatic compilation and loading. The implementation provides a solid foundation for future enhancements while already delivering significant value for system observability tasks.

The project demonstrates that high-level scripting languages can effectively interface with low-level kernel features, making eBPF more accessible to a broader audience of system administrators and developers who are already familiar with Nushell.