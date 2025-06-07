# Potential Language Extensions for eBPF Plugin

## Current Language Support

### What We Support Now
- Basic expressions and operators
- eBPF built-in variables ($pid, $uid, $comm)
- Simple function calls (print, count, emit)
- If/else conditionals
- String and integer literals

### What We Could Add

## 1. The `where` Keyword

The `where` keyword is natural for Nushell users and could be translated to conditionals:

```nushell
# Current approach:
bpf-kprobe "sys_read" { |event|
    if $event.size > 1024 {
        emit($event)
    }
}

# With 'where' support:
bpf-kprobe "sys_read" { |event|
    where $event.size > 1024
    emit($event)
}

# Or even more Nushell-like:
bpf-kprobe "sys_read" { |event|
    $event | where size > 1024 | emit
}
```

**Implementation**: We'd parse `where` as syntactic sugar for `if`, generating the same eBPF code.

## 2. Event Field Access

Currently we only support built-in variables. With BTF integration, we could access event fields:

```nushell
# Access syscall arguments
bpf-tracepoint "syscalls:sys_enter_open" { |args|
    if $args.filename == "/etc/passwd" {
        print "Security: passwd accessed"
    }
}

# Access kernel struct fields
bpf-kprobe "tcp_sendmsg" { |ctx|
    if $ctx.sk.sk_family == AF_INET {
        emit($ctx.sk.sk_daddr)  # Destination IP
    }
}
```

**Implementation**: Requires BTF parsing and field offset resolution at compile time.

## 3. Pattern Matching

Nushell's `match` expression could be powerful for eBPF:

```nushell
bpf-kprobe "sys_open" { ||
    match $uid {
        0 => print "Root file access"
        1000 => count()
        _ => {
            if $pid > 10000 {
                emit("high_pid_access")
            }
        }
    }
}
```

**Implementation**: Translate to chained if/else in generated code.

## 4. Enhanced Built-in Functions

### Stack Traces
```nushell
bpf-kprobe "kmalloc" { ||
    if $size > 1048576 {  # 1MB
        let stack = get_stack()
        emit({
            size: $size,
            stack: $stack
        })
    }
}
```

### Timestamps for Latency
```nushell
bpf-kprobe "sys_read" { ||
    let start = timestamp()
    # Store in map for kretprobe
    set_context($pid, $start)
}

bpf-kretprobe "sys_read" { ||
    let start = get_context($pid)
    let latency = timestamp() - $start
    if $latency > 1000000 {  # 1ms
        print "Slow read detected"
    }
}
```

### String Operations
```nushell
bpf-kprobe "do_sys_open" { |ctx|
    if str_contains($ctx.filename, "secret") {
        emit("sensitive_file_access")
    }
}
```

## 5. Map Operations

Direct map manipulation for advanced use cases:

```nushell
# Define and use maps
let counts = bpf-map create hash<int, int> 1024

bpf-kprobe "sys_read" { ||
    let current = map_get($counts, $pid) ?? 0
    map_set($counts, $pid, $current + 1)
}

# Query from Nushell
bpf-map read $counts | where value > 100
```

## 6. Limited Loops

While general loops are forbidden in eBPF, bounded loops are possible:

```nushell
# Bounded loop for string comparison (unrolled at compile time)
bpf-kprobe "sys_open" { |ctx|
    for i in 0..16 {  # Max 16 chars
        if $ctx.filename[i] == 0 { break }
        # Process char
    }
}
```

**Implementation**: Unroll at compile time, ensure bounds are static.

## 7. Record/Struct Construction

Build structured data for emission:

```nushell
bpf-kprobe "tcp_connect" { |ctx|
    emit({
        timestamp: timestamp(),
        pid: $pid,
        comm: $comm,
        dest_ip: $ctx.daddr,
        dest_port: $ctx.dport
    })
}
```

## 8. Pipeline-Style Operations

Limited pipeline operations that can be compiled to eBPF:

```nushell
bpf-kprobe "sys_write" { ||
    $pid 
    | if $in > 1000 { $in } else { 0 }
    | if $in != 0 { count() }
}
```

## 9. Constants and Compile-Time Values

Allow capturing Nushell constants:

```nushell
const THRESHOLD = 1024
const ALLOWED_UIDS = [1000, 1001, 1002]

bpf-kprobe "sys_read" { ||
    if $size > THRESHOLD && $uid in ALLOWED_UIDS {
        emit("large_read")
    }
}
```

## 10. Type Annotations

Optional type hints for better code generation:

```nushell
bpf-kprobe "vfs_write" { |ctx: VfsWriteContext|
    let bytes: int = $ctx.count
    if $bytes > 1mb {  # Unit conversions
        print "Large write detected"
    }
}
```

## Implementation Priorities

Based on user value and implementation complexity:

### High Priority (High Value, Moderate Complexity)
1. **Event field access** - Most requested feature
2. **where keyword** - Natural for Nushell users
3. **Enhanced built-ins** (timestamp, get_stack)
4. **Map operations** - Essential for stateful analysis

### Medium Priority
5. **Pattern matching** - Nice syntax sugar
6. **Record construction** - Better event data
7. **Constants** - Improves maintainability

### Low Priority (Complex or Niche)
8. **Bounded loops** - Tricky to verify
9. **Pipeline operations** - Complex translation
10. **Type annotations** - More of a nice-to-have

## Conclusion

These extensions would make the eBPF plugin feel more native to Nushell while staying within eBPF's constraints. The key is maintaining the balance between Nushell's expressiveness and eBPF's safety requirements.