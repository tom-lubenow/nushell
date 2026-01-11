# nu-ebpf

eBPF integration for Nushell. Write kernel tracing programs using Nushell closures.

## Overview

This crate enables writing eBPF programs directly in Nushell syntax. Closures are compiled to eBPF bytecode and loaded into the Linux kernel to trace system calls, kernel functions, and more.

```nushell
# Trace all file opens and show which processes are opening files
ebpf attach -s 'kprobe:do_sys_openat2' {|ctx|
    { pid: $ctx.pid, comm: $ctx.comm } | emit
} | first 10
```

## Requirements

- **Linux kernel 4.18+** with eBPF support
- **Root access** or `CAP_BPF` capability
- Currently supports **x86_64** and **aarch64** architectures

## Commands

### Probe Management

| Command | Description |
|---------|-------------|
| `ebpf attach <probe> {closure}` | Compile and attach an eBPF probe |
| `ebpf detach <id>` | Detach a probe by ID |
| `ebpf list` | List all active probes |
| `ebpf attach -s` | Stream events directly (with --stream flag) |
| `ebpf counters <id>` | Display counter values from `count` |
| `ebpf histogram <id>` | Display histogram from `histogram` |
| `ebpf stacks <id>` | Display stack traces from `$ctx.kstack`/`$ctx.ustack` |

### Probe Types

The probe specification format is `type:target`:

| Type | Example | Description |
|------|---------|-------------|
| `kprobe` | `kprobe:do_sys_openat2` | Kernel function entry |
| `kretprobe` | `kretprobe:do_sys_openat2` | Kernel function return |
| `tracepoint` | `tracepoint:syscalls/sys_enter_read` | Kernel tracepoint |
| `uprobe` | `uprobe:/bin/bash:readline` | Userspace function entry |
| `uretprobe` | `uretprobe:/bin/bash:readline` | Userspace function return |

### Context Fields

Access probe context via the closure parameter `{|ctx| ... }`:

| Field | Description |
|-------|-------------|
| `$ctx.pid` | Thread ID (what Linux calls pid) |
| `$ctx.tgid` | Process ID (thread group ID) |
| `$ctx.uid` | User ID |
| `$ctx.gid` | Group ID |
| `$ctx.ktime` | Kernel monotonic time (nanoseconds) |
| `$ctx.comm` | Process name (8-byte string) |
| `$ctx.arg0` - `$ctx.arg5` | Function arguments (kprobe/uprobe) |
| `$ctx.retval` | Return value (kretprobe/uretprobe only) |
| `$ctx.kstack` | Kernel stack trace ID |
| `$ctx.ustack` | User stack trace ID |

For tracepoints, context fields are read from the kernel's format specification:
```nushell
# syscalls/sys_enter_openat tracepoint fields
ebpf attach 'tracepoint:syscalls/sys_enter_openat' {|ctx|
    { dfd: $ctx.dfd, filename: $ctx.filename, flags: $ctx.flags } | emit
}
```

### Helper Commands

These commands are used inside eBPF closures:

#### Output

| Command | Description |
|---------|-------------|
| `emit` | Emit value, string, or record to ring buffer |
| `read-str` | Read string from userspace memory pointer |
| `read-kernel-str` | Read string from kernel memory pointer |

#### Control Flow

| Command | Description |
|---------|-------------|
| `filter` | Exit program early if condition is false |

#### Aggregation

| Command | Description |
|---------|-------------|
| `count` | Increment counter keyed by input value (supports both integers like `$ctx.pid` and strings like `$ctx.comm`) |
| `histogram` | Add value to log2 histogram |
| `start-timer` | Start latency timer (store ktime by TID) |
| `stop-timer` | Stop timer and return elapsed nanoseconds |

## Examples

### Trace System Calls

```nushell
# Watch which processes are reading files (stream 100 events)
ebpf attach -s 'kprobe:ksys_read' {|ctx|
    $ctx.pid | emit
} | first 100 | uniq-by value | each { get value }
```

### Count Events by Process

```nushell
# Count read() calls per process name
let id = ebpf attach 'kprobe:ksys_read' {|ctx|
    $ctx.comm | count
}
sleep 5sec
ebpf counters $id | sort-by count --reverse
ebpf detach $id
```

### Count Events by PID

```nushell
# Count read() calls per PID
let id = ebpf attach 'kprobe:ksys_read' {|ctx|
    $ctx.pid | count
}
sleep 5sec
ebpf counters $id | sort-by count --reverse
ebpf detach $id
```

### Structured Events

```nushell
# Emit structured events with multiple fields
ebpf attach -s 'kprobe:do_sys_openat2' {|ctx|
    { pid: $ctx.pid, uid: $ctx.uid, time: $ctx.ktime } | emit
} | first 10
```

### Filtering Events

```nushell
# Only emit events for root user (uid == 0)
ebpf attach -s 'kprobe:do_sys_openat2' {|ctx|
    if $ctx.uid == 0 { $ctx.pid | emit }
} | first 10

# Filter by process name
ebpf attach -s 'kprobe:ksys_read' {|ctx|
    if $ctx.comm == "nginx" { { pid: $ctx.pid, comm: $ctx.comm } | emit }
} | first 10
```

### Conditional Tracing

```nushell
# Use if for more complex conditions
let id = ebpf attach 'kprobe:ksys_read' {|ctx|
    if $ctx.pid == 1234 {
        $ctx.pid | emit
    }
}
```

### Bounded Loops

```nushell
# Loops with compile-time known bounds are supported (requires kernel 5.3+)
let id = ebpf attach 'kprobe:ksys_read' {|ctx|
    for i in 1..5 {
        # Loop body executes 4 times (1, 2, 3, 4)
        $i | count
    }
}
```

Note: Only ranges with literal integer bounds are supported (e.g., `1..10`, `1..=5`).
Dynamic iterators and unbounded loops are not supported in eBPF.

### Latency Histogram

```nushell
# Measure read() latency distribution using shared maps
let entry = ebpf attach --pin lat 'kprobe:ksys_read' {|ctx| start-timer }
let ret = ebpf attach --pin lat 'kretprobe:ksys_read' {|ctx| stop-timer | histogram }

sleep 5sec

ebpf histogram $ret --ns
ebpf detach $entry
ebpf detach $ret
```

Output:
```
╭───┬────────┬─────────────┬───────┬──────────────────────────────────────────╮
│ # │ bucket │    range    │ count │                   bar                    │
├───┼────────┼─────────────┼───────┼──────────────────────────────────────────┤
│ 0 │     10 │ 512ns - 1us │   127 │ ########                                 │
│ 1 │     11 │ 1us - 2us   │   584 │ ######################################## │
│ 2 │     12 │ 2us - 4us   │   312 │ #####################                    │
│ 3 │     13 │ 4us - 8us   │    89 │ ######                                   │
│ 4 │     14 │ 8us - 16us  │    23 │ ##                                       │
╰───┴────────┴─────────────┴───────┴──────────────────────────────────────────╯
```

### Reading String Arguments

```nushell
# Trace file paths being opened (read from userspace pointer)
ebpf attach -s 'kprobe:do_sys_openat2' {|ctx|
    $ctx.arg1 | read-str
} | first 10
```

### Stack Traces

```nushell
# Capture kernel stack traces for file opens
let id = ebpf attach 'kprobe:do_sys_openat2' {|ctx|
    { pid: $ctx.pid, kstack: $ctx.kstack } | emit
}
sleep 2sec
ebpf stacks $id --symbolize
ebpf detach $id
```

Output:
```
╭───┬────┬────────┬─────────────────────────────────────────────────────────╮
│ # │ id │  type  │                         frames                          │
├───┼────┼────────┼─────────────────────────────────────────────────────────┤
│ 0 │ 42 │ kernel │ [do_sys_openat2+0x0, __x64_sys_openat+0x55, ...]        │
│ 1 │ 43 │ kernel │ [do_sys_openat2+0x0, __x64_sys_open+0x1d, ...]          │
╰───┴────┴────────┴─────────────────────────────────────────────────────────╯
```

The `--symbolize` flag resolves kernel addresses to function names via `/proc/kallsyms`.
Note: Reading `/proc/kallsyms` may require root or `kernel.kptr_restrict=0`.

### Dry Run (Generate Bytecode)

```nushell
# Generate eBPF ELF without loading into kernel
ebpf attach --dry-run 'kprobe:ksys_read' {|ctx| $ctx.pid | emit } | save probe.elf
```

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Nushell Closure │ --> │  MIR Compiler    │ --> │  eBPF Bytecode  │
│  {|ctx| $ctx.pid}│     │                  │     │  (ELF binary)   │
└─────────────────┘     └──────────────────┘     └─────────────────┘
                                                          │
                                                          v
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  ebpf attach -s │ <-- │  Ring Buffer     │ <-- │  Kernel (aya)   │
│  (userspace)    │     │  (events map)    │     │  (BPF verifier) │
└─────────────────┘     └──────────────────┘     └─────────────────┘
```

The compiler pipeline:
1. **IR → MIR**: Lowers Nushell IR to Mid-level IR with virtual registers
2. **CFG Analysis**: Builds control flow graph, computes liveness
3. **Optimization**: Dead code elimination, constant folding
4. **Register Allocation**: Linear scan allocation to eBPF registers
5. **Code Generation**: Emits eBPF bytecode with map relocations
6. **Loading**: Uses [aya](https://github.com/aya-rs/aya) to load into kernel

## Limitations

- **Linux only**: eBPF is a Linux kernel feature
- **Bounded loops only**: Loops require compile-time known bounds (e.g., `for i in 1..10`). Dynamic iterators are not supported.
- **No strings in eBPF**: String operations happen at emit time or userspace
- **Stack limit**: eBPF programs have a 512-byte stack limit
- **Verifier constraints**: The kernel verifier may reject some valid-looking programs

## Troubleshooting

### "Permission denied"
Run with `sudo` or grant `CAP_BPF` capability.

### "Invalid probe specification"
Check format: `kprobe:function_name` or `tracepoint:category/name`.
Use `cat /proc/kallsyms | grep function_name` to verify the function exists.

### "eBPF compilation failed"
The closure uses unsupported operations. Simplify the logic or check error message.

### "Failed to attach probe"
The kernel function may not exist or be traceable. Some functions are inlined or have different names across kernel versions.

## License

This crate is part of Nushell and is licensed under the MIT license.
