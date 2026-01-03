# nu-ebpf

eBPF integration for Nushell. Write kernel tracing programs using Nushell closures.

## Overview

This crate enables writing eBPF programs directly in Nushell syntax. Closures are compiled to eBPF bytecode and loaded into the Linux kernel to trace system calls, kernel functions, and more.

```nushell
# Trace all file opens and show which processes are opening files
let id = ebpf attach 'kprobe:do_sys_openat2' {|ctx|
    { pid: $ctx.pid, comm: $ctx.comm } | emit
}
sleep 5sec
ebpf events $id
ebpf detach $id
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
| `ebpf events <id>` | Poll events from a probe's perf buffer |
| `ebpf counters <id>` | Display counter values from `count` |
| `ebpf histogram <id>` | Display histogram from `histogram` |

### Probe Types

The probe specification format is `type:target`:

| Type | Example | Description |
|------|---------|-------------|
| `kprobe` | `kprobe:do_sys_openat2` | Trace kernel function entry |
| `kretprobe` | `kretprobe:do_sys_openat2` | Trace kernel function return |
| `tracepoint` | `tracepoint:syscalls/sys_enter_read` | Trace static tracepoint |

### Context Fields

Access probe context via the closure parameter `{|ctx| ... }`:

| Field | Description |
|-------|-------------|
| `$ctx.pid` | Process ID (thread group ID) |
| `$ctx.uid` | User ID |
| `$ctx.ktime` | Kernel monotonic time (nanoseconds) |
| `$ctx.comm` | Process name (16-byte string) |
| `$ctx.arg0` - `$ctx.arg5` | Function arguments (kprobe) |
| `$ctx.ret` | Return value (kretprobe only) |

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
| `emit` | Emit value, string, or record to perf buffer |
| `read-str` | Read string from userspace memory pointer |
| `read-kernel-str` | Read string from kernel memory pointer |

#### Aggregation

| Command | Description |
|---------|-------------|
| `count` | Increment counter keyed by input value |
| `histogram` | Add value to log2 histogram |
| `start-timer` | Start latency timer (store ktime by TID) |
| `stop-timer` | Stop timer and return elapsed nanoseconds |

## Examples

### Trace System Calls

```nushell
# Watch which processes are reading files
let id = ebpf attach 'kprobe:ksys_read' {|ctx|
    $ctx.pid | emit
}
sleep 2sec
ebpf events $id | uniq-by value | each { get value }
ebpf detach $id
```

### Count Events by Process

```nushell
# Count read() calls per process
let id = ebpf attach 'kprobe:ksys_read' {|ctx|
    $ctx.comm | count
}
sleep 5sec
ebpf counters $id | sort-by count --reverse
ebpf detach $id
```

### Structured Events

```nushell
# Emit structured events with multiple fields
let id = ebpf attach 'kprobe:do_sys_openat2' {|ctx|
    { pid: $ctx.pid, uid: $ctx.uid, time: $ctx.ktime } | emit
}
sleep 1sec
ebpf events $id
ebpf detach $id
```

### Conditional Tracing

```nushell
# Only emit events for a specific PID
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
let id = ebpf attach 'kprobe:do_sys_openat2' {|ctx|
    $ctx.arg1 | read-str
}
sleep 2sec
ebpf events $id
ebpf detach $id
```

### Dry Run (Generate Bytecode)

```nushell
# Generate eBPF ELF without loading into kernel
ebpf attach --dry-run 'kprobe:ksys_read' {|ctx| $ctx.pid | emit } | save probe.elf
```

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Nushell Closure │ --> │  IR Compiler     │ --> │  eBPF Bytecode  │
│  {|ctx| $ctx.pid}│     │  (ir_to_ebpf.rs) │     │  (ELF binary)   │
└─────────────────┘     └──────────────────┘     └─────────────────┘
                                                          │
                                                          v
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  ebpf events    │ <-- │  Perf Buffer     │ <-- │  Kernel (aya)   │
│  (userspace)    │     │  (events map)    │     │  (BPF verifier) │
└─────────────────┘     └──────────────────┘     └─────────────────┘
```

The compiler:
1. Takes Nushell's IR (intermediate representation) from the closure
2. Translates IR instructions to eBPF bytecode
3. Recognizes context field access (`$ctx.pid`, etc.) and emits BPF helper calls
4. Generates proper ELF with BTF (BPF Type Format) for kernel loading
5. Uses [aya](https://github.com/aya-rs/aya) to load and attach the program

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
