# nu-ebpf

eBPF integration for Nushell. Write kernel tracing programs using Nushell closures.

## Overview

This crate enables writing eBPF programs directly in Nushell syntax. Closures are compiled to eBPF bytecode and loaded into the Linux kernel to trace system calls, kernel functions, and more.

```nushell
# Trace all file opens and show which processes are opening files
let id = ebpf attach 'kprobe:do_sys_openat2' {||
    { pid: (bpf-tgid), comm: (bpf-comm) } | bpf-emit
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
| `ebpf counters <id>` | Display counter values from `bpf-count` |
| `ebpf histogram <id>` | Display histogram from `bpf-histogram` |

### Probe Types

The probe specification format is `type:target`:

| Type | Example | Description |
|------|---------|-------------|
| `kprobe` | `kprobe:do_sys_openat2` | Trace kernel function entry |
| `kretprobe` | `kretprobe:do_sys_openat2` | Trace kernel function return |
| `tracepoint` | `tracepoint:syscalls/sys_enter_read` | Trace static tracepoint |

### BPF Helper Commands

These commands work both at regular runtime (for testing) and compile to eBPF bytecode:

#### Data Collection

| Command | Description |
|---------|-------------|
| `bpf-tgid` | Get process ID (thread group ID) |
| `bpf-pid` | Get full pid_tgid value |
| `bpf-uid` | Get user ID |
| `bpf-ktime` | Get kernel monotonic time (nanoseconds) |
| `bpf-comm` | Get process name (first 8 bytes as int) |
| `bpf-arg <n>` | Read nth function argument (0-5) |
| `bpf-retval` | Read function return value (kretprobe only) |

#### Output

| Command | Description |
|---------|-------------|
| `bpf-emit` | Emit value or record to perf buffer |
| `bpf-emit-comm` | Emit full process name (16 bytes) |
| `bpf-read-str` | Read string from kernel memory pointer |
| `bpf-read-user-str` | Read string from user-space memory pointer |

#### Aggregation

| Command | Description |
|---------|-------------|
| `bpf-count` | Increment counter keyed by input value |
| `bpf-histogram` | Add value to log2 histogram |
| `bpf-start-timer` | Start latency timer (store ktime by TID) |
| `bpf-stop-timer` | Stop timer and return elapsed nanoseconds |

#### Filtering

| Command | Description |
|---------|-------------|
| `bpf-filter-pid <pid>` | Exit early if TGID doesn't match |
| `bpf-filter-comm <name>` | Exit early if comm doesn't match |

## Examples

### Trace System Calls

```nushell
# Watch which processes are reading files
let id = ebpf attach 'kprobe:ksys_read' {||
    bpf-tgid | bpf-emit
}
sleep 2sec
ebpf events $id | uniq-by value | each { get value }
ebpf detach $id
```

### Count Events by Process

```nushell
# Count read() calls per process
let id = ebpf attach 'kprobe:ksys_read' {||
    bpf-comm | bpf-count
}
sleep 5sec
ebpf counters $id | sort-by count --reverse
ebpf detach $id
```

### Structured Events

```nushell
# Emit structured events with multiple fields
let id = ebpf attach 'kprobe:do_sys_openat2' {||
    { pid: (bpf-tgid), uid: (bpf-uid), time: (bpf-ktime) } | bpf-emit
}
sleep 1sec
ebpf events $id
ebpf detach $id
```

### Filter by Process

```nushell
# Only trace events from nginx
let id = ebpf attach 'kprobe:ksys_read' {||
    bpf-filter-comm 'nginx'
    bpf-tgid | bpf-emit
}
```

### Latency Histogram

```nushell
# Measure read() latency distribution
let entry = ebpf attach 'kprobe:ksys_read' {|| bpf-start-timer }
let ret = ebpf attach 'kretprobe:ksys_read' {|| bpf-stop-timer | bpf-histogram }

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
# Trace file paths being opened
let id = ebpf attach 'kprobe:do_sys_openat2' {||
    bpf-arg 1 | bpf-read-user-str
}
sleep 2sec
ebpf events $id
ebpf detach $id
```

### Dry Run (Generate Bytecode)

```nushell
# Generate eBPF ELF without loading into kernel
ebpf attach --dry-run 'kprobe:ksys_read' {|| bpf-tgid | bpf-emit } | save probe.elf
```

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Nushell Closure │ --> │  IR Compiler     │ --> │  eBPF Bytecode  │
│  {|| bpf-tgid }  │     │  (ir_to_ebpf.rs) │     │  (ELF binary)   │
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
3. Recognizes `bpf-*` commands and emits corresponding BPF helper calls
4. Generates proper ELF with BTF (BPF Type Format) for kernel loading
5. Uses [aya](https://github.com/aya-rs/aya) to load and attach the program

## Limitations

- **Linux only**: eBPF is a Linux kernel feature
- **Limited control flow**: Complex conditionals and loops may not compile
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
