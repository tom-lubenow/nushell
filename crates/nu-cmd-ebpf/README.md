# nu-cmd-ebpf

This crate contains Nushell's eBPF commands for Linux kernel tracing and monitoring.

## Commands

- `bpf-kprobe` - Attach eBPF programs to kernel probes
- `bpf-uprobe` - Attach eBPF programs to user-space probes (future)
- `bpf-tracepoint` - Attach eBPF programs to tracepoints (future)

## Requirements

- Linux kernel 4.18+ with eBPF support
- Root or CAP_BPF capability
- BTF (BPF Type Format) enabled kernel

## Features

- Real-time kernel event monitoring
- Custom filtering and data collection
- Integration with Nushell's type system
- Safe eBPF code generation from Nushell expressions

## Platform Support

These commands are only available on Linux systems and require appropriate permissions.