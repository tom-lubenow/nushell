# eBPF Development Setup for Nushell

This repository contains a fork of Nushell prepared for offline eBPF development work. The goal is to implement eBPF scripting capabilities within Nushell using the Rust/Aya codegen approach.

**Development Note**: This setup is designed to work across platforms - you can develop on ARM64 macOS, x86_64 Linux, or any Docker-supported platform. The container will automatically use the appropriate architecture and toolchain.

## Quick Start

### 1. Container Setup

This setup is designed to work with the [codex-universal](https://github.com/openai/codex-universal) Docker container:

```bash
# Pull the base container
docker pull ghcr.io/openai/codex-universal:latest

# Run the container with this repository mounted
docker run --rm -it \
    --privileged \
    --cap-add=SYS_ADMIN \
    --cap-add=BPF \
    -v $(pwd):/workspace \
    -w /workspace \
    ghcr.io/openai/codex-universal:latest
```

### 2. Run Setup Script

Inside the container, execute the setup script to prepare for offline development:

```bash
# This will download all dependencies, documentation, and tools
./container_setup.sh
```

**Important**: After this script completes, internet access will be cut off, but you'll have everything needed for development.

### 3. Start Development

```bash
# Source the environment (includes Rust setup)
source /workspace/offline_resources/setup_env.sh

# Load helper functions
source /workspace/offline_resources/dev_helpers.sh

# Check BPF capabilities
check_bpf

# Verify Rust is available
rustc --version

# Start developing!
```

## What Gets Installed

The setup script prepares the container with:

### Core Dependencies
- **Rust toolchain** with nightly (for `-Z build-std`)
- **bpf-linker** - Converts LLVM bitcode to eBPF bytecode (pure Rust)
- **eBPF tools**: `bpftool`, `clang`, `llvm` (for bpf-linker)
- **Development tools**: `gdb`, `strace`, `valgrind`, etc.

**Note**: Aya is pure Rust and does NOT require `libbpf`, `bcc`, or `cargo-bpf`

### eBPF Framework and Examples
- **Aya** - Pure Rust eBPF framework (our only dependency!)
- **XDP tutorial** - Learning examples for eBPF concepts

### Documentation
- Kernel BPF documentation (offline mirror)
- BPF helpers man pages
- eBPF instruction set documentation
- Brendan Gregg's BPF performance tools

### Kernel Resources
- BTF type information (`vmlinux.btf`)
- Kernel types header (`vmlinux.h`)
- Kernel headers for development

## Development Workflow

### Phase 1: Research & Design
- Study Nushell's IR/AST structure in `/workspace/nushell/src/`
- Examine Aya examples in `/workspace/offline_resources/repos/aya/examples/`
- Design the Nushell-to-eBPF transpiler architecture

### Phase 2: Minimal Prototype
- Implement basic `bpf_probe` command in Nushell
- Create simple kprobe that prints messages
- Establish end-to-end compilation pipeline

### Phase 3: Basic Codegen
- Implement Nushell closure → Rust eBPF code generation
- Add support for basic expressions and conditionals
- Integrate with Aya for program loading

### Phase 4: Language Expansion
- Support more Nushell constructs (variables, arithmetic, etc.)
- Add tracepoints, uprobes, and other probe types
- Implement BPF-specific built-ins (`count()`, `emit()`, etc.)

### Phase 5: Polish & Optimization
- Error handling and debugging support
- Performance optimizations
- Documentation and examples

## Key Files and Directories

```
/workspace/nushell/                   # Main Nushell repository
├── container_setup.sh               # Setup script (run once)
├── IMPLEMENTATION_PLAN.md           # Detailed implementation plan
├── README_EBPF_SETUP.md            # This file
└── offline_resources/               # Created by setup script
    ├── docs/                        # eBPF documentation
    ├── repos/                       # eBPF repositories
    │   ├── aya/                     # Pure Rust eBPF framework
    │   └── xdp-tutorial/            # Learning examples
    ├── kernel/                      # Kernel headers and BTF
    ├── setup_env.sh                 # Environment setup
    ├── dev_helpers.sh               # Development utilities
    ├── OFFLINE_DEVELOPMENT_GUIDE.md # Offline development guide
    └── EBPF_QUICK_REFERENCE.md      # eBPF quick reference
```

## Helper Commands

After sourcing the helper scripts, you have access to:

```bash
# Check BPF system capabilities
check_bpf

# Generate vmlinux.h from BTF
generate_vmlinux_h

# Build an Aya eBPF program
build_aya_program /path/to/program

# Show available examples
show_examples
```

## Nushell eBPF Integration Points

Based on the implementation plan, key integration points include:

### 1. Command Interface
```nushell
# Proposed syntax for eBPF commands
bpf_probe kernel:function("do_sys_open") {|event| 
    if $event.filename == "secret.txt" { 
        send($event.pid) 
    } 
}

bpf_tracepoint syscalls:sys_enter_openat {|event|
    count()
}
```

### 2. Code Generation Pipeline
1. Parse Nushell closure AST
2. Generate Rust eBPF code using Aya macros
3. Compile with `cargo +nightly build --target bpfel-unknown-none -Z build-std=core`
4. Link with `bpf-linker` (LLVM bitcode → eBPF bytecode)
5. Load and attach using Aya userspace API

### 3. Data Flow
- **Kernel → Userspace**: Ring buffers, perf events, BPF maps
- **Nushell Integration**: Stream events as Nushell tables/records
- **Pipeline Support**: Pipe eBPF output to other Nushell commands

## Requirements

- **Privileged container**: eBPF requires `CAP_SYS_ADMIN` or `CAP_BPF`
- **Modern kernel**: Linux 5.4+ recommended for BTF support
- **Rust nightly**: Required for eBPF target compilation
- **Cross-platform note**: This setup works on any Docker-supported platform (ARM64 macOS, x86_64 Linux, etc.) - the container will use the appropriate architecture

## Troubleshooting

### BPF Not Available
```bash
# Check if BPF is supported
check_bpf

# Verify container capabilities
capsh --print | grep bpf
```

### Missing BTF
```bash
# Check BTF availability
ls -la /sys/kernel/btf/vmlinux

# Generate vmlinux.h manually if needed
generate_vmlinux_h
```

### Compilation Issues
```bash
# Verify Rust BPF targets
rustup target list --installed | grep bpf

# Check bpf-linker installation
which bpf-linker
```

## References

- [Implementation Plan](IMPLEMENTATION_PLAN.md) - Detailed technical plan
- [Aya Book](https://aya-rs.dev/book/) - Aya framework documentation
- [Nushell Book](https://www.nushell.sh/book/) - Nushell language guide
- [eBPF Documentation](https://docs.kernel.org/bpf/) - Kernel eBPF docs

## Contributing

This is experimental work to add eBPF capabilities to Nushell. The implementation follows the phased approach outlined in `IMPLEMENTATION_PLAN.md`.

Key principles:
- **Beauty in code** - Strive for elegant solutions
- **Thoughtful development** - State assumptions and verify with testing
- **Incremental progress** - Build working prototypes at each phase

## Known Issues

- **BPF targets availability**: BPF targets (`bpfel-unknown-none`, `bpfeb-unknown-none`) are Tier 3 targets and not always available in every nightly Rust build. This is normal and expected:
  - **Aya works regardless**: Aya uses `bpf-linker` which processes LLVM bitcode, so it can work even without BPF targets
  - The setup script handles this gracefully and provides appropriate messaging
  - If targets are missing, you can still develop and research eBPF concepts
- **Rust environment**: If `rustc` is not found after setup, make sure to source the environment: `source /workspace/offline_resources/setup_env.sh`
- Some Linux distributions may not have the latest kernel headers
- bpftool installation may fail on some systems (the script handles this gracefully)
- Container needs privileged mode for eBPF development

---

**Note**: This setup is designed for offline development. After running `container_setup.sh`, no internet access is required for development work. 