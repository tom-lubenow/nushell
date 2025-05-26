# Container Setup Summary for eBPF Development

This repository has been prepared for offline eBPF development work with Nushell. Here's what has been set up:

## 🎯 Objective

Implement eBPF scripting capabilities within Nushell using the Rust/Aya codegen approach, allowing users to write eBPF programs using Nushell's modern pipeline syntax.

## 📁 Repository Structure

```
nushell/                              # Nushell fork repository
├── container_setup.sh               # 🔧 Main setup script (run in container)
├── README_EBPF_SETUP.md            # 📖 Setup and usage guide
├── CONTAINER_SETUP_SUMMARY.md      # 📋 This summary
├── IMPLEMENTATION_PLAN.md          # 📝 Detailed technical plan
├── ebpf_dev/                       # 🧪 eBPF development workspace
│   ├── README.md                   # Development guide
│   ├── docs/                       # Development documentation
│   │   └── nushell_internals_reference.md
│   ├── examples/                   # Example programs (to be created)
│   └── prototypes/                 # Prototype implementations
├── external/                       # 📚 External dependencies
│   └── aya/                        # Aya eBPF framework (submodule)
└── offline_resources/              # 🔄 Created by setup script
    ├── repos/                      # eBPF framework repositories
    ├── docs/                       # Offline documentation
    ├── kernel/                     # Kernel headers and BTF
    ├── setup_env.sh               # Environment setup
    ├── dev_helpers.sh              # Development utilities
    └── *.md                        # Guides and references
```

## 🚀 Quick Start Workflow

### 1. Container Launch
```bash
# Pull the codex-universal container
docker pull ghcr.io/openai/codex-universal:latest

# Run with this repository mounted
docker run --rm -it \
    --privileged \
    --cap-add=SYS_ADMIN \
    --cap-add=BPF \
    -v $(pwd):/workspace \
    -w /workspace \
    ghcr.io/openai/codex-universal:latest
```

### 2. Setup for Offline Work
```bash
# Inside the container, run the setup script
./container_setup.sh
```

**This script will**:
- Install all eBPF development tools (`bpftool`, `clang`, `llvm`)
- Set up Rust with BPF targets (`bpfel-unknown-none`, `bpfeb-unknown-none`)
- Clone eBPF frameworks (Aya, libbpf, bpftrace, BCC, RedBPF)
- Download offline documentation and examples
- Cache Rust dependencies for common eBPF crates
- Generate kernel headers and BTF information
- Create helper scripts and development guides

### 3. Start Development (Offline)
```bash
# Source the environment
source /workspace/offline_resources/setup_env.sh

# Load helper functions
source /workspace/offline_resources/dev_helpers.sh

# Check BPF capabilities
check_bpf

# Begin Phase 1: Research Nushell internals
cd /workspace/ebpf_dev
```

## 🎯 Development Phases

### Phase 1: Research & Design *(Current)*
- **Goal**: Understand Nushell's IR/AST and design transpiler architecture
- **Key Tasks**: Study parser, AST structure, closure representation
- **Deliverable**: Architecture design for Nushell → eBPF pipeline

### Phase 2: Minimal Prototype
- **Goal**: Basic `bpf_probe` command with hardcoded eBPF program
- **Key Tasks**: Command structure, Aya integration, kprobe attachment
- **Deliverable**: Working end-to-end proof of concept

### Phase 3: Basic Codegen
- **Goal**: Nushell closure → Rust eBPF code generation
- **Key Tasks**: AST analysis, code generation, runtime compilation
- **Deliverable**: Dynamic eBPF program generation from Nushell

### Phase 4: Language Expansion
- **Goal**: Support more Nushell constructs and probe types
- **Key Tasks**: Expressions, conditionals, tracepoints, uprobes
- **Deliverable**: Feature-complete eBPF DSL within Nushell

### Phase 5: Polish & Optimization
- **Goal**: Production-ready implementation
- **Key Tasks**: Error handling, performance, documentation
- **Deliverable**: Stable, documented eBPF integration

## 🛠️ What's Available Offline

### eBPF Frameworks
- **Aya** - Primary Rust eBPF framework (pure Rust, no libbpf dependency)
- **libbpf** - C eBPF library for reference
- **bpftrace** - High-level tracing language for comparison
- **BCC** - BPF Compiler Collection for reference
- **RedBPF** - Alternative Rust framework

### Documentation
- Kernel BPF documentation (offline mirror)
- BPF helpers man pages
- eBPF instruction set documentation
- Brendan Gregg's BPF performance tools
- Rust documentation (cached)

### Development Tools
- `bpftool` - BPF introspection and debugging
- `cargo-bpf` - Cargo extension for BPF development
- `bpf-linker` - BPF program linker
- Standard debugging tools (`gdb`, `strace`, `valgrind`)

### Kernel Resources
- BTF type information (`vmlinux.btf`)
- Kernel types header (`vmlinux.h`)
- Kernel headers for development

## 🎨 Proposed Nushell eBPF Syntax

```nushell
# Kernel function probes
bpf_kprobe "do_sys_open" {|ctx| 
    if $ctx.filename == "secret.txt" { 
        emit($ctx.pid) 
    } 
}

# Tracepoints
bpf_tracepoint "syscalls:sys_enter_openat" {|event|
    count()
}

# User-space probes
bpf_uprobe "/bin/bash" "readline" {|ctx|
    emit($ctx.line)
}

# With Nushell pipeline integration
bpf_kprobe "vfs_read" {|ctx| emit($ctx.pid) } 
| where pid > 1000 
| group-by pid 
| each {|group| {pid: $group.name, count: ($group.items | length)}}
```

## 🔧 Helper Commands Available

After setup, these commands are available:

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

## 📚 Key References

- **[Implementation Plan](IMPLEMENTATION_PLAN.md)** - Detailed technical architecture
- **[Setup Guide](README_EBPF_SETUP.md)** - Complete setup instructions
- **[Development Guide](ebpf_dev/README.md)** - Development workflow and phases
- **[Nushell Internals](ebpf_dev/docs/nushell_internals_reference.md)** - AST and IR reference

## ⚡ Key Technical Decisions

1. **Rust/Aya Approach**: Using Aya for pure-Rust eBPF development (no libbpf dependency)
2. **Built-in Commands**: Implementing as Nushell built-ins rather than plugins for direct AST access
3. **JIT Compilation**: Runtime generation and compilation of Rust eBPF code
4. **CO-RE Support**: Using BTF for portable eBPF programs across kernel versions
5. **Pipeline Integration**: eBPF output streams as Nushell tables for pipeline processing

## 🎯 Success Criteria

- **Phase 1**: Clear understanding of Nushell AST and transpiler design
- **Phase 2**: Working kprobe that prints "Hello World" on function entry
- **Phase 3**: Dynamic eBPF program generation from Nushell closures
- **Phase 4**: Support for common tracing scenarios (kprobes, tracepoints, uprobes)
- **Phase 5**: Production-ready implementation with error handling and docs

## 🚨 Important Notes

- **Privileged Access Required**: eBPF needs `CAP_SYS_ADMIN` or `CAP_BPF` capabilities
- **Modern Kernel Recommended**: Linux 5.4+ for BTF support and advanced features
- **Offline Ready**: After `container_setup.sh`, no internet access required
- **Beauty-First Development**: Follow the principle of beautiful, thoughtful code

---

**Status**: Ready for Phase 1 development
**Next Step**: Run `container_setup.sh` in the codex-universal container and begin Nushell internals research 