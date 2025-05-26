# eBPF Development Directory

This directory contains the development work for integrating eBPF capabilities into Nushell.

## Directory Structure

```
ebpf_dev/
├── README.md           # This file
├── docs/               # Development documentation
├── examples/           # Example eBPF programs and Nushell scripts
└── prototypes/         # Prototype implementations
```

## Development Phases

### Phase 1: Research & Design (Current)
**Goal**: Understand Nushell's IR/AST and design the transpiler architecture

**Tasks**:
- [ ] Study Nushell's parser and IR structure
- [ ] Analyze how closures are represented in the AST
- [ ] Design the Nushell-to-Rust eBPF code generation pipeline
- [ ] Create initial architecture documentation

**Key Files to Study**:
- `src/nu-parser/` - Nushell parser implementation
- `src/nu-protocol/` - Core data structures and IR
- `src/nu-engine/` - Evaluation engine
- `crates/nu-command/` - Built-in command implementations

### Phase 2: Minimal Prototype
**Goal**: Create a basic `bpf_probe` command that can attach a simple kprobe

**Tasks**:
- [ ] Implement basic plugin structure for eBPF commands
- [ ] Create hardcoded eBPF program that prints on kprobe hit
- [ ] Establish loading and attachment mechanism using Aya
- [ ] Verify end-to-end functionality

### Phase 3: Basic Codegen
**Goal**: Implement Nushell closure → Rust eBPF code generation

**Tasks**:
- [ ] Parse Nushell closure AST
- [ ] Generate basic Rust eBPF code templates
- [ ] Implement runtime compilation with rustc
- [ ] Support basic expressions and variables

### Phase 4: Language Expansion
**Goal**: Support more Nushell constructs and probe types

**Tasks**:
- [ ] Add support for conditionals, arithmetic, comparisons
- [ ] Implement tracepoints and uprobes
- [ ] Add BPF-specific built-ins (count, emit, etc.)
- [ ] Support context data access ($event.field)

### Phase 5: Polish & Optimization
**Goal**: Production-ready implementation

**Tasks**:
- [ ] Error handling and debugging support
- [ ] Performance optimizations
- [ ] Documentation and examples
- [ ] Testing and validation

## Key Integration Points

### 1. Nushell Command Interface
The eBPF functionality will be exposed through new Nushell commands:

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
```

### 2. Code Generation Pipeline
1. **Parse**: Extract closure AST from Nushell command
2. **Analyze**: Validate eBPF constraints and supported features
3. **Generate**: Create Rust eBPF code using Aya macros
4. **Compile**: Invoke rustc with BPF target
5. **Load**: Use Aya to load and attach the program

### 3. Data Flow
- **Kernel Events**: Captured by eBPF programs
- **Ring Buffers**: Transfer data to userspace
- **Nushell Tables**: Present events as structured data
- **Pipeline Integration**: Allow piping to other Nushell commands

## Development Environment

### Prerequisites
- Rust nightly toolchain
- BPF targets: `bpfel-unknown-none`, `bpfeb-unknown-none`
- `bpf-linker` for linking eBPF programs
- `bpftool` for debugging and introspection
- Privileged container or root access for eBPF loading

### Setup
1. Run the container setup script: `./container_setup.sh`
2. Source the environment: `source /workspace/offline_resources/setup_env.sh`
3. Load helper functions: `source /workspace/offline_resources/dev_helpers.sh`

### Useful Commands
```bash
# Check BPF system support
check_bpf

# List available examples
show_examples

# Build Nushell with eBPF features
cargo build --features ebpf

# Run tests
cargo test ebpf
```

## Architecture Notes

### Nushell IR Analysis
Nushell parses scripts into an intermediate representation (IR) that we can analyze:
- **Blocks**: Represent closures `{|param| body}`
- **Expressions**: Arithmetic, comparisons, function calls
- **Statements**: Variable assignments, conditionals
- **Pipelines**: Command chains with `|`

### eBPF Constraints
Our transpiler must enforce eBPF limitations:
- No heap allocation
- No unbounded loops
- Limited stack size (512 bytes)
- No dynamic function calls
- Maximum instruction count (~4096)

### Aya Integration
We'll use Aya's proc macros for eBPF program generation:
- `#[kprobe]` for kernel function probes
- `#[tracepoint]` for static tracepoints
- `#[map]` for BPF maps
- `#[xdp]` for network packet processing

## References

- [Nushell Architecture](../src/) - Core Nushell implementation
- [Aya Framework](../external/aya/) - Rust eBPF framework
- [Implementation Plan](../IMPLEMENTATION_PLAN.md) - Detailed technical plan
- [Setup Guide](../README_EBPF_SETUP.md) - Container setup instructions

## Contributing

Follow the beauty-first development approach:
1. **State intentions clearly** before implementing
2. **Verify assumptions** with debug prints and testing
3. **Build incrementally** with working prototypes at each step
4. **Document decisions** and architectural choices

---

**Current Status**: Phase 1 - Research & Design
**Next Milestone**: Understand Nushell IR structure and design transpiler architecture 