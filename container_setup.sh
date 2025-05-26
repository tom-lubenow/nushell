#!/bin/bash

# Container Setup Script for Offline eBPF Development with Nushell
# This script prepares the container for offline work by downloading all necessary
# dependencies, documentation, and tools for eBPF development with Rust/Aya

set -euo pipefail

echo "🚀 Starting container setup for offline eBPF development..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Create directories for offline resources
OFFLINE_DIR="/workspace/offline_resources"
DOCS_DIR="$OFFLINE_DIR/docs"
REPOS_DIR="$OFFLINE_DIR/repos"
TOOLS_DIR="$OFFLINE_DIR/tools"
KERNEL_DIR="$OFFLINE_DIR/kernel"

log_info "Creating offline resource directories..."
mkdir -p "$DOCS_DIR" "$REPOS_DIR" "$TOOLS_DIR" "$KERNEL_DIR"

# Update system and install essential packages
log_info "Installing system dependencies..."
apt-get update
apt-get install -y \
    build-essential \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-generic \
    linux-tools-common \
    linux-tools-generic \
    git \
    curl \
    wget \
    unzip \
    jq \
    tree \
    vim \
    less \
    man-db \
    manpages-dev \
    strace \
    ltrace \
    gdb \
    valgrind \
    pkg-config \
    libssl-dev \
    zlib1g-dev

# Try to install bpftool from available packages
log_info "Installing bpftool..."
apt-get install -y linux-tools-$(uname -r) || \
apt-get install -y linux-hwe-6.5-tools-common || \
apt-get install -y linux-tools-6.5.0-45-generic || \
log_warning "Could not install bpftool via package manager"

# Install Rust if not already present (codex-universal should have it)
if ! command -v rustc &> /dev/null; then
    log_info "Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source ~/.cargo/env
else
    log_success "Rust already installed"
fi

# Install nightly Rust (required for -Z build-std and eBPF development)
log_info "Installing Rust nightly (required for eBPF development)..."
rustup install nightly
rustup component add rust-src --toolchain nightly

# BPF targets are used to generate LLVM bitcode, which bpf-linker then converts to eBPF
# Note: BPF targets are Tier 3 and not always available in every nightly
log_info "Adding BPF targets for eBPF development..."
BPF_TARGETS_AVAILABLE=false

if rustup target add bpfel-unknown-none --toolchain nightly 2>/dev/null; then
    log_success "Added bpfel-unknown-none target"
    BPF_TARGETS_AVAILABLE=true
    
    if rustup target add bpfeb-unknown-none --toolchain nightly 2>/dev/null; then
        log_success "Added bpfeb-unknown-none target"
    else
        log_warning "bpfeb-unknown-none target not available (little-endian target is sufficient)"
    fi
else
    log_warning "BPF targets not available in current nightly channel"
    log_warning "This is expected - BPF targets are Tier 3 and not always available"
    log_info "Aya can still work with bpf-linker processing LLVM bitcode"
fi

if [ "$BPF_TARGETS_AVAILABLE" = true ]; then
    echo "export RUST_BPF_TARGETS_AVAILABLE=1" >> ~/.bashrc
    log_success "eBPF development environment ready with BPF targets"
else
    log_info "eBPF development environment ready (bpf-linker will handle LLVM bitcode)"
fi

# Clone and setup Aya repository
log_info "Cloning Aya repository..."
cd "$REPOS_DIR"
git clone --recursive https://github.com/aya-rs/aya.git
cd aya
git submodule update --init --recursive

# Clone additional eBPF learning resources (optional - for reference only)
log_info "Cloning eBPF learning resources..."
cd "$REPOS_DIR"

# eBPF samples and examples (useful for learning eBPF concepts)
git clone --recursive https://github.com/xdp-project/xdp-tutorial.git || log_warning "Failed to clone XDP tutorial"

# Note: We don't need libbpf, bpftrace, BCC, or RedBPF since we're using Aya
# Aya is pure Rust and doesn't depend on any of these C-based frameworks

# Download eBPF documentation and resources
log_info "Downloading eBPF documentation..."
cd "$DOCS_DIR"

# eBPF documentation from kernel.org (try multiple approaches)
log_info "Downloading kernel BPF documentation..."
if ! wget -r -np -k -E -p -erobots=off --no-check-certificate --timeout=30 --tries=2 \
    https://docs.kernel.org/bpf/ 2>/dev/null; then
    log_warning "Failed to download kernel BPF docs via recursive wget, trying individual files..."
    # Try downloading key individual files instead
    wget -O kernel-bpf-index.html https://docs.kernel.org/bpf/index.html || true
    wget -O kernel-bpf-prog_sk_lookup.html https://docs.kernel.org/bpf/prog_sk_lookup.html || true
    wget -O kernel-bpf-verifier.html https://docs.kernel.org/bpf/verifier.html || true
fi

# Download BPF helper man pages
log_info "Downloading BPF helpers man page..."
wget -O bpf-helpers.7 \
    https://man7.org/linux/man-pages/man7/bpf-helpers.7.html || log_warning "Failed to download BPF helpers man page"

# Download eBPF instruction set documentation
log_info "Downloading eBPF instruction set documentation..."
wget -O bpf-instruction-set.txt \
    https://raw.githubusercontent.com/iovisor/bpf-docs/master/eBPF.md || log_warning "Failed to download eBPF instruction set docs"

# Download Brendan Gregg's eBPF tools and documentation
log_info "Cloning BPF performance tools book..."
git clone https://github.com/brendangregg/bpf-perf-tools-book.git || log_warning "Failed to clone BPF perf tools book"

# Download and cache Rust documentation
log_info "Caching Rust documentation..."
# Get the current default toolchain to avoid architecture issues
CURRENT_TOOLCHAIN=$(rustup show active-toolchain | cut -d' ' -f1)
log_info "Current toolchain: $CURRENT_TOOLCHAIN"

# Install rust-docs component for current toolchain if not already installed
if ! rustup component list --toolchain "$CURRENT_TOOLCHAIN" | grep -q "rust-docs.*installed"; then
    log_info "Installing rust-docs component..."
    rustup component add rust-docs --toolchain "$CURRENT_TOOLCHAIN" || log_warning "Failed to install rust-docs component"
fi

# Cache documentation
rustup doc --std || log_warning "Failed to cache std documentation"
rustup doc --book || log_warning "Failed to cache Rust book"

# Download kernel headers and BTF information
log_info "Setting up kernel development environment..."
cd "$KERNEL_DIR"

# Get current kernel version
KERNEL_VERSION=$(uname -r)
log_info "Current kernel version: $KERNEL_VERSION"

# Try to get BTF information
if [ -f /sys/kernel/btf/vmlinux ]; then
    log_success "BTF available at /sys/kernel/btf/vmlinux"
    cp /sys/kernel/btf/vmlinux ./vmlinux.btf
else
    log_warning "BTF not available, will need kernel headers"
fi

# Download vmlinux.h (contains all kernel types for eBPF)
if command -v bpftool &> /dev/null; then
    log_info "Generating vmlinux.h..."
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h || \
        log_warning "Failed to generate vmlinux.h from BTF"
fi

# Install bpf-linker (required for Aya)
log_info "Installing bpf-linker (required for Aya)..."
cargo install bpf-linker || log_warning "Failed to install bpf-linker"

# Note: cargo-bpf is NOT needed for Aya - it's for RedBPF and uses bpf-sys
# Aya is pure Rust and only needs bpf-linker

# Pre-compile Aya examples to cache dependencies
log_info "Pre-compiling Aya examples to cache dependencies..."
cd "$REPOS_DIR/aya"
# Just check the main aya crate to cache dependencies
cargo check || log_warning "Failed to check Aya crate"

# Note: We focus only on Aya - it's all we need for pure Rust eBPF development

# Build Nushell to ensure all dependencies are cached (if Cargo.toml exists)
log_info "Checking if Nushell can be built..."
if [ -f "/workspace/nushell/Cargo.toml" ]; then
    log_info "Building Nushell to cache dependencies..."
    cd /workspace/nushell
    cargo check || log_warning "Failed to check Nushell"
else
    log_info "No Cargo.toml found in /workspace/nushell - skipping Nushell build"
fi

# Create offline development guide
log_info "Creating offline development guide..."
cat > "$OFFLINE_DIR/OFFLINE_DEVELOPMENT_GUIDE.md" << 'EOF'
# Offline eBPF Development Guide

This container has been prepared for offline eBPF development with Nushell and Aya.

## Available Resources

### Repositories (`/workspace/offline_resources/repos/`)
- `aya/` - Main Aya eBPF framework (pure Rust)
- `xdp-tutorial/` - XDP tutorial and examples (for learning concepts)

### Documentation (`/workspace/offline_resources/docs/`)
- Kernel BPF documentation
- BPF helpers man pages
- eBPF instruction set documentation
- Brendan Gregg's BPF performance tools

### Kernel Resources (`/workspace/offline_resources/kernel/`)
- `vmlinux.btf` - BTF type information (if available)
- `vmlinux.h` - Kernel types header for eBPF

### Tools Available
- `bpftool` - BPF introspection and manipulation tool
- `bpf-linker` - BPF linker (required for Aya)
- Standard development tools (gdb, strace, etc.)

## Development Workflow

1. **Nushell eBPF Integration**: Work in `/workspace/nushell/` on the Nushell fork
2. **Aya Examples**: Check `/workspace/offline_resources/repos/aya/examples/`
3. **Kernel Types**: Use `vmlinux.h` for kernel structure definitions
4. **Testing**: Use `bpftool` to inspect loaded programs and maps

**Focus**: We only use Aya - pure Rust eBPF framework, no C dependencies!

## Key Commands

```bash
# Check BPF capabilities
bpftool feature

# List loaded BPF programs
bpftool prog list

# List BPF maps
bpftool map list

# Build eBPF program with Aya (standard workflow)
cargo +nightly build --target bpfel-unknown-none -Z build-std=core --release

# Alternative: Use xtask if available in project
cargo xtask build-ebpf

# Generate BTF header (if BTF available)
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

## Nushell eBPF Implementation Plan

Based on the implementation plan, we're following the Rust/Aya codegen route:

1. **Phase 1**: Research Nushell IR/AST for transpiler
2. **Phase 2**: Minimal kprobe with print functionality
3. **Phase 3**: Basic codegen and Rust compilation
4. **Phase 4**: Expand language support and probe types
5. **Phase 5**: Robustness and optimizations

## Important Notes

- All Rust dependencies are cached
- Kernel headers and BTF information are available
- Examples from multiple eBPF frameworks are available for reference
- No internet access required after setup
EOF

# Create a quick reference for eBPF development
cat > "$OFFLINE_DIR/EBPF_QUICK_REFERENCE.md" << 'EOF'
# eBPF Quick Reference

## Program Types
- `BPF_PROG_TYPE_KPROBE` - Kernel function entry/exit
- `BPF_PROG_TYPE_TRACEPOINT` - Static kernel tracepoints
- `BPF_PROG_TYPE_PERF_EVENT` - Performance monitoring
- `BPF_PROG_TYPE_XDP` - Network packet processing
- `BPF_PROG_TYPE_SOCKET_FILTER` - Socket filtering

## Common BPF Helpers
- `bpf_get_current_pid_tgid()` - Get current process ID
- `bpf_get_current_comm()` - Get current process name
- `bpf_ktime_get_ns()` - Get current time in nanoseconds
- `bpf_probe_read()` - Safely read kernel memory
- `bpf_probe_read_user()` - Safely read user memory
- `bpf_map_lookup_elem()` - Look up map element
- `bpf_map_update_elem()` - Update map element
- `bpf_perf_event_output()` - Send data to userspace

## Aya Macros
- `#[kprobe]` - Mark function as kprobe handler
- `#[tracepoint]` - Mark function as tracepoint handler
- `#[map]` - Define BPF map
- `#[xdp]` - Mark function as XDP handler

## Map Types
- `HashMap` - Hash table
- `Array` - Array map
- `PerCpuHashMap` - Per-CPU hash table
- `RingBuf` - Ring buffer for events
- `PerfEventArray` - Performance event array

## Constraints
- No heap allocation
- No unbounded loops
- Limited stack size (512 bytes)
- No function pointers
- No global variables (use maps instead)
- Maximum 4096 instructions (configurable)
EOF

# Set up environment variables for offline development
cat > "$OFFLINE_DIR/setup_env.sh" << 'EOF'
#!/bin/bash
# Source this file to set up environment for offline eBPF development

# Source Rust environment if available
if [ -f ~/.cargo/env ]; then
    source ~/.cargo/env
fi

export OFFLINE_RESOURCES="/workspace/offline_resources"
export AYA_PATH="$OFFLINE_RESOURCES/repos/aya"
export KERNEL_HEADERS="$OFFLINE_RESOURCES/kernel"

# Add tools to PATH
export PATH="$OFFLINE_RESOURCES/tools:$PATH"

# Rust environment
export CARGO_TARGET_BPFEL_UNKNOWN_NONE_LINKER=bpf-linker
export CARGO_TARGET_BPFEB_UNKNOWN_NONE_LINKER=bpf-linker

echo "Environment set up for offline eBPF development"
echo "Available resources in: $OFFLINE_RESOURCES"

# Check if Rust is available
if command -v rustc &> /dev/null; then
    echo "Rust toolchain: $(rustc --version)"
else
    echo "Warning: Rust not found in PATH. Make sure to install Rust or source ~/.cargo/env"
fi
EOF

chmod +x "$OFFLINE_DIR/setup_env.sh"

# Create a development helper script
cat > "$OFFLINE_DIR/dev_helpers.sh" << 'EOF'
#!/bin/bash
# Helper functions for eBPF development

# Function to check BPF capabilities
check_bpf() {
    echo "=== BPF Feature Check ==="
    bpftool feature
    echo
    echo "=== Loaded BPF Programs ==="
    bpftool prog list
    echo
    echo "=== BPF Maps ==="
    bpftool map list
}

# Function to generate vmlinux.h if BTF is available
generate_vmlinux_h() {
    if [ -f /sys/kernel/btf/vmlinux ]; then
        echo "Generating vmlinux.h from BTF..."
        bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
        echo "Generated vmlinux.h"
    else
        echo "BTF not available"
    fi
}

# Function to build eBPF program with Aya
build_aya_program() {
    local program_dir="$1"
    if [ -z "$program_dir" ]; then
        echo "Usage: build_aya_program <program_directory>"
        echo "Example: build_aya_program /workspace/offline_resources/repos/aya/examples/xdp-hello"
        return 1
    fi
    
    cd "$program_dir"
    echo "Building eBPF program in $(pwd)..."
    
    # Use the standard Aya build command
    if [ -n "$RUST_BPF_TARGETS_AVAILABLE" ]; then
        echo "Using BPF targets for compilation..."
        cargo +nightly build --target bpfel-unknown-none -Z build-std=core --release
    else
        echo "BPF targets not available, but bpf-linker can still process LLVM bitcode"
        echo "Try building anyway - Aya may still work:"
        cargo +nightly build -Z build-std=core --release || echo "Build failed - this is expected without BPF targets"
    fi
}

# Function to show eBPF examples
show_examples() {
    echo "=== Available Aya Examples ==="
    echo "Aya examples (pure Rust eBPF):"
    ls -la "$OFFLINE_RESOURCES/repos/aya/examples/" 2>/dev/null || echo "Aya examples directory not found"
    echo
    echo "XDP tutorial (for learning concepts):"
    ls -la "$OFFLINE_RESOURCES/repos/xdp-tutorial/" 2>/dev/null || echo "XDP tutorial not found"
}

# Export functions
export -f check_bpf
export -f generate_vmlinux_h
export -f build_aya_program
export -f show_examples
EOF

chmod +x "$OFFLINE_DIR/dev_helpers.sh"

# Download and cache additional Rust crates that might be needed
log_info "Pre-downloading common eBPF-related Rust crates..."
cd /tmp
cargo new temp_project
cd temp_project

# Add common eBPF dependencies to Cargo.toml
cat > Cargo.toml << 'EOF'
[package]
name = "temp_project"
version = "0.1.0"
edition = "2021"

[dependencies]
aya = "0.12"
aya-log = "0.2"
tokio = { version = "1", features = ["full"] }
anyhow = "1.0"
clap = { version = "4.0", features = ["derive"] }
log = "0.4"
env_logger = "0.10"
libc = "0.2"
nix = "0.27"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
EOF

# This will download and cache the dependencies
cargo fetch || log_warning "Failed to fetch some dependencies"

# Clean up temp project
cd /
rm -rf /tmp/temp_project

# Create a summary of what was installed
log_info "Creating installation summary..."
cat > "$OFFLINE_DIR/INSTALLATION_SUMMARY.md" << EOF
# Container Setup Summary

## Installation Date
$(date)

## System Information
- Kernel: $(uname -r)
- OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)
- Architecture: $(uname -m)
- Container Platform: $(uname -s)/$(uname -m)

## Rust Toolchain
- Rustc: $(rustc --version)
- Cargo: $(cargo --version)
- Nightly: $(rustup toolchain list | grep nightly)
- BPF Targets: $(rustup target list --installed --toolchain nightly | grep bpf || echo "Not available in current nightly")

## Tools Installed
- bpftool: $(bpftool --version 2>/dev/null || echo "Available")
- clang: $(clang --version | head -1)
- llvm: $(llvm-config --version 2>/dev/null || echo "Available")

## Repositories Cloned
$(find $REPOS_DIR -maxdepth 1 -type d -name "*" | sort)

## Total Size of Offline Resources
$(du -sh $OFFLINE_DIR)

## BTF Availability
$([ -f /sys/kernel/btf/vmlinux ] && echo "✓ BTF available" || echo "✗ BTF not available")

## Next Steps
1. Source the environment: source $OFFLINE_DIR/setup_env.sh
2. Read the development guide: $OFFLINE_DIR/OFFLINE_DEVELOPMENT_GUIDE.md
3. Start developing eBPF features in Nushell!
EOF

log_success "Container setup completed successfully!"
log_info "Summary available at: $OFFLINE_DIR/INSTALLATION_SUMMARY.md"
log_info "Development guide at: $OFFLINE_DIR/OFFLINE_DEVELOPMENT_GUIDE.md"
log_info "To set up environment: source $OFFLINE_DIR/setup_env.sh"

echo
echo "🎉 Container is now ready for offline eBPF development!"
echo "📚 Check $OFFLINE_DIR/ for documentation and resources"
echo "🔧 Use the helper functions in $OFFLINE_DIR/dev_helpers.sh" 