#!/bin/bash
# Test eBPF plugin using Lima VM

set -e

echo "🐧 Testing eBPF plugin in Lima VM..."
echo "==================================="

# The files are already available via mount, no need to copy

# Build in the VM
echo ""
echo "🔨 Building in Linux VM..."
limactl shell ebpf-dev -- bash -c "cd ~/proj/nushell && source ~/.cargo/env && cargo build --release --package nu_plugin_ebpf"

# Run tests
echo ""
echo "🧪 Running tests..."
limactl shell ebpf-dev -- bash -c "cd ~/proj/nushell && source ~/.cargo/env && ./scripts/test-ebpf-linux.sh"

# Test with sudo for actual eBPF loading
echo ""
echo "🔒 Testing with sudo for kernel loading..."
echo "Note: This will prompt for the VM's sudo password"
limactl shell ebpf-dev -- bash -c "cd ~/proj/nushell && source ~/.cargo/env && sudo ./scripts/test-ebpf-linux.sh"

echo ""
echo "✅ eBPF Linux testing complete!"