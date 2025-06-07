#!/bin/bash
# Quick test script for eBPF - assumes Lima VM already exists

set -euo pipefail

VM_NAME="nushell-ebpf-test"
NUSHELL_DIR=$(pwd)

echo "🚀 Quick eBPF test in Lima VM"
echo ""

# Build in VM
limactl shell "$VM_NAME" bash <<EOF
source ~/.cargo/env
cd "$NUSHELL_DIR"
cargo build --features ebpf
EOF

# Create minimal test
cat > /tmp/quick-test.nu <<'NUSCRIPT'
print "Testing bpf-kprobe command:"
help bpf-kprobe | lines | first 3
print ""
print "Dry run test:"
bpf-kprobe "test_probe" { || print "hello" } --dry-run | get generated_code | lines | first 10
NUSCRIPT

limactl copy /tmp/quick-test.nu "$VM_NAME:/tmp/quick-test.nu"

# Run test
limactl shell "$VM_NAME" bash <<EOF
cd "$NUSHELL_DIR"
./target/debug/nu /tmp/quick-test.nu
EOF