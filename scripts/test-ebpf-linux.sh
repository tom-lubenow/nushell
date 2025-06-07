#!/bin/bash
# Script to test eBPF functionality in Linux VM

set -e

echo "🐧 Testing eBPF functionality in Linux VM"
echo "========================================="
echo ""

# Check if we're in Linux
if [[ "$(uname)" != "Linux" ]]; then
    echo "❌ This script must be run inside a Linux VM"
    echo "   Run: limactl shell ebpf-dev"
    exit 1
fi

# Check for required tools
echo "📋 Checking prerequisites..."
command -v rustc >/dev/null 2>&1 || { echo "❌ Rust not installed"; exit 1; }
command -v cargo >/dev/null 2>&1 || { echo "❌ Cargo not installed"; exit 1; }
command -v bpftool >/dev/null 2>&1 || { echo "❌ bpftool not installed"; exit 1; }

echo "✅ All prerequisites found"
echo ""

# Navigate to project directory
cd /Users/tomlubenow/proj/nushell

# Build the eBPF plugin
echo "🔨 Building nu_plugin_ebpf..."
cargo build --release --package nu_plugin_ebpf

# Build Nushell
echo "🔨 Building Nushell..."
cargo build --release

# Test eBPF functionality
echo ""
echo "🧪 Testing eBPF plugin..."

# Create a test script
cat > test_ebpf_linux.nu << 'EOF'
#!/usr/bin/env nu

print "Testing eBPF plugin on Linux..."
print ""

# Register the plugin
print "Registering eBPF plugin..."
plugin add target/release/nu_plugin_ebpf

print ""
print "Test 1: Simple print with actual eBPF loading"
print "============================================"

# Note: This requires root to actually load eBPF programs
if (whoami) == "root" {
    print "Running as root - attempting actual eBPF load..."
    bpf-kprobe "do_sys_open" { || print "File opened!" }
} else {
    print "Not running as root - will generate code only"
    print "Run with: sudo ./target/release/nu test_ebpf_linux.nu"
    bpf-kprobe "do_sys_open" { || print "File opened!" }
}

print ""
print "Test 2: Variable access"
print "======================="
bpf-kprobe "sys_write" { || $pid }

print ""
print "Test completed!"
EOF

# Run the test
echo ""
echo "🚀 Running eBPF tests..."
./target/release/nu test_ebpf_linux.nu

# Check if we should run with sudo
echo ""
echo "📝 Note: To test actual eBPF loading, run:"
echo "   sudo ./scripts/test-ebpf-linux.sh"

# If running as root, try actual eBPF operations
if [[ $EUID -eq 0 ]]; then
    echo ""
    echo "🔒 Running as root - testing actual eBPF operations..."
    
    # List loaded eBPF programs
    echo "📊 Current eBPF programs:"
    bpftool prog list
    
    # Show eBPF maps
    echo ""
    echo "📊 Current eBPF maps:"
    bpftool map list
fi

echo ""
echo "✅ eBPF Linux tests completed!"