#!/bin/bash
# Real-world eBPF examples to test our implementation

echo "🧪 Testing Real eBPF Use Cases"
echo "=============================="

# Build the plugin first
echo "Building plugin..."
cargo build -p nu_plugin_ebpf --release

# Start nu with the plugin
echo "Testing examples..."

# Example 1: Simple file open monitoring
echo ""
echo "📍 Example 1: Monitor file opens"
echo 'bpf-kprobe "do_sys_open" { || print "File opened" }' | \
    ./target/release/nu -c "register target/release/nu_plugin_ebpf; source -"

# Example 2: Monitor specific files
echo ""
echo "📍 Example 2: Monitor /etc/passwd access"
echo 'bpf-kprobe "do_sys_open" { || print $ctx.filename }' | \
    ./target/release/nu -c "register target/release/nu_plugin_ebpf; source -"

# Example 3: Large read detection
echo ""
echo "📍 Example 3: Detect large reads"
echo 'bpf-kprobe "sys_read" { || if $ctx.count > 4096 { print "Large read" } }' | \
    ./target/release/nu -c "register target/release/nu_plugin_ebpf; source -"

# Example 4: Count events
echo ""
echo "📍 Example 4: Count system calls"
echo 'bpf-kprobe "sys_write" { || count() }' | \
    ./target/release/nu -c "register target/release/nu_plugin_ebpf; source -"

echo ""
echo "✅ Test complete. Check generated code above."