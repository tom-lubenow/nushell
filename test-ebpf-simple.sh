#!/bin/bash
# Test if eBPF is available and working

echo "Checking eBPF support..."
if [ -f /sys/kernel/btf/vmlinux ]; then
    echo "✓ BTF is available"
else
    echo "✗ BTF not found"
fi

echo -e "\nChecking if BCC tools are available..."
if command -v bpftrace &> /dev/null; then
    echo "✓ bpftrace is available"
    bpftrace --version
else
    echo "✗ bpftrace not found"
fi

echo -e "\nTrying to list available kprobes..."
if [ -f /sys/kernel/debug/tracing/available_filter_functions ]; then
    echo "✓ Kprobes available. Showing first 10 containing 'open':"
    sudo grep -i open /sys/kernel/debug/tracing/available_filter_functions | head -10
else
    echo "✗ Kprobes not accessible"
fi