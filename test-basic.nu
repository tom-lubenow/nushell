# Test basic eBPF command
echo "Testing eBPF command availability..."
help bpf-kprobe | lines | first 1