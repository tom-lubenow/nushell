#!/bin/bash
# Test eBPF functionality using bpftrace

echo "Testing eBPF attachment with bpftrace..."
echo "This will trace file opens for 5 seconds..."

# Create a simple bpftrace program
cat > /tmp/trace_opens.bt << 'EOF'
kprobe:do_sys_open
{
    printf("File opened by PID %d: %s\n", pid, comm);
}

BEGIN
{
    printf("Tracing file opens... Hit Ctrl-C to stop\n");
}
EOF

# Run it for 5 seconds
sudo timeout 5 bpftrace /tmp/trace_opens.bt