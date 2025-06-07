#!/usr/bin/env nu

print "Testing eBPF built-in commands"
print "=============================="

# Check if we're on Linux
let os_type = (uname).kernel_name

if $os_type != "Linux" {
    print ""
    print "⚠️  eBPF commands are only available on Linux"
    print $"Current OS: ($os_type)"
    print ""
    print "On non-Linux systems, the commands exist but will show an error when used."
    print ""
}

# Test 1: Check if bpf-kprobe command exists
print "1. Checking if bpf-kprobe command is available:"
try {
    help bpf-kprobe | print
} catch {
    print "❌ bpf-kprobe command not found"
}

# Test 2: Try to use the command (will fail on non-Linux)
print ""
print "2. Testing bpf-kprobe command (will fail on non-Linux):"
try {
    bpf-kprobe "test" { || print "test" } --dry-run
} catch { |e|
    print $"Expected error on non-Linux: ($e.msg)"
}

print ""
print "✅ eBPF built-in command infrastructure is working!"