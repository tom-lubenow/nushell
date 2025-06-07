#!/usr/bin/env nu

# Test script for eBPF plugin with span-based parsing

print "Testing eBPF plugin with closure source extraction..."
print ""

# Register the plugin if needed
print "Registering eBPF plugin..."
register target/release/nu_plugin_ebpf

print ""
print "Test 1: Simple print statement"
print "================================"
bpf-kprobe "sys_open" { || print "File opened!" }

print ""
print "Test 2: Variable access"
print "================================"
bpf-kprobe "sys_write" { || $pid }

print ""
print "Test 3: Function call"
print "================================"
bpf-kprobe "sys_read" { || count() }

print ""
print "Test 4: String literal"
print "================================"
bpf-kprobe "sys_close" { || "File closed" }

print ""
print "Test 5: Number literal"
print "================================"
bpf-kprobe "sys_exit" { || 42 }

print ""
print "Test completed!"