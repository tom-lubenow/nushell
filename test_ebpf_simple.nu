#!/usr/bin/env nu

# Simple test for eBPF plugin with closure source extraction

print "Testing eBPF plugin with closure source extraction..."
print ""

# Register the plugin if needed
print "Registering eBPF plugin..."
plugin add target/release/nu_plugin_ebpf

print ""
print "Test: Simple print closure"
print "================================"
bpf-kprobe "sys_open" { || print "File opened!" }