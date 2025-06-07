#!/usr/bin/env nu

# Test script for eBPF event streaming

print "Testing eBPF event streaming..."
print ""

# Register the plugin
print "Registering eBPF plugin..."
plugin add target/release/nu_plugin_ebpf

print ""
print "Test 1: Basic streaming (limited to 10 events)"
print "============================================"
bpf-stream | first 10 | each { |event|
    print $"[($event.type)] ($event | to json -r)"
}

print ""
print "Test 2: Filter probe hits"
print "========================"
bpf-stream | first 20 | where type == "probe_hit" | each { |event|
    print $"Probe ($event.probe) hit by PID ($event.pid)"
}

print ""
print "Test 3: Count events by type"
print "============================"
let events = bpf-stream | first 20
let types = $events | get type | uniq
let counts = $types | each { |t| 
    {
        type: $t,
        count: ($events | where type == $t | length)
    }
}
print ($counts | to md)

print ""
print "Test 4: Stream to file"
print "====================="
bpf-stream | first 5 | save -f test_events.jsonl
print "Saved 5 events to test_events.jsonl"

print ""
print "Streaming tests completed!"