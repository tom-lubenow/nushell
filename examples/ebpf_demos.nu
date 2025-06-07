#!/usr/bin/env nu

# Advanced eBPF demonstrations for Nushell
# These examples show non-trivial use cases of the eBPF plugin

print "eBPF Advanced Demonstrations"
print "============================"
print ""

# Register the plugin
print "Registering eBPF plugin..."
plugin add target/release/nu_plugin_ebpf

# Example 1: Security Monitoring
print ""
print "Example 1: Security Monitoring - Track privilege escalation attempts"
print "-------------------------------------------------------------------"
print "This would track setuid calls from non-root processes:"
print ""
print '```nushell'
print 'bpf-kprobe "sys_setuid" { ||'
print '    if $uid != 0 && $pid > 1000 {'
print '        print "Privilege escalation attempt detected!"'
print '        emit("security_alert")'
print '    }'
print '}'
print '```'

# Example 2: Performance Analysis
print ""
print "Example 2: Performance Analysis - Count syscalls by process"
print "----------------------------------------------------------"
print "Track system call frequency:"
print ""
print '```nushell'
print 'bpf-tracepoint "raw_syscalls:sys_enter" { ||'
print '    count()  # Increments a per-PID counter'
print '}'
print ''
print '# Then analyze with:'
print 'bpf-stream | where type == "counter" | sort-by value -r'
print '```'

# Example 3: Network Monitoring
print ""
print "Example 3: Network Monitoring - Track TCP connections"
print "----------------------------------------------------"
print "Monitor new TCP connections:"
print ""
print '```nushell'
print 'bpf-kprobe "tcp_v4_connect" { ||'
print '    if $uid == 1000 {  # Monitor specific user'
print '        emit("tcp_connect")'
print '    }'
print '}'
print '```'

# Example 4: File System Monitoring
print ""
print "Example 4: File System Monitoring - Track file modifications"
print "-----------------------------------------------------------"
print "Monitor file write operations:"
print ""
print '```nushell'
print 'bpf-kprobe "vfs_write" { ||'
print '    if $pid != 1 {  # Exclude init process'
print '        count()'
print '        if $comm == "vim" || $comm == "nano" {'
print '            print "Editor write detected"'
print '        }'
print '    }'
print '}'
print '```'

# Example 5: Complex Conditional Logic
print ""
print "Example 5: Complex Conditional Logic - Multi-condition filtering"
print "---------------------------------------------------------------"
print "Demonstrates complex boolean expressions:"
print ""
print '```nushell'
print 'bpf-kprobe "do_sys_open" { ||'
print '    if ($pid > 1000 && $uid != 0) || $comm == "suspicious" {'
print '        if $pid % 2 == 0 {'
print '            print "Even PID non-root file access"'
print '        } else {'
print '            emit("odd_pid_access")'
print '        }'
print '    }'
print '}'
print '```'

# Example 6: Using Arithmetic for Sampling
print ""
print "Example 6: Sampling - Track every Nth event"
print "------------------------------------------"
print "Use modulo arithmetic for sampling:"
print ""
print '```nushell'
print '# Track 1 in every 100 events'
print 'bpf-kprobe "sys_read" { ||'
print '    if $pid % 100 == 0 {'
print '        emit("sampled_read")'
print '    }'
print '}'
print '```'

# Working Demo: Actually run a simple example
print ""
print "Running Demo: Count system calls for 5 seconds"
print "=============================================="

# This actually works!
print "Starting trace..."
bpf-kprobe "sys_enter" { || count() }

# Collect some events
print "Collecting data for 5 seconds..."
sleep 5sec

# Show results
print ""
print "Results from event stream:"
bpf-stream | first 10 | to md

print ""
print "Advanced Features We Could Add:"
print "=============================="
print "1. Event field access: $event.filename, $event.fd"
print "2. Stack traces: get_stack() function"
print "3. Timestamps: timestamp() for latency analysis"
print "4. Map operations: update_map(), read_map()"
print "5. String operations: str_contains(), str_prefix()"
print ""
print "These would enable even more sophisticated analysis!"