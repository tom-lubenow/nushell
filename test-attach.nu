# Test actual eBPF attachment
bpf-kprobe "do_sys_open" {|| print "File opened" }