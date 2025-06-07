# Test with print instead of echo
bpf-kprobe "do_sys_open" {|| print "File opened" } --dry-run