# Test with print command
bpf-kprobe "do_sys_open" {|| print "File opened" } --dry-run