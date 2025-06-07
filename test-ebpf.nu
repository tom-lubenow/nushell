# Test different syntax
let probe = "do_sys_open"
let program = {|| print "test" }
bpf-kprobe $probe $program --dry-run