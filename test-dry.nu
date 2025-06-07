# Test dry run with explicit parameters
let probe = "do_sys_open"
let code = {|| 
    echo "test"
}

# Try calling with dry-run
bpf-kprobe $probe $code --dry-run