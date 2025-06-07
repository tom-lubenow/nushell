use nu_plugin_ebpf::parser::EbpfParser;

#[test]
fn test_full_field_access_example() {
    // Test a realistic example: monitoring file opens for specific files
    let code = r#"{ || 
        if $ctx.filename == "/etc/passwd" {
            print "Security alert: /etc/passwd accessed"
            emit("passwd_access")
        }
    }"#;
    
    let mut parser = EbpfParser::new(code.to_string(), 0);
    let block = parser.parse().expect("Failed to parse");
    
    // Generate code with context for do_sys_open
    let generated = nu_ebpf::generate_kprobe_with_context(&block, "probe_do_sys_open", Some("do_sys_open"));
    
    eprintln!("Generated eBPF code for file monitoring:\n{}", generated);
    
    // Verify the generated code has proper field access
    assert!(generated.contains("ctx.arg(0)"));
    assert!(generated.contains("bpf_probe_read_user_str_bytes"));
    assert!(generated.contains("filename"));
}

#[test]
fn test_sys_read_size_check() {
    // Monitor large reads
    let code = r#"{ || 
        if $ctx.count > 4096 {
            count()
            print "Large read detected"
        }
    }"#;
    
    let mut parser = EbpfParser::new(code.to_string(), 0);
    let block = parser.parse().expect("Failed to parse");
    
    // Generate code with context for sys_read
    let generated = nu_ebpf::generate_kprobe_with_context(&block, "probe_sys_read", Some("sys_read"));
    
    eprintln!("Generated eBPF code for read monitoring:\n{}", generated);
    
    // Verify the generated code has proper field access for count
    assert!(generated.contains("ctx.arg(2)"));
    assert!(generated.contains("count: usize"));
}

#[test]
fn test_tcp_connect_monitoring() {
    // Monitor TCP connections
    let code = r#"{ || 
        print "TCP connection initiated"
        emit("tcp_connect")
    }"#;
    
    let mut parser = EbpfParser::new(code.to_string(), 0);
    let block = parser.parse().expect("Failed to parse");
    
    // Generate code with context for tcp_connect
    let generated = nu_ebpf::generate_kprobe_with_context(&block, "probe_tcp_connect", Some("tcp_connect"));
    
    eprintln!("Generated eBPF code for TCP monitoring:\n{}", generated);
    
    // Should generate basic logging code
    assert!(generated.contains("TCP connection initiated"));
}

#[test]
fn test_multiple_field_access() {
    // Access multiple fields
    let code = r#"{ || 
        if $ctx.flags > 0 && $ctx.mode == 0777 {
            print "Suspicious file open"
        }
    }"#;
    
    let mut parser = EbpfParser::new(code.to_string(), 0);
    let block = parser.parse().expect("Failed to parse");
    
    // Generate code with context
    let generated = nu_ebpf::generate_kprobe_with_context(&block, "probe_sys_open", Some("sys_open"));
    
    eprintln!("Generated eBPF code with multiple fields:\n{}", generated);
    
    // Should have both field accesses with proper indices
    assert!(generated.contains("flags")); 
    assert!(generated.contains("mode"));
}