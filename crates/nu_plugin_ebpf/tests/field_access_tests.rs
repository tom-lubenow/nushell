use nu_plugin_ebpf::parser::EbpfParser;
use nu_plugin_ebpf::probe_context::{ProbeRegistry, generate_field_access_code};

#[test]
fn test_parse_field_access_with_context() {
    // Parse a field access expression
    let mut parser = EbpfParser::new("{ || $ctx.filename }".to_string(), 0);
    let result = parser.parse();
    assert!(result.is_ok());
    
    // Verify we can generate code for it
    let registry = ProbeRegistry::new();
    let code = generate_field_access_code("do_sys_open", "filename", &registry);
    assert!(code.is_ok());
    
    let generated = code.unwrap();
    assert!(generated.contains("bpf_probe_read_user_str_bytes"));
    assert!(generated.contains("ctx.arg(0)"));
}

#[test]
fn test_field_access_in_condition() {
    // Parse field access in a condition
    let mut parser = EbpfParser::new(r#"{ || if $ctx.size > 1024 { print "large" } }"#.to_string(), 0);
    let result = parser.parse();
    assert!(result.is_ok());
    
    // Test with where clause
    let mut parser = EbpfParser::new(r#"{ || where $ctx.fd == 0 }"#.to_string(), 0);
    let result = parser.parse();
    assert!(result.is_ok());
}

#[test]
fn test_multiple_field_access() {
    // Test accessing multiple fields
    let test_cases = vec![
        r#"{ || if $ctx.flags > 0 && $ctx.mode == 0777 { count() } }"#,
        r#"{ || print $ctx.filename }"#,
        r#"{ || where $ctx.count > 0 }"#,
    ];
    
    for test in test_cases {
        let mut parser = EbpfParser::new(test.to_string(), 0);
        let result = parser.parse();
        assert!(result.is_ok(), "Failed to parse: {}", test);
    }
}

#[test]
fn test_known_probe_contexts() {
    let registry = ProbeRegistry::new();
    
    // Test various known functions
    let test_cases = vec![
        ("do_sys_open", vec!["filename", "flags", "mode"]),
        ("sys_read", vec!["fd", "buf", "count"]),
        ("sys_write", vec!["fd", "buf", "count"]),
        ("tcp_connect", vec!["sk", "uaddr", "addr_len"]),
        ("kmalloc", vec!["size", "flags"]),
    ];
    
    for (func, fields) in test_cases {
        let ctx = registry.get_context(func);
        assert!(ctx.is_some(), "Missing context for {}", func);
        
        for field in fields {
            let field_type = registry.get_field_type(func, field);
            assert!(field_type.is_some(), "Missing field {} for {}", field, func);
        }
    }
}

#[test]
fn test_code_generation_for_different_types() {
    let registry = ProbeRegistry::new();
    
    // Test string field
    let code = generate_field_access_code("do_sys_open", "filename", &registry).unwrap();
    assert!(code.contains("*const u8"));
    assert!(code.contains("bpf_probe_read_user_str_bytes"));
    
    // Test integer field
    let code = generate_field_access_code("sys_read", "fd", &registry).unwrap();
    assert!(code.contains("let fd: u32"));
    assert!(!code.contains("bpf_probe_read"));
    
    // Test size_t field
    let code = generate_field_access_code("sys_read", "count", &registry).unwrap();
    assert!(code.contains("let count: usize"));
}