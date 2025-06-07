use nu_plugin_ebpf::parser::EbpfParser;
use nu_ebpf::generate_kprobe_with_context;

#[test]
fn test_improved_print_generation() {
    let mut parser = EbpfParser::new(r#"{ || print "Hello eBPF" }"#.to_string(), 0);
    let block = parser.parse().expect("Failed to parse");
    
    let generated = generate_kprobe_with_context(&block, "test_probe", None);
    eprintln!("Print generation:\n{}", generated);
    
    // Should generate actual info! macro call
    assert!(generated.contains(r#"info!(&ctx, "Hello eBPF");"#));
}

#[test]
fn test_improved_field_access_generation() {
    let mut parser = EbpfParser::new(r#"{ || print $ctx.filename }"#.to_string(), 0);
    let block = parser.parse().expect("Failed to parse");
    
    let generated = generate_kprobe_with_context(&block, "test_probe", Some("do_sys_open"));
    eprintln!("Field access generation:\n{}", generated);
    
    // Should have field access code AND use it
    assert!(generated.contains("ctx.arg(0)"));
    assert!(generated.contains("filename"));
}

#[test]
fn test_conditional_generation() {
    let code = r#"{ || 
        if $ctx.count > 1024 {
            print "Large read"
        }
    }"#;
    
    let mut parser = EbpfParser::new(code.to_string(), 0);
    let block = parser.parse().expect("Failed to parse");
    
    let generated = generate_kprobe_with_context(&block, "test_probe", Some("sys_read"));
    eprintln!("Conditional generation:\n{}", generated);
    
    // Should generate comparison expression
    assert!(generated.contains("count"));
    assert!(generated.contains("1024"));
}

#[test] 
fn test_arithmetic_expression() {
    let code = r#"{ || 
        if $ctx.size * 2 > 4096 {
            count()
        }
    }"#;
    
    let mut parser = EbpfParser::new(code.to_string(), 0);
    let block = parser.parse().expect("Failed to parse");
    
    let generated = generate_kprobe_with_context(&block, "test_probe", Some("kmalloc"));
    eprintln!("Arithmetic generation:\n{}", generated);
    
    // Should have arithmetic operation
    assert!(generated.contains("size"));
    assert!(generated.contains("*"));
    assert!(generated.contains("2"));
}