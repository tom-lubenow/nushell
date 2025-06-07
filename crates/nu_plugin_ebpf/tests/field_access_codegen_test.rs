use nu_plugin_ebpf::parser::EbpfParser;
use nu_ebpf::generate_kprobe;

#[test]
fn test_field_access_code_generation() {
    // Parse a closure with field access
    let mut parser = EbpfParser::new("{ || $ctx.filename }".to_string(), 0);
    let block = parser.parse().expect("Failed to parse");
    
    // Generate eBPF code without context
    let generated_code = generate_kprobe(&block, "probe_do_sys_open");
    
    eprintln!("Generated code without context:\n{}", generated_code);
    
    // Check that the generated code contains generic field access
    assert!(generated_code.contains("$ctx.filename"));
}

#[test]
fn test_field_access_with_probe_context() {
    // Parse a closure with field access
    let mut parser = EbpfParser::new("{ || $ctx.filename }".to_string(), 0);
    let block = parser.parse().expect("Failed to parse");
    
    // Generate eBPF code WITH context
    let generated_code = nu_ebpf::generate_kprobe_with_context(&block, "probe_do_sys_open", Some("do_sys_open"));
    
    eprintln!("Generated code with context:\n{}", generated_code);
    
    // Check that the generated code contains proper field access
    assert!(generated_code.contains("bpf_probe_read_user_str_bytes"));
    assert!(generated_code.contains("ctx.arg(0)"));
}

#[test]
fn test_field_access_in_condition_codegen() {
    // Parse a closure with field access in condition
    let mut parser = EbpfParser::new("{ || if $ctx.size > 1024 { print \"large\" } }".to_string(), 0);
    let block = parser.parse().expect("Failed to parse");
    
    // Generate eBPF code
    let generated_code = generate_kprobe(&block, "probe_sys_read");
    
    eprintln!("Generated code with field access in condition:\n{}", generated_code);
    
    // Check that the generated code handles the field access
    assert!(generated_code.contains("ctx"));
}