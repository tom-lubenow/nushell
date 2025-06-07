use nu_plugin_ebpf::parser::EbpfParser;

#[test]
fn test_parse_empty_closure() {
    let mut parser = EbpfParser::new("{ || }".to_string(), 0);
    let result = parser.parse();
    
    assert!(result.is_ok());
    let block = result.unwrap();
    assert_eq!(block.pipelines.len(), 0);
}

#[test]
fn test_parse_simple_print() {
    let mut parser = EbpfParser::new(r#"{ || print "hello" }"#.to_string(), 0);
    let result = parser.parse();
    
    assert!(result.is_ok());
    let block = result.unwrap();
    assert_eq!(block.pipelines.len(), 1);
}

#[test]
fn test_parse_variable_reference() {
    let mut parser = EbpfParser::new("{ || $pid }".to_string(), 0);
    let result = parser.parse();
    
    assert!(result.is_ok());
    let block = result.unwrap();
    assert_eq!(block.pipelines.len(), 1);
}

#[test]
fn test_parse_function_call() {
    let mut parser = EbpfParser::new("{ || count() }".to_string(), 0);
    let result = parser.parse();
    
    assert!(result.is_ok());
    let block = result.unwrap();
    assert_eq!(block.pipelines.len(), 1);
}

#[test]
fn test_parse_string_literal() {
    let mut parser = EbpfParser::new(r#"{ || "test string" }"#.to_string(), 0);
    let result = parser.parse();
    
    assert!(result.is_ok());
    let block = result.unwrap();
    assert_eq!(block.pipelines.len(), 1);
}

#[test]
fn test_parse_number_literal() {
    let mut parser = EbpfParser::new("{ || 42 }".to_string(), 0);
    let result = parser.parse();
    
    assert!(result.is_ok());
    let block = result.unwrap();
    assert_eq!(block.pipelines.len(), 1);
}

#[test]
fn test_parse_closure_with_parameter() {
    let mut parser = EbpfParser::new("{ |event| $event }".to_string(), 0);
    let result = parser.parse();
    
    assert!(result.is_ok());
    let block = result.unwrap();
    // Parameters are currently skipped, so we just check it parses
    assert_eq!(block.pipelines.len(), 1);
}

#[test]
fn test_parse_multiple_expressions() {
    let mut parser = EbpfParser::new(r#"{ || print "one" count() }"#.to_string(), 0);
    let result = parser.parse();
    
    assert!(result.is_ok());
    let block = result.unwrap();
    assert_eq!(block.pipelines.len(), 2);
}

#[test]
fn test_parse_missing_closing_brace() {
    let mut parser = EbpfParser::new("{ || print \"test\"".to_string(), 0);
    let result = parser.parse();
    
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Expected '}'"));
}

#[test]
fn test_parse_all_builtin_variables() {
    let variables = vec!["$pid", "$uid", "$comm"];
    
    for var in variables {
        let code = format!("{{ || {} }}", var);
        let mut parser = EbpfParser::new(code, 0);
        let result = parser.parse();
        assert!(result.is_ok(), "Failed to parse variable: {}", var);
    }
}

#[test]
fn test_parse_all_builtin_functions() {
    let functions = vec![
        r#"print "message""#,
        "count()",
        r#"emit("event")"#,
        "timestamp()",
        "get_stack()",
    ];
    
    for func in functions {
        let code = format!("{{ || {} }}", func);
        let mut parser = EbpfParser::new(code, 0);
        let result = parser.parse();
        assert!(result.is_ok(), "Failed to parse function: {}", func);
    }
}

#[test]
fn test_parse_whitespace_handling() {
    let cases = vec![
        "{||print\"test\"}",           // No spaces
        "{ || print \"test\" }",      // Normal spacing
        "{  ||  print  \"test\"  }",  // Extra spaces
        "{\n||\nprint\n\"test\"\n}",  // Newlines
    ];
    
    for case in cases {
        let mut parser = EbpfParser::new(case.to_string(), 0);
        let result = parser.parse();
        assert!(result.is_ok(), "Failed to parse with whitespace: {}", case);
    }
}

// ============================================================================
// Parser tests for planned features (should fail appropriately)
// ============================================================================

#[test]
fn test_parse_if_statement() {
    // Test that if statements are parsed correctly
    let mut parser = EbpfParser::new("{ || if $pid > 1000 { print \"high\" } }".to_string(), 0);
    let result = parser.parse();
    
    // Parser should successfully parse if statements
    assert!(result.is_ok());
    
    // Test with else clause
    let mut parser = EbpfParser::new("{ || if $pid > 1000 { print \"high\" } else { print \"low\" } }".to_string(), 0);
    let result = parser.parse();
    assert!(result.is_ok());
}

#[test]
fn test_parse_arithmetic_operators() {
    let operators = vec![
        ("$pid + 1", "addition"),
        ("$pid - 1", "subtraction"),
        ("$pid * 2", "multiplication"),
        ("$pid / 2", "division"),
        ("$pid % 2", "modulo"),
    ];
    
    for (expr, desc) in operators {
        let code = format!("{{ || {} }}", expr);
        let mut parser = EbpfParser::new(code.clone(), 0);
        let result = parser.parse();
        assert!(result.is_ok(), "Failed to parse {}: {}", desc, code);
    }
}

#[test]
fn test_parse_comparison_operators() {
    let operators = vec![
        ("$pid == 1000", "equals"),
        ("$pid != 1000", "not equals"),
        ("$pid < 1000", "less than"),
        ("$pid <= 1000", "less than or equal"),
        ("$pid > 1000", "greater than"),
        ("$pid >= 1000", "greater than or equal"),
    ];
    
    for (expr, desc) in operators {
        let code = format!("{{ || {} }}", expr);
        let mut parser = EbpfParser::new(code.clone(), 0);
        let result = parser.parse();
        assert!(result.is_ok(), "Failed to parse {}: {}", desc, code);
    }
}

#[test]
fn test_parse_boolean_operators() {
    let operators = vec![
        ("$pid > 1000 && $uid == 0", "logical and"),
        ("$pid > 1000 || $uid == 0", "logical or"),
    ];
    
    for (expr, desc) in operators {
        let code = format!("{{ || {} }}", expr);
        let mut parser = EbpfParser::new(code.clone(), 0);
        let result = parser.parse();
        assert!(result.is_ok(), "Failed to parse {}: {}", desc, code);
    }
}

#[test]
#[ignore = "Event field access not yet implemented"]
fn test_parse_event_field_access() {
    let mut parser = EbpfParser::new("{ |event| $event.filename }".to_string(), 0);
    let result = parser.parse();
    
    assert!(result.is_ok());
    // Should parse field access
}

#[test]
fn test_parse_where_keyword() {
    // Simple where clause
    let mut parser = EbpfParser::new("{ || where $pid > 1024 }".to_string(), 0);
    let result = parser.parse();
    
    assert!(result.is_ok());
    
    // Where with complex condition
    let mut parser = EbpfParser::new("{ || where $pid > 1000 && $uid == 0 }".to_string(), 0);
    let result = parser.parse();
    
    assert!(result.is_ok());
}

#[test]
#[ignore = "Record construction not yet implemented"]
fn test_parse_record_construction() {
    let mut parser = EbpfParser::new("{ || {pid: $pid, time: timestamp()} }".to_string(), 0);
    let result = parser.parse();
    
    assert!(result.is_ok());
    // Should parse record literal
}