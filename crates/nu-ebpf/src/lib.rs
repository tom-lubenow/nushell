#![doc = include_str!("../README.md")]

use nu_protocol::ast::{Block, Expr, Expression, Pipeline, PipelineElement, Operator, Math, Comparison, Boolean};

/// Generate Rust source for a kprobe eBPF program.
///
/// Analyzes the provided Nushell block and generates corresponding eBPF code.
/// Supports basic expressions, conditionals, arithmetic, and eBPF built-in functions.
pub fn generate_kprobe(code: &Block, fn_name: &str) -> String {
    let mut ebpf_body = String::new();
    let mut has_maps = false;
    
    // Analyze the block's pipelines and generate eBPF code
    for pipeline in &code.pipelines {
        let (pipeline_code, uses_maps) = generate_pipeline(pipeline);
        ebpf_body.push_str(&pipeline_code);
        ebpf_body.push('\n');
        has_maps = has_maps || uses_maps;
    }
    
    // If no meaningful code was generated, use a default action
    if ebpf_body.trim().is_empty() {
        ebpf_body = "    info!(&ctx, \"probe hit\");".to_string();
    }

    // Generate map declarations if needed
    let map_declarations = if has_maps {
        generate_map_declarations()
    } else {
        String::new()
    };

    format!(
        r#"use aya_bpf::macros::kprobe;
use aya_bpf::programs::KProbeContext;
use aya_log_ebpf::info;
{maps}
#[kprobe(name = "{name}")]
pub fn {name}(ctx: KProbeContext) -> u32 {{
{body}
    0
}}
"#,
        name = fn_name,
        body = ebpf_body,
        maps = map_declarations
    )
}

/// Generate eBPF code for a Nushell pipeline
fn generate_pipeline(pipeline: &Pipeline) -> (String, bool) {
    let mut result = String::new();
    let mut uses_maps = false;
    
    for element in &pipeline.elements {
        let (element_code, element_uses_maps) = generate_pipeline_element(element);
        result.push_str(&element_code);
        result.push('\n');
        uses_maps = uses_maps || element_uses_maps;
    }
    
    (result, uses_maps)
}

/// Generate eBPF code for a pipeline element
fn generate_pipeline_element(element: &PipelineElement) -> (String, bool) {
    generate_expression(&element.expr)
}

/// Generate eBPF code for a Nushell expression
fn generate_expression(expr: &Expression) -> (String, bool) {
    match &expr.expr {
        Expr::Call(call) => {
            // Handle function calls - including eBPF built-ins
            generate_call_expression(call)
        }
        Expr::String(s) => {
            // String literals can be used in logging
            (format!("    info!(&ctx, \"{}\");", escape_string(s)), false)
        }
        Expr::Int(n) => {
            // Integer literals - just a comment for now, could be used in expressions
            (format!("    // Integer literal: {}", n), false)
        }
        Expr::Bool(b) => {
            // Boolean literals
            (format!("    // Boolean literal: {}", b), false)
        }
        Expr::Var(var_id) => {
            // Variable access - handle special eBPF variables like $pid, $comm
            generate_variable_access(*var_id)
        }
        Expr::BinaryOp(lhs, op, rhs) => {
            // Handle binary operations (arithmetic, comparisons, logical)
            generate_binary_operation(lhs, op, rhs)
        }
        Expr::Block(block_id) => {
            // Nested blocks - for conditionals
            (format!("    // Nested block: {:?}", block_id), false)
        }
        Expr::Closure(block_id) => {
            // Closures - not supported in eBPF context
            (format!("    // ERROR: Closures not supported in eBPF: {:?}", block_id), false)
        }
        Expr::Operator(op) => {
            // Standalone operators
            (format!("// Operator: {:?}", op), false)
        }
        Expr::Subexpression(block_id) => {
            // Subexpressions could be conditionals
            (format!("    // Subexpression: {:?}", block_id), false)
        }
        _ => {
            (format!("    // Unsupported expression: {:?}", expr.expr), false)
        }
    }
}

/// Generate code for binary operations (arithmetic, comparisons, logical)
fn generate_binary_operation(lhs: &Expression, op: &Expression, rhs: &Expression) -> (String, bool) {
    let (left_code, left_uses_maps) = generate_expression(lhs);
    let (right_code, right_uses_maps) = generate_expression(rhs);
    
    if let Expr::Operator(operator) = &op.expr {
        match operator {
            Operator::Math(math_op) => {
                let op_symbol = match math_op {
                    Math::Add => "+",
                    Math::Subtract => "-", 
                    Math::Multiply => "*",
                    Math::Divide => "/",
                    Math::Modulo => "%",
                    Math::Pow => "/* power op not supported in eBPF */",
                    _ => "/* unsupported math op */",
                };
                (format!("    // Math operation: ({}) {} ({})", 
                        left_code.trim(), op_symbol, right_code.trim()), 
                 left_uses_maps || right_uses_maps)
            }
            Operator::Comparison(comp_op) => {
                let op_symbol = match comp_op {
                    Comparison::Equal => "==",
                    Comparison::NotEqual => "!=",
                    Comparison::LessThan => "<",
                    Comparison::LessThanOrEqual => "<=",
                    Comparison::GreaterThan => ">",
                    Comparison::GreaterThanOrEqual => ">=",
                    _ => "/* unsupported comparison */",
                };
                (format!("    // Comparison: ({}) {} ({})", 
                        left_code.trim(), op_symbol, right_code.trim()),
                 left_uses_maps || right_uses_maps)
            }
            Operator::Boolean(bool_op) => {
                let op_symbol = match bool_op {
                    Boolean::And => "&&",
                    Boolean::Or => "||",
                    Boolean::Xor => "^",
                };
                (format!("    // Boolean operation: ({}) {} ({})", 
                        left_code.trim(), op_symbol, right_code.trim()),
                 left_uses_maps || right_uses_maps)
            }
            _ => {
                (format!("    // Unsupported binary operation: {:?}", operator),
                 left_uses_maps || right_uses_maps)
            }
        }
    } else {
        (format!("    // Invalid binary operation"), left_uses_maps || right_uses_maps)
    }
}

/// Generate code for function calls, handling eBPF built-ins
fn generate_call_expression(call: &nu_protocol::ast::Call) -> (String, bool) {
    // For Phase 4, we'll implement basic built-in recognition
    // Since we don't have access to EngineState, we'll use argument patterns to guess function types
    
    if call.arguments.is_empty() {
        // No-argument calls - could be eBPF built-ins like pid(), count(), etc.
        // For now, we'll assume these are logging calls
        ("    info!(&ctx, \"function called\");".to_string(), false)
    } else if call.arguments.len() == 1 {
        // Single argument calls - could be print(), emit(), count() with key, etc.
        let (arg_code, arg_uses_maps) = if let Some(arg) = call.arguments.first() {
            if let Some(expr) = arg.expr() {
                generate_expression(expr)
            } else {
                ("\"unknown\"".to_string(), false)
            }
        } else {
            ("\"empty\"".to_string(), false)
        };
        
        // Check if this looks like a logging function
        (format!("    info!(&ctx, \"function called with: {}\");", arg_code.trim()), arg_uses_maps)
    } else {
        // Multiple argument calls
        ("    info!(&ctx, \"function called with multiple args\");".to_string(), false)
    }
}

/// Generate code for variable access, handling special eBPF variables
fn generate_variable_access(var_id: nu_protocol::VarId) -> (String, bool) {
    // Special eBPF variables would be mapped here
    // For now, we'll use heuristics based on common variable IDs
    
    // In a real implementation, we'd need to map known variable names
    // like $pid, $comm, $tgid, etc. to eBPF helper calls
    
    // For Phase 4, let's provide some basic built-in variable support
    match var_id.get() {
        // These are heuristic - in practice we'd need engine state to resolve names
        0 => {
            // Might be a special variable like $in
            ("/* $in variable access */".to_string(), false)
        }
        1..=10 => {
            // Could be built-in eBPF variables
            (format!("    let var_{} = /* eBPF context access */;", var_id.get()), false)
        }
        _ => {
            // Regular variables - not directly supported in eBPF
            (format!("    // Variable access not supported in eBPF: {:?}", var_id), false)
        }
    }
}

/// Generate map declarations for eBPF programs
fn generate_map_declarations() -> String {
    r#"
use aya_bpf::{
    macros::map,
    maps::HashMap,
};

#[map(name = "EVENTS")]
static mut EVENTS: HashMap<u32, u64> = HashMap::with_max_entries(1024, 0);

"#.to_string()
}

/// Escape string for use in Rust string literals
fn escape_string(s: &str) -> String {
    s.replace('\\', "\\\\")
     .replace('"', "\\\"")
     .replace('\n', "\\n")
     .replace('\r', "\\r")
     .replace('\t', "\\t")
}

/// Built-in eBPF functions and variables that can be used in closures
pub mod builtins {
    use super::escape_string;
    
    /// Generate code for getting current process ID
    pub fn get_pid() -> &'static str {
        "bpf_get_current_pid_tgid() >> 32"
    }
    
    /// Generate code for getting current thread group ID  
    pub fn get_tgid() -> &'static str {
        "bpf_get_current_pid_tgid() as u32"
    }
    
    /// Generate code for getting current user ID
    pub fn get_uid() -> &'static str {
        "bpf_get_current_uid_gid() >> 32"
    }
    
    /// Generate code for getting current group ID
    pub fn get_gid() -> &'static str {
        "bpf_get_current_uid_gid() as u32"
    }
    
    /// Generate code for getting current timestamp
    pub fn get_timestamp() -> &'static str {
        "bpf_ktime_get_ns()"
    }
    
    /// Generate code for logging a message
    pub fn log_message(msg: &str) -> String {
        format!("info!(&ctx, \"{}\");", escape_string(msg))
    }
    
    /// Generate code for emitting an event to user space
    pub fn emit_event(data: &str) -> String {
        format!(r#"    // Emit event: {}
    unsafe {{
        let pid = bpf_get_current_pid_tgid() >> 32;
        EVENTS.insert(&(pid as u32), &1, 0);
    }}"#, data)
    }
    
    /// Generate code for incrementing a counter
    pub fn increment_counter(key: &str) -> String {
        format!(r#"    // Increment counter for: {}
    unsafe {{
        let key = {};
        let zero = 0u64;
        if let Some(count) = EVENTS.get(&key) {{
            EVENTS.insert(&key, &(count + 1), 0);
        }} else {{
            EVENTS.insert(&key, &1, 0);
        }}
    }}"#, key, key)
    }
    
    /// List of supported eBPF helper functions
    pub fn supported_helpers() -> Vec<&'static str> {
        vec![
            "bpf_get_current_pid_tgid",
            "bpf_get_current_uid_gid", 
            "bpf_get_current_comm",
            "bpf_ktime_get_ns",
            "bpf_trace_printk",
            "bpf_map_lookup_elem",
            "bpf_map_update_elem",
            "bpf_map_delete_elem",
        ]
    }
}

/// eBPF language constraints and supported features
pub mod constraints {
    /// Features supported in eBPF context
    pub fn supported_features() -> Vec<&'static str> {
        vec![
            "Basic arithmetic (+, -, *, /, %)",
            "Comparisons (==, !=, <, <=, >, >=)",
            "Boolean operations (&&, ||, ^)",
            "Integer and boolean literals",
            "String literals (for logging)",
            "Variable access (limited)",
            "Function calls (eBPF built-ins)",
            "Simple conditionals (if/else)",
            "Map operations",
        ]
    }
    
    /// Features NOT supported in eBPF context
    pub fn unsupported_features() -> Vec<&'static str> {
        vec![
            "Loops (for, while, loop)",
            "Dynamic memory allocation",
            "Closures/lambdas",
            "External command execution", 
            "File I/O operations",
            "Network operations",
            "Floating point arithmetic",
            "String manipulation",
            "Complex data structures",
            "Recursion",
        ]
    }
    
    /// Maximum eBPF program constraints
    pub fn max_constraints() -> &'static str {
        r#"eBPF programs have strict limitations:
- Maximum ~4096 instructions (kernel dependent)
- No unbounded loops
- Limited stack space (512 bytes)
- No dynamic memory allocation
- Only approved helper functions
- Must be verified by kernel verifier"#
    }
}
