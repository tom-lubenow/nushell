#![doc = include_str!("../README.md")]

use nu_protocol::ast::{Block, Expr, Expression, Pipeline, PipelineElement};

/// Generate Rust source for a kprobe eBPF program.
///
/// Analyzes the provided Nushell block and generates corresponding eBPF code.
/// Supports basic expressions and eBPF built-in functions.
pub fn generate_kprobe(code: &Block, fn_name: &str) -> String {
    let mut ebpf_body = String::new();
    
    // Analyze the block's pipelines and generate eBPF code
    for pipeline in &code.pipelines {
        let pipeline_code = generate_pipeline(pipeline);
        ebpf_body.push_str(&pipeline_code);
        ebpf_body.push('\n');
    }
    
    // If no meaningful code was generated, use a default action
    if ebpf_body.trim().is_empty() {
        ebpf_body = "    info!(&ctx, \"probe hit\");".to_string();
    }

    format!(
        r#"use aya_bpf::macros::kprobe;
use aya_bpf::programs::KProbeContext;
use aya_log_ebpf::info;

#[kprobe(name = "{name}")]
pub fn {name}(ctx: KProbeContext) -> u32 {{
{body}
    0
}}
"#,
        name = fn_name,
        body = ebpf_body
    )
}

/// Generate eBPF code for a Nushell pipeline
fn generate_pipeline(pipeline: &Pipeline) -> String {
    let mut result = String::new();
    
    for element in &pipeline.elements {
        let element_code = generate_pipeline_element(element);
        result.push_str(&element_code);
        result.push('\n');
    }
    
    result
}

/// Generate eBPF code for a pipeline element
fn generate_pipeline_element(element: &PipelineElement) -> String {
    generate_expression(&element.expr)
}

/// Generate eBPF code for a Nushell expression
fn generate_expression(expr: &Expression) -> String {
    match &expr.expr {
        Expr::Call(call) => {
            // Handle function calls - could be eBPF built-ins
            generate_call_expression(call)
        }
        Expr::String(s) => {
            // String literals can be used in logging
            format!("    info!(&ctx, \"{}\");", escape_string(s))
        }
        Expr::Int(n) => {
            // Integer literals - could be used in comparisons or assignments
            format!("    // Integer: {}", n)
        }
        Expr::Bool(b) => {
            // Boolean literals
            format!("    // Boolean: {}", b)
        }
        Expr::Var(var_id) => {
            // Variable access - handle special eBPF variables
            generate_variable_access(*var_id)
        }
        Expr::BinaryOp(lhs, op, rhs) => {
            // Handle binary operations
            let left_code = generate_expression(lhs);
            let right_code = generate_expression(rhs);
            let op_code = generate_expression(op);
            format!("    // Binary op: {} {} {}", 
                   left_code.trim(), op_code.trim(), right_code.trim())
        }
        Expr::Block(block_id) => {
            // Nested blocks - for now just note them
            format!("    // Block: {:?}", block_id)
        }
        Expr::Closure(block_id) => {
            // Closures - for now just note them
            format!("    // Closure: {:?}", block_id)
        }
        Expr::Operator(op) => {
            // Operators in expressions
            format!("{:?}", op)
        }
        _ => {
            format!("    // Unsupported expression: {:?}", expr.expr)
        }
    }
}

/// Generate code for function calls, handling eBPF built-ins
fn generate_call_expression(call: &nu_protocol::ast::Call) -> String {
    // For Phase 3, we'll implement some basic built-in recognition
    // Since we don't have access to EngineState here, we'll use simple heuristics
    
    // Check if this might be a print/log function by examining arguments
    if call.arguments.is_empty() {
        // No-argument calls like print(), count(), etc.
        "    info!(&ctx, \"function called\");".to_string()
    } else {
        // Calls with arguments - try to generate something useful
        "    info!(&ctx, \"function called with args\");".to_string()
    }
}

/// Generate code for variable access, handling special eBPF variables
fn generate_variable_access(var_id: nu_protocol::VarId) -> String {
    // For Phase 3, we'll provide basic variable handling
    // Special eBPF variables like $pid, $comm would need to be mapped here
    // For now, we'll generate a comment
    format!("    // Variable access: {:?}", var_id)
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
        "(bpf_get_current_pid_tgid() >> 32) as u32"
    }
    
    /// Generate code for getting current thread group ID  
    pub fn get_tgid() -> &'static str {
        "bpf_get_current_pid_tgid() as u32"
    }
    
    /// Generate code for logging a message
    pub fn log_message(msg: &str) -> String {
        format!("info!(&ctx, \"{}\");", escape_string(msg))
    }
    
    /// Generate code for emitting an event
    pub fn emit_event(data: &str) -> String {
        format!("// TODO: Emit event with data: {}", data)
    }
}
