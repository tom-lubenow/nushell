#![doc = include_str!("../README.md")]

use nu_protocol::ast::{Block, Expr, Expression, Pipeline, PipelineElement, Operator, Math, Comparison, Boolean, FullCellPath, PathMember};

pub mod codegen_v2;
pub mod statement_gen;

/// Context for code generation, including probe-specific information
pub struct GenerationContext {
    pub probe_function: Option<String>,
}

/// Generate Rust source for a kprobe eBPF program.
///
/// Analyzes the provided Nushell block and generates corresponding eBPF code.
/// Supports basic expressions, conditionals, arithmetic, and eBPF built-in functions.
pub fn generate_kprobe(code: &Block, fn_name: &str) -> String {
    generate_kprobe_with_context(code, fn_name, None)
}

/// Generate Rust source for a kprobe eBPF program with probe context.
///
/// This version accepts an optional probe function name to enable field access resolution.
pub fn generate_kprobe_with_context(code: &Block, fn_name: &str, probe_function: Option<&str>) -> String {
    let mut ebpf_body = String::new();
    let mut has_maps = false;
    
    // Create a generation context
    let ctx = GenerationContext {
        probe_function: probe_function.map(|s| s.to_string()),
    };
    
    // Analyze the block's pipelines and generate eBPF code
    for pipeline in &code.pipelines {
        let (pipeline_code, uses_maps) = generate_pipeline_with_context(pipeline, &ctx);
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
    let ctx = GenerationContext { probe_function: None };
    generate_pipeline_with_context(pipeline, &ctx)
}

/// Generate eBPF code for a Nushell pipeline with context
fn generate_pipeline_with_context(pipeline: &Pipeline, ctx: &GenerationContext) -> (String, bool) {
    let mut result = String::new();
    let mut uses_maps = false;
    
    for element in &pipeline.elements {
        let (element_code, element_uses_maps) = generate_pipeline_element_with_context(element, ctx);
        result.push_str(&element_code);
        result.push('\n');
        uses_maps = uses_maps || element_uses_maps;
    }
    
    (result, uses_maps)
}

/// Generate eBPF code for a pipeline element
fn generate_pipeline_element(element: &PipelineElement) -> (String, bool) {
    let ctx = GenerationContext { probe_function: None };
    generate_pipeline_element_with_context(element, &ctx)
}

/// Generate eBPF code for a pipeline element with context
fn generate_pipeline_element_with_context(element: &PipelineElement, ctx: &GenerationContext) -> (String, bool) {
    // Use statement generation for top-level expressions
    statement_gen::generate_statement(&element.expr, ctx)
}

/// Generate eBPF code for a Nushell expression
fn generate_expression(expr: &Expression) -> (String, bool) {
    let ctx = GenerationContext { probe_function: None };
    generate_expression_with_context(expr, &ctx)
}

/// Generate eBPF code for a Nushell expression with context
fn generate_expression_with_context(expr: &Expression, ctx: &GenerationContext) -> (String, bool) {
    match &expr.expr {
        Expr::Call(call) => {
            // Handle function calls - including eBPF built-ins
            generate_call_expression_v2(call, ctx)
        }
        Expr::String(s) => {
            // Return string literal as a value (for comparisons, etc)
            (format!("\"{}\"", escape_string(s)), false)
        }
        Expr::Int(n) => {
            // Return integer literal as a value
            (n.to_string(), false)
        }
        Expr::Bool(b) => {
            // Return boolean literal as a value
            (b.to_string(), false)
        }
        Expr::Var(var_id) => {
            // Variable access - handle special eBPF variables like $pid, $comm
            generate_variable_access_v2(*var_id)
        }
        Expr::BinaryOp(lhs, op, rhs) => {
            // Handle binary operations (arithmetic, comparisons, logical)
            generate_binary_operation_with_context(lhs, op, rhs, ctx)
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
        Expr::FullCellPath(cell_path) => {
            // Field access expressions like $ctx.filename
            generate_field_access_with_context(cell_path, ctx)
        }
        _ => {
            (format!("    // Unsupported expression: {:?}", expr.expr), false)
        }
    }
}

/// Generate code for binary operations (arithmetic, comparisons, logical)
fn generate_binary_operation(lhs: &Expression, op: &Expression, rhs: &Expression) -> (String, bool) {
    let ctx = GenerationContext { probe_function: None };
    generate_binary_operation_with_context(lhs, op, rhs, &ctx)
}

/// Generate code for binary operations with context
fn generate_binary_operation_with_context(lhs: &Expression, op: &Expression, rhs: &Expression, ctx: &GenerationContext) -> (String, bool) {
    let (left_code, left_uses_maps) = generate_expression_with_context(lhs, ctx);
    let (right_code, right_uses_maps) = generate_expression_with_context(rhs, ctx);
    
    if let Expr::Operator(operator) = &op.expr {
        let op_symbol = match operator {
            Operator::Math(math_op) => match math_op {
                Math::Add => "+",
                Math::Subtract => "-", 
                Math::Multiply => "*",
                Math::Divide => "/",
                Math::Modulo => "%",
                _ => "?",
            },
            Operator::Comparison(comp_op) => match comp_op {
                Comparison::Equal => "==",
                Comparison::NotEqual => "!=",
                Comparison::LessThan => "<",
                Comparison::LessThanOrEqual => "<=",
                Comparison::GreaterThan => ">",
                Comparison::GreaterThanOrEqual => ">=",
                _ => "?",
            },
            Operator::Boolean(bool_op) => match bool_op {
                Boolean::And => "&&",
                Boolean::Or => "||",
                Boolean::Xor => "^",
            },
            _ => "?",
        };
        
        // Generate actual expression code, not comments
        (format!("({} {} {})", left_code.trim(), op_symbol, right_code.trim()), 
         left_uses_maps || right_uses_maps)
    } else {
        (format!("({} ? {})", left_code.trim(), right_code.trim()), 
         left_uses_maps || right_uses_maps)
    }
}

/// Generate code for function calls, handling eBPF built-ins
fn generate_call_expression(call: &nu_protocol::ast::Call) -> (String, bool) {
    let ctx = GenerationContext { probe_function: None };
    generate_call_expression_v2(call, &ctx)
}

/// Generate code for function calls v2 - produces actual function calls
fn generate_call_expression_v2(call: &nu_protocol::ast::Call, ctx: &GenerationContext) -> (String, bool) {
    // Since we can't resolve function names from DeclId without engine state,
    // we'll recognize common patterns based on arguments
    
    // Check argument patterns to infer function type
    match call.arguments.len() {
        0 => {
            // No-argument calls - likely count(), timestamp(), get_stack()
            ("    count += 1;".to_string(), true)
        }
        1 => {
            // Single argument - likely print(), emit()
            if let Some(arg) = call.arguments.first() {
                if let Some(expr) = arg.expr() {
                    let (arg_code, uses_maps) = generate_expression_with_context(expr, ctx);
                    
                    // If the argument is a string literal, it's likely print()
                    if matches!(&expr.expr, Expr::String(_)) {
                        (format!("    info!(&ctx, {});", arg_code), uses_maps)
                    } else {
                        // Otherwise might be emit() or count(key)
                        (format!("    emit_event({});", arg_code), true)
                    }
                } else {
                    ("    // Unknown function call".to_string(), false)
                }
            } else {
                ("    // Empty argument".to_string(), false)
            }
        }
        _ => {
            // Multiple arguments - generate a generic call
            ("    // Multi-argument function call".to_string(), false)
        }
    }
}

/// Generate code for variable access, handling special eBPF variables
fn generate_variable_access(var_id: nu_protocol::VarId) -> (String, bool) {
    let ctx = GenerationContext { probe_function: None };
    generate_variable_access_v2(var_id)
}

/// Generate code for variable access v2 - returns the expression value
fn generate_variable_access_v2(var_id: nu_protocol::VarId) -> (String, bool) {
    // Since we can't resolve variable names from IDs without engine state,
    // we'll use common patterns. In a real implementation, we'd need to
    // track variable names during parsing.
    
    // Common eBPF variables based on typical var_id patterns
    match var_id.get() {
        0 => ("ctx".to_string(), false),  // Often $ctx
        1 => ("(bpf_get_current_pid_tgid() >> 32)".to_string(), false), // $pid
        2 => ("(bpf_get_current_uid_gid() >> 32)".to_string(), false),  // $uid
        3 => {
            // $comm - requires buffer
            ("comm".to_string(), false)  // Assume it's been read into a variable
        }
        _ => (format!("var_{}", var_id.get()), false),
    }
}

/// Generate code for field access expressions like $ctx.filename
fn generate_field_access(cell_path: &FullCellPath) -> (String, bool) {
    let ctx = GenerationContext { probe_function: None };
    generate_field_access_with_context(cell_path, &ctx)
}

/// Generate code for field access expressions with probe context
fn generate_field_access_with_context(cell_path: &FullCellPath, ctx: &GenerationContext) -> (String, bool) {
    // For expressions, we need to return just the variable name that will hold the value
    // The actual field access code should be generated separately as statements
    
    if let Expr::Var(_var_id) = &cell_path.head.expr {
        if let Some(PathMember::String { val: field_name, .. }) = cell_path.tail.first() {
            // Return the field name as the expression value
            // The actual access code needs to be generated before this expression is used
            (field_name.clone(), false)
        } else {
            ("unknown_field".to_string(), false)
        }
    } else {
        ("complex_field_access".to_string(), false)
    }
}

/// Generate field access code for specific probe functions
fn generate_field_for_probe(probe_func: &str, field_name: &str) -> String {
    // This provides accurate field access for known probe functions
    match (probe_func, field_name) {
        // do_sys_open / sys_open
        ("do_sys_open" | "sys_open", "filename") => format!(
            r#"    // Access filename in {}
    let filename_ptr: *const u8 = ctx.arg(0).ok()?;
    let mut filename_buf = [0u8; 256];
    unsafe {{
        bpf_probe_read_user_str_bytes(filename_ptr, &mut filename_buf).ok()?;
    }}
    let filename = core::str::from_utf8(&filename_buf).ok()?;"#,
            probe_func
        ),
        ("do_sys_open" | "sys_open", "flags") => format!(
            r#"    // Access flags in {}
    let flags: i32 = ctx.arg(1).ok()?;"#,
            probe_func
        ),
        ("do_sys_open" | "sys_open", "mode") => format!(
            r#"    // Access mode in {}
    let mode: u16 = ctx.arg(2).ok()?;"#,
            probe_func
        ),
        
        // sys_read / sys_write
        ("sys_read" | "sys_write", "fd") => format!(
            r#"    // Access fd in {}
    let fd: u32 = ctx.arg(0).ok()?;"#,
            probe_func
        ),
        ("sys_read" | "sys_write", "buf") => format!(
            r#"    // Access buffer pointer in {}
    let buf: *const u8 = ctx.arg(1).ok()?;"#,
            probe_func
        ),
        ("sys_read" | "sys_write", "count") => format!(
            r#"    // Access count in {}
    let count: usize = ctx.arg(2).ok()?;"#,
            probe_func
        ),
        
        // tcp_connect
        ("tcp_connect", "sk") => format!(
            r#"    // Access socket in tcp_connect
    let sk: *const core::ffi::c_void = ctx.arg(0).ok()?;"#
        ),
        ("tcp_connect", "addr_len") => format!(
            r#"    // Access addr_len in tcp_connect
    let addr_len: i32 = ctx.arg(2).ok()?;"#
        ),
        
        // kmalloc
        ("kmalloc", "size") => format!(
            r#"    // Access size in kmalloc
    let size: usize = ctx.arg(0).ok()?;"#
        ),
        ("kmalloc", "flags") => format!(
            r#"    // Access flags in kmalloc
    let flags: u32 = ctx.arg(1).ok()?;"#
        ),
        
        // Default: empty string to fall back to generic handling
        _ => String::new(),
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
