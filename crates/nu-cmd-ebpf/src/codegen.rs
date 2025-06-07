use nu_engine::eval_expression;
use nu_protocol::{
    ast::{Block, Expr, Expression, PathMember},
    debugger::WithoutDebug,
    engine::{EngineState, Stack},
    ShellError,
};
use std::collections::HashSet;

/// Generate eBPF code from a Nushell block with full engine state access
pub fn generate_ebpf_with_engine(
    block: &Block,
    probe_name: &str,
    engine_state: &EngineState,
    stack: &mut Stack,
) -> Result<String, ShellError> {
    let mut ebpf_body = String::new();
    let mut field_setup = String::new();
    let mut uses_maps = false;
    let fn_name = format!("probe_{}", probe_name);
    
    // First pass: collect field accesses and check for map usage
    let mut used_fields = std::collections::HashSet::new();
    for pipeline in &block.pipelines {
        for element in &pipeline.elements {
            collect_field_accesses(&element.expr, &mut used_fields);
            if uses_count_function(&element.expr) {
                uses_maps = true;
            }
        }
    }
    
    // Generate field access setup code
    for field in &used_fields {
        if let Some(setup_code) = generate_field_setup(probe_name, field) {
            field_setup.push_str(&setup_code);
            field_setup.push('\n');
        }
    }
    
    // Second pass: generate statements
    for pipeline in &block.pipelines {
        for element in &pipeline.elements {
            let stmt = generate_statement_with_engine(
                &element.expr,
                probe_name,
                engine_state,
                stack,
            )?;
            ebpf_body.push_str(&stmt);
            ebpf_body.push('\n');
        }
    }
    
    // If no meaningful code was generated, use a default action
    if ebpf_body.trim().is_empty() {
        ebpf_body = r#"    info!(&ctx, "probe hit");"#.to_string();
    }
    
    // Combine field setup and body
    let full_body = if field_setup.is_empty() {
        ebpf_body
    } else {
        format!("{}\n{}", field_setup, ebpf_body)
    };
    
    // Generate map declarations if needed
    let map_decls = if uses_maps {
        r#"
use aya_bpf::{macros::map, maps::HashMap};

#[map(name = "COUNTERS")]
static mut COUNTERS: HashMap<u32, u64> = HashMap::with_max_entries(1024, 0);
"#
    } else {
        ""
    };
    
    // Generate the complete eBPF program
    Ok(format!(
        r#"use aya_bpf::{{macros::kprobe, programs::KProbeContext, helpers::*}};
use aya_log_ebpf::info;
{maps}
#[kprobe(name = "{name}")]
pub fn {name}(ctx: KProbeContext) -> u32 {{
{body}
    0
}}
"#,
        maps = map_decls,
        name = fn_name,
        body = full_body
    ))
}

/// Generate a statement from an expression using engine state
fn generate_statement_with_engine(
    expr: &Expression,
    probe_name: &str,
    engine_state: &EngineState,
    stack: &mut Stack,
) -> Result<String, ShellError> {
    match &expr.expr {
        Expr::Call(call) => {
            // Get the command name
            let decl = engine_state.get_decl(call.decl_id);
                let cmd_name = decl.name();
                
                match cmd_name {
                    "print" => {
                        // Handle print command
                        if let Some(arg) = call.positional_nth(0) {
                            match &arg.expr {
                                Expr::String(s) => {
                                    Ok(format!(r#"    info!(&ctx, "{}");"#, escape_string(s)))
                                }
                                Expr::FullCellPath(cell_path) => {
                                    let field_code = generate_field_access(cell_path, probe_name)?;
                                    Ok(format!(r#"    info!(&ctx, "{{}}", {});"#, field_code))
                                }
                                _ => {
                                    // Evaluate the expression
                                    let value = eval_expression::<WithoutDebug>(engine_state, stack, arg)?;
                                    let string_val = value.to_expanded_string("", engine_state.get_config());
                                    Ok(format!(r#"    info!(&ctx, "{}");"#, escape_string(&string_val)))
                                }
                            }
                        } else {
                            Ok(r#"    info!(&ctx, "");"#.to_string())
                        }
                    }
                    "count" => {
                        // Handle count command - needs to use a BPF map
                        Ok(r#"    // Increment counter in BPF map
    let key = 0u32;
    unsafe {
        if let Some(count) = COUNTERS.get(&key) {
            let new_count = *count + 1;
            COUNTERS.insert(&key, &new_count, 0).ok();
        } else {
            COUNTERS.insert(&key, &1u64, 0).ok();
        }
    }"#.to_string())
                    }
                    "if" => {
                        // Handle if statement
                        generate_if_statement(call, probe_name, engine_state, stack)
                    }
                    _ => {
                        // Unknown command
                        Ok(format!("    // Unknown command: {}", cmd_name))
                    }
                }
        }
        Expr::String(s) => {
            // Standalone string becomes print
            Ok(format!(r#"    info!(&ctx, "{}");"#, escape_string(s)))
        }
        _ => {
            // Try to evaluate as expression
            Ok(format!("    // Unhandled expression: {:?}", expr.expr))
        }
    }
}

/// Generate field access code
fn generate_field_access(
    cell_path: &nu_protocol::ast::FullCellPath,
    probe_name: &str,
) -> Result<String, ShellError> {
    if let Expr::Var(_) = &cell_path.head.expr {
        if let Some(nu_protocol::ast::PathMember::String { val: field_name, .. }) = cell_path.tail.first() {
            // Generate appropriate field access based on probe type
            match (probe_name, field_name.as_str()) {
                ("do_sys_open", "filename") => Ok("filename".to_string()),
                ("sys_read", "count") => Ok("count".to_string()),
                ("sys_write", "count") => Ok("count".to_string()),
                _ => Ok(format!("ctx_{}", field_name)),
            }
        } else {
            Err(ShellError::GenericError {
                error: "Invalid field access".into(),
                msg: "Expected field name".into(),
                span: Some(cell_path.head.span),
                help: None,
                inner: vec![],
            })
        }
    } else {
        Err(ShellError::GenericError {
            error: "Invalid field access".into(),
            msg: "Expected $ctx".into(),
            span: Some(cell_path.head.span),
            help: None,
            inner: vec![],
        })
    }
}

/// Generate if statement
fn generate_if_statement(
    _call: &nu_protocol::ast::Call,
    _probe_name: &str,
    _engine_state: &EngineState,
    _stack: &mut Stack,
) -> Result<String, ShellError> {
    // In built-in commands, we can properly parse if statements
    // For now, return a placeholder
    Ok("    // If statement generation TBD".to_string())
}

/// Escape string for Rust string literals
fn escape_string(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

/// Collect field accesses from an expression
fn collect_field_accesses(expr: &Expression, fields: &mut HashSet<String>) {
    match &expr.expr {
        Expr::FullCellPath(cell_path) => {
            if let Expr::Var(_) = &cell_path.head.expr {
                if let Some(PathMember::String { val: field_name, .. }) = cell_path.tail.first() {
                    fields.insert(field_name.clone());
                }
            }
        }
        Expr::Call(call) => {
            // Check arguments for field accesses
            for arg in &call.arguments {
                if let Some(expr) = arg.expr() {
                    collect_field_accesses(expr, fields);
                }
            }
        }
        Expr::BinaryOp(lhs, _, rhs) => {
            collect_field_accesses(lhs, fields);
            collect_field_accesses(rhs, fields);
        }
        _ => {}
    }
}

/// Generate field setup code for a specific field
fn generate_field_setup(probe_name: &str, field_name: &str) -> Option<String> {
    match (probe_name, field_name) {
        // do_sys_open / sys_open fields
        ("do_sys_open" | "sys_open", "filename") => Some(
            r#"    let filename_ptr: *const u8 = match ctx.arg(0) {
        Ok(ptr) => ptr,
        Err(_) => return 0,
    };
    let mut filename_buf = [0u8; 256];
    let filename = unsafe {
        match bpf_probe_read_user_str_bytes(filename_ptr, &mut filename_buf) {
            Ok(_) => match core::str::from_utf8(&filename_buf) {
                Ok(s) => s.trim_end_matches('\0'),
                Err(_) => "invalid_utf8",
            },
            Err(_) => "read_error",
        }
    };"#.to_string()
        ),
        ("do_sys_open" | "sys_open", "flags") => Some(
            r#"    let flags: i32 = match ctx.arg(1) {
        Ok(f) => f,
        Err(_) => return 0,
    };"#.to_string()
        ),
        ("do_sys_open" | "sys_open", "mode") => Some(
            r#"    let mode: u16 = match ctx.arg(2) {
        Ok(m) => m,
        Err(_) => return 0,
    };"#.to_string()
        ),
        
        // sys_read / sys_write fields
        ("sys_read" | "sys_write", "fd") => Some(
            r#"    let fd: u32 = match ctx.arg(0) {
        Ok(f) => f,
        Err(_) => return 0,
    };"#.to_string()
        ),
        ("sys_read" | "sys_write", "count") => Some(
            r#"    let count: usize = match ctx.arg(2) {
        Ok(c) => c,
        Err(_) => return 0,
    };"#.to_string()
        ),
        
        // kmalloc fields
        ("kmalloc", "size") => Some(
            r#"    let size: usize = match ctx.arg(0) {
        Ok(s) => s,
        Err(_) => return 0,
    };"#.to_string()
        ),
        
        _ => None,
    }
}

/// Check if an expression uses the count function
fn uses_count_function(expr: &Expression) -> bool {
    match &expr.expr {
        Expr::Call(call) => {
            // We can't check the function name directly without engine state,
            // but we can check if it's a no-argument call (likely count())
            call.arguments.is_empty()
        }
        _ => false,
    }
}