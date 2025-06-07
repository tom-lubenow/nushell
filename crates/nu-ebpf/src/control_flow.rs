/// Control flow generation for eBPF
/// Handles if/else statements and other control structures

use nu_protocol::ast::{Expr, Expression, Block as AstBlock};
use crate::{GenerationContext, generate_expression_with_context, generate_field_for_probe};

/// Analyze a block and generate proper control flow
pub fn generate_block_with_control_flow(block: &AstBlock, ctx: &GenerationContext) -> String {
    let mut output = String::new();
    let mut field_accesses = Vec::new();
    
    // First pass: collect field accesses that need setup
    for pipeline in &block.pipelines {
        for element in &pipeline.elements {
            collect_field_accesses(&element.expr, &mut field_accesses);
        }
    }
    
    // Generate field access setup code
    for field_name in field_accesses {
        if let Some(probe_func) = &ctx.probe_function {
            let access_code = generate_field_for_probe(probe_func, &field_name);
            if !access_code.is_empty() {
                output.push_str(&access_code);
                output.push('\n');
            }
        }
    }
    
    // Second pass: generate actual statements
    for pipeline in &block.pipelines {
        for element in &pipeline.elements {
            let stmt = generate_statement_with_control_flow(&element.expr, ctx);
            output.push_str(&stmt);
            output.push('\n');
        }
    }
    
    output
}

/// Collect field names that need access code
fn collect_field_accesses(expr: &Expression, accesses: &mut Vec<String>) {
    match &expr.expr {
        Expr::FullCellPath(cell_path) => {
            if let Expr::Var(_) = &cell_path.head.expr {
                if let Some(nu_protocol::ast::PathMember::String { val: field_name, .. }) = cell_path.tail.first() {
                    if !accesses.contains(field_name) {
                        accesses.push(field_name.clone());
                    }
                }
            }
        }
        Expr::BinaryOp(lhs, _, rhs) => {
            collect_field_accesses(lhs, accesses);
            collect_field_accesses(rhs, accesses);
        }
        Expr::Call(call) => {
            for arg in &call.arguments {
                if let Some(expr) = arg.expr() {
                    collect_field_accesses(expr, accesses);
                }
            }
        }
        _ => {}
    }
}

/// Generate a statement with proper control flow handling
fn generate_statement_with_control_flow(expr: &Expression, ctx: &GenerationContext) -> String {
    match &expr.expr {
        // Check for 'if' function call pattern
        Expr::Call(call) if is_if_call(call) => {
            generate_if_statement(call, ctx)
        }
        
        // Other calls are regular statements
        Expr::Call(call) => {
            crate::statement_gen::generate_call_statement(call, ctx).0
        }
        
        // Standalone strings become print statements
        Expr::String(s) => {
            format!("    info!(&ctx, \"{}\");", crate::escape_string(s))
        }
        
        _ => {
            format!("    // Unhandled statement: {:?}", expr.expr)
        }
    }
}

/// Check if a call looks like an if statement
fn is_if_call(call: &nu_protocol::ast::Call) -> bool {
    // In our parser, 'if' becomes a function call with the condition as first arg
    call.arguments.len() >= 1
}

/// Generate an if statement from a call
fn generate_if_statement(call: &nu_protocol::ast::Call, ctx: &GenerationContext) -> String {
    if let Some(condition_arg) = call.arguments.first() {
        if let Some(condition_expr) = condition_arg.expr() {
            let (condition_code, _) = generate_expression_with_context(condition_expr, ctx);
            
            // For now, generate a simple if statement
            // In a full implementation, we'd parse the then/else blocks
            format!("    if {} {{\n        // TODO: then block\n    }}", condition_code)
        } else {
            "    // Invalid if condition".to_string()
        }
    } else {
        "    // Missing if condition".to_string()
    }
}