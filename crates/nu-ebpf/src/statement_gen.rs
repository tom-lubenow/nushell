/// Statement generation for eBPF code
/// This module handles generating complete statements from expressions

use nu_protocol::ast::{Expr, Expression, Call, Argument};
use crate::{GenerationContext, generate_expression_with_context, generate_field_for_probe};

/// Generate a complete statement from an expression
pub fn generate_statement(expr: &Expression, ctx: &GenerationContext) -> (String, bool) {
    match &expr.expr {
        // Function calls become statements
        Expr::Call(call) => generate_call_statement(call, ctx),
        
        // String literals alone become print statements
        Expr::String(s) => {
            (format!("    info!(&ctx, \"{}\");", crate::escape_string(s)), false)
        }
        
        // Binary operations might be conditions
        Expr::BinaryOp(lhs, _op, _rhs) => {
            // Check if this is an if condition by looking at the context
            // For now, just evaluate as expression
            let (code, uses_maps) = generate_expression_with_context(expr, ctx);
            (format!("    // Expression result: {}", code), uses_maps)
        }
        
        // Field access needs setup code
        Expr::FullCellPath(cell_path) => {
            generate_field_access_statement(cell_path, ctx)
        }
        
        _ => {
            // Default: try to generate as expression
            let (code, uses_maps) = generate_expression_with_context(expr, ctx);
            (format!("    // Expression: {}", code), uses_maps)
        }
    }
}

/// Generate a function call as a statement
fn generate_call_statement(call: &Call, ctx: &GenerationContext) -> (String, bool) {
    // Try to identify the function based on its arguments
    match call.arguments.len() {
        0 => {
            // No args - likely count(), timestamp(), etc.
            ("    count += 1;".to_string(), true)
        }
        1 => {
            if let Some(arg) = call.arguments.first() {
                if let Some(expr) = arg.expr() {
                    // Check for special patterns
                    match &expr.expr {
                        Expr::String(s) => {
                            // print("string")
                            (format!("    info!(&ctx, \"{}\");", crate::escape_string(s)), false)
                        }
                        Expr::Call(_) => {
                            // Nested call like print(timestamp())
                            let (inner_code, uses_maps) = generate_expression_with_context(expr, ctx);
                            (format!("    info!(&ctx, \"Value: {{}}\", {});", inner_code), uses_maps)
                        }
                        _ => {
                            // emit(value) or similar
                            let (arg_code, uses_maps) = generate_expression_with_context(expr, ctx);
                            (format!("    emit_event({});", arg_code), true)
                        }
                    }
                } else {
                    ("    // Unknown function argument".to_string(), false)
                }
            } else {
                ("    // Empty function argument".to_string(), false)
            }
        }
        _ => {
            // Multiple arguments
            ("    // Multi-argument function not yet supported".to_string(), false)
        }
    }
}

/// Generate field access with necessary setup code
fn generate_field_access_statement(cell_path: &nu_protocol::ast::FullCellPath, ctx: &GenerationContext) -> (String, bool) {
    if let Expr::Var(_) = &cell_path.head.expr {
        if let Some(nu_protocol::ast::PathMember::String { val: field_name, .. }) = cell_path.tail.first() {
            // Generate the field access code if we have probe context
            if let Some(probe_func) = &ctx.probe_function {
                let access_code = generate_field_for_probe(probe_func, field_name);
                if !access_code.is_empty() {
                    return (access_code, false);
                }
            }
            
            // Fallback: generic field access
            (format!("    // Field access: $ctx.{} (need probe context)", field_name), false)
        } else {
            ("    // Invalid field access".to_string(), false)
        }
    } else {
        ("    // Complex field access not supported".to_string(), false)
    }
}

/// Check if an expression is likely an if condition
pub fn is_condition_context(expr: &Expression) -> bool {
    // In the future, we'd check parent context
    // For now, binary comparisons are likely conditions
    matches!(&expr.expr, Expr::BinaryOp(_, _, _))
}