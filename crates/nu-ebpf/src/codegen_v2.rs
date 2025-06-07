/// Improved code generation that produces functional eBPF code
/// This module generates actual executable code instead of debug comments

use nu_protocol::ast::{Expr, Expression, Operator, Math, Comparison, Boolean};
use crate::GenerationContext;

/// Generate code for expressions as values (for use in conditions, assignments, etc)
pub fn generate_expression_value(expr: &Expression, ctx: &GenerationContext) -> String {
    match &expr.expr {
        Expr::Int(n) => n.to_string(),
        Expr::Bool(b) => b.to_string(),
        Expr::String(s) => format!("\"{}\"", crate::escape_string(s)),
        
        Expr::Var(_var_id) => {
            // TODO: Resolve variable names properly
            // For now, assume common eBPF variables
            "var_placeholder".to_string()
        }
        
        Expr::FullCellPath(cell_path) => {
            // Generate the field access and return the variable name
            if let Expr::Var(_) = &cell_path.head.expr {
                if let Some(nu_protocol::ast::PathMember::String { val: field_name, .. }) = cell_path.tail.first() {
                    // For field access, we need the variable name that holds the value
                    field_name.clone()
                } else {
                    "field_unknown".to_string()
                }
            } else {
                "complex_field".to_string()
            }
        }
        
        Expr::BinaryOp(lhs, op, rhs) => {
            let left = generate_expression_value(lhs, ctx);
            let right = generate_expression_value(rhs, ctx);
            
            if let Expr::Operator(operator) = &op.expr {
                match operator {
                    Operator::Math(math_op) => {
                        let op_str = match math_op {
                            Math::Add => "+",
                            Math::Subtract => "-",
                            Math::Multiply => "*",
                            Math::Divide => "/",
                            Math::Modulo => "%",
                            _ => "?",
                        };
                        format!("({} {} {})", left, op_str, right)
                    }
                    Operator::Comparison(comp_op) => {
                        let op_str = match comp_op {
                            Comparison::Equal => "==",
                            Comparison::NotEqual => "!=",
                            Comparison::LessThan => "<",
                            Comparison::LessThanOrEqual => "<=",
                            Comparison::GreaterThan => ">",
                            Comparison::GreaterThanOrEqual => ">=",
                            _ => "?",
                        };
                        format!("({} {} {})", left, op_str, right)
                    }
                    Operator::Boolean(bool_op) => {
                        let op_str = match bool_op {
                            Boolean::And => "&&",
                            Boolean::Or => "||",
                            Boolean::Xor => "^",
                        };
                        format!("({} {} {})", left, op_str, right)
                    }
                    _ => format!("({} ? {})", left, right),
                }
            } else {
                format!("({} ? {})", left, right)
            }
        }
        
        _ => "unknown_expr".to_string(),
    }
}

/// Generate a proper if statement
pub fn generate_if_statement(condition: &Expression, then_body: &str, else_body: Option<&str>, ctx: &GenerationContext) -> String {
    let cond_code = generate_expression_value(condition, ctx);
    
    let mut code = format!("    if {} {{\n{}\n    }}", cond_code, then_body);
    
    if let Some(else_code) = else_body {
        code.push_str(&format!(" else {{\n{}\n    }}", else_code));
    }
    
    code
}