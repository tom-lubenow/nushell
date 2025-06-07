use nu_protocol::{ast::*, Span, Type, SpanId, VarId, DeclId};
use std::collections::HashMap;

/// A minimal parser for the eBPF-safe subset of Nushell
/// This parser handles the limited syntax allowed in eBPF programs:
/// - Arithmetic operations: +, -, *, /, %
/// - Comparisons: ==, !=, <, <=, >, >=
/// - Boolean operations: &&, ||
/// - Variables: $pid, $uid, $comm
/// - Functions: print(), count(), emit(), timestamp(), get_stack()
/// - Literals: strings and integers
/// - Keywords: if/else, where
/// - Simple if/else statements
pub struct EbpfParser {
    source: String,
    position: usize,
    span_offset: usize,
}

impl EbpfParser {
    pub fn new(source: String, span_offset: usize) -> Self {
        Self {
            source,
            position: 0,
            span_offset,
        }
    }

    /// Parse the source into a Block suitable for eBPF code generation
    pub fn parse(&mut self) -> Result<Block, String> {
        self.skip_whitespace();
        
        // Handle the closure syntax: { || ... } or { |args| ... }
        if self.consume_char('{') {
            self.skip_whitespace();
            
            // Check for parameter list
            if self.consume_char('|') {
                // Skip parameters for now - eBPF closures don't use them
                while !self.consume_char('|') && !self.is_at_end() {
                    self.advance();
                }
                self.skip_whitespace();
            }
            
            // Parse the body
            let mut block = Block::new();
            
            // Parse all expressions until we hit the closing brace
            while !self.peek_char().map(|c| c == '}').unwrap_or(true) && !self.is_at_end() {
                self.skip_whitespace();
                
                // Check if we've reached the closing brace after skipping whitespace
                if self.peek_char() == Some('}') {
                    break;
                }
                
                let expr = self.parse_simple_expression()?;
                let pipeline = self.create_pipeline(expr);
                block.pipelines.push(pipeline);
            }
            
            if !self.consume_char('}') {
                return Err("Expected '}' at end of closure".to_string());
            }
            
            Ok(block)
        } else {
            // Try to parse as a simple expression
            let mut block = Block::new();
            let expr = self.parse_simple_expression()?;
            let pipeline = self.create_pipeline(expr);
            block.pipelines = vec![pipeline];
            Ok(block)
        }
    }

    fn create_pipeline(&self, expr: Expression) -> Pipeline {
        let mut pipeline = Pipeline::new();
        
        // Create a pipeline element
        let element = PipelineElement {
            pipe: None,
            expr,
            redirection: None,
        };
        
        pipeline.elements.push(element);
        pipeline
    }

    fn parse_simple_expression(&mut self) -> Result<Expression, String> {
        // Parse expressions with operator precedence
        self.parse_or_expression()
    }
    
    // Logical OR (||) - lowest precedence
    fn parse_or_expression(&mut self) -> Result<Expression, String> {
        let mut left = self.parse_and_expression()?;
        
        while self.peek_string("||") {
            self.advance();
            self.advance();
            let right = self.parse_and_expression()?;
            left = self.create_binary_op(left, Operator::Boolean(Boolean::Or), right);
        }
        
        Ok(left)
    }
    
    // Logical AND (&&) 
    fn parse_and_expression(&mut self) -> Result<Expression, String> {
        let mut left = self.parse_equality_expression()?;
        
        while self.peek_string("&&") {
            self.advance();
            self.advance();
            let right = self.parse_equality_expression()?;
            left = self.create_binary_op(left, Operator::Boolean(Boolean::And), right);
        }
        
        Ok(left)
    }
    
    // Equality operators (==, !=)
    fn parse_equality_expression(&mut self) -> Result<Expression, String> {
        let mut left = self.parse_comparison_expression()?;
        
        loop {
            if self.peek_string("==") {
                self.advance();
                self.advance();
                let right = self.parse_comparison_expression()?;
                left = self.create_binary_op(left, Operator::Comparison(Comparison::Equal), right);
            } else if self.peek_string("!=") {
                self.advance();
                self.advance();
                let right = self.parse_comparison_expression()?;
                left = self.create_binary_op(left, Operator::Comparison(Comparison::NotEqual), right);
            } else {
                break;
            }
        }
        
        Ok(left)
    }
    
    // Comparison operators (<, <=, >, >=)
    fn parse_comparison_expression(&mut self) -> Result<Expression, String> {
        let mut left = self.parse_additive_expression()?;
        
        loop {
            if self.peek_string("<=") {
                self.advance();
                self.advance();
                let right = self.parse_additive_expression()?;
                left = self.create_binary_op(left, Operator::Comparison(Comparison::LessThanOrEqual), right);
            } else if self.peek_string(">=") {
                self.advance();
                self.advance();
                let right = self.parse_additive_expression()?;
                left = self.create_binary_op(left, Operator::Comparison(Comparison::GreaterThanOrEqual), right);
            } else if self.peek_char() == Some('<') {
                self.advance();
                let right = self.parse_additive_expression()?;
                left = self.create_binary_op(left, Operator::Comparison(Comparison::LessThan), right);
            } else if self.peek_char() == Some('>') {
                self.advance();
                let right = self.parse_additive_expression()?;
                left = self.create_binary_op(left, Operator::Comparison(Comparison::GreaterThan), right);
            } else {
                break;
            }
        }
        
        Ok(left)
    }
    
    // Addition and subtraction (+, -)
    fn parse_additive_expression(&mut self) -> Result<Expression, String> {
        let mut left = self.parse_multiplicative_expression()?;
        
        loop {
            self.skip_whitespace();
            match self.peek_char() {
                Some('+') => {
                    self.advance();
                    let right = self.parse_multiplicative_expression()?;
                    left = self.create_binary_op(left, Operator::Math(Math::Add), right);
                }
                Some('-') => {
                    self.advance();
                    let right = self.parse_multiplicative_expression()?;
                    left = self.create_binary_op(left, Operator::Math(Math::Subtract), right);
                }
                _ => break,
            }
        }
        
        Ok(left)
    }
    
    // Multiplication, division, and modulo (*, /, %)
    fn parse_multiplicative_expression(&mut self) -> Result<Expression, String> {
        let mut left = self.parse_primary_expression()?;
        
        loop {
            self.skip_whitespace();
            match self.peek_char() {
                Some('*') => {
                    self.advance();
                    let right = self.parse_primary_expression()?;
                    left = self.create_binary_op(left, Operator::Math(Math::Multiply), right);
                }
                Some('/') => {
                    self.advance();
                    let right = self.parse_primary_expression()?;
                    left = self.create_binary_op(left, Operator::Math(Math::Divide), right);
                }
                Some('%') => {
                    self.advance();
                    let right = self.parse_primary_expression()?;
                    left = self.create_binary_op(left, Operator::Math(Math::Modulo), right);
                }
                _ => break,
            }
        }
        
        Ok(left)
    }
    
    // Primary expressions (literals, variables, function calls, parentheses)
    fn parse_primary_expression(&mut self) -> Result<Expression, String> {
        self.skip_whitespace();
        
        // Handle parentheses
        if self.peek_char() == Some('(') {
            self.advance();
            let expr = self.parse_or_expression()?;
            self.skip_whitespace();
            if self.peek_char() != Some(')') {
                return Err("Expected closing parenthesis".to_string());
            }
            self.advance();
            return Ok(expr);
        }
        
        // Variables
        if self.peek_char() == Some('$') {
            self.advance(); // consume $
            let var_name = self.parse_identifier()?;
            eprintln!("  📊 Found eBPF variable: ${}", var_name);
            
            // Check for field access
            let mut expr = self.create_variable_expression(var_name.clone());
            
            while self.peek_char() == Some('.') {
                self.advance(); // consume .
                let field_name = self.parse_identifier()?;
                eprintln!("  📍 Found field access: ${}.{}", var_name, field_name);
                
                // Create a field access expression
                expr = self.create_field_access(expr, field_name);
            }
            
            return Ok(expr);
        }
        
        // String literals
        if self.peek_char() == Some('"') {
            self.advance(); // consume "
            let mut string_val = String::new();
            while let Some(ch) = self.peek_char() {
                if ch == '"' {
                    self.advance();
                    break;
                }
                string_val.push(ch);
                self.advance();
            }
            eprintln!("  📝 Found string literal: \"{}\"", string_val);
            
            return Ok(self.create_string_expression(string_val));
        }
        
        // Numbers
        if let Some(ch) = self.peek_char() {
            if ch.is_ascii_digit() {
                let num = self.parse_number()?;
                eprintln!("  🔢 Found number: {}", num);
                return Ok(self.create_int_expression(num));
            }
            
            // Function calls or keywords
            if ch.is_alphabetic() {
                let ident = self.parse_identifier()?;
                
                // Check for keywords
                if ident == "if" {
                    return self.parse_if_expression();
                } else if ident == "where" {
                    return self.parse_where_expression();
                }
                
                // Function call
                eprintln!("  🔧 Found eBPF function: {}()", ident);
                
                // For functions like print, we should parse arguments even without parentheses
                let args = if ident == "print" || ident == "emit" {
                    // Parse the next expression as an argument
                    self.skip_whitespace();
                    if self.peek_char() == Some('"') || self.peek_char() == Some('$') || 
                       self.peek_char().map(|c| c.is_ascii_digit()).unwrap_or(false) {
                        vec![self.parse_primary_expression()?]
                    } else {
                        vec![]
                    }
                } else if self.peek_char() == Some('(') {
                    self.advance();
                    let mut args = vec![];
                    
                    while self.peek_char() != Some(')') && !self.is_at_end() {
                        self.skip_whitespace();
                        if self.peek_char() == Some(')') {
                            break;
                        }
                        
                        args.push(self.parse_or_expression()?);
                        
                        self.skip_whitespace();
                        if self.peek_char() == Some(',') {
                            self.advance();
                        }
                    }
                    
                    if self.peek_char() == Some(')') {
                        self.advance();
                    } else {
                        return Err("Expected closing parenthesis in function call".to_string());
                    }
                    
                    args
                } else {
                    vec![]
                };
                
                return Ok(self.create_function_call(ident, args));
            }
        }
        
        // Default: create a nothing expression
        Ok(self.create_nothing_expression())
    }

    fn parse_identifier(&mut self) -> Result<String, String> {
        let mut ident = String::new();
        
        while let Some(ch) = self.peek_char() {
            if ch.is_alphanumeric() || ch == '_' {
                ident.push(ch);
                self.advance();
            } else {
                break;
            }
        }
        
        if ident.is_empty() {
            Err("Expected identifier".to_string())
        } else {
            Ok(ident)
        }
    }

    fn parse_number(&mut self) -> Result<i64, String> {
        let mut num_str = String::new();
        
        while let Some(ch) = self.peek_char() {
            if ch.is_ascii_digit() {
                num_str.push(ch);
                self.advance();
            } else {
                break;
            }
        }
        
        num_str.parse::<i64>()
            .map_err(|_| format!("Invalid number: {}", num_str))
    }

    // Helper methods for creating expressions
    fn create_int_expression(&self, value: i64) -> Expression {
        Expression {
            expr: Expr::Int(value),
            span: self.current_span(),
            span_id: SpanId::new(0), // Placeholder
            ty: Type::Int,
            custom_completion: None,
        }
    }

    fn create_string_expression(&self, value: String) -> Expression {
        Expression {
            expr: Expr::String(value),
            span: self.current_span(),
            span_id: SpanId::new(0), // Placeholder
            ty: Type::String,
            custom_completion: None,
        }
    }

    fn create_nothing_expression(&self) -> Expression {
        Expression {
            expr: Expr::Nothing,
            span: self.current_span(),
            span_id: SpanId::new(0), // Placeholder
            ty: Type::Nothing,
            custom_completion: None,
        }
    }
    
    fn create_variable_expression(&self, _var_name: String) -> Expression {
        Expression {
            expr: Expr::Var(VarId::new(0)), // Placeholder - would need proper variable resolution
            span: self.current_span(),
            span_id: SpanId::new(0),
            ty: Type::Any, // eBPF variables could be various types
            custom_completion: None,
        }
    }
    
    fn create_field_access(&self, base_expr: Expression, field_name: String) -> Expression {
        // Create a cell path for field access
        let member = PathMember::String {
            val: field_name,
            span: self.current_span(),
            optional: false,
            casing: Default::default(), // Use default casing
        };
        
        Expression {
            expr: Expr::FullCellPath(Box::new(FullCellPath {
                head: base_expr,
                tail: vec![member],
            })),
            span: self.current_span(),
            span_id: SpanId::new(0),
            ty: Type::Any,
            custom_completion: None,
        }
    }
    
    fn create_binary_op(&self, left: Expression, op: Operator, right: Expression) -> Expression {
        let op_expr = Expression {
            expr: Expr::Operator(op),
            span: self.current_span(),
            span_id: SpanId::new(0),
            ty: Type::Any,
            custom_completion: None,
        };
        
        Expression {
            expr: Expr::BinaryOp(Box::new(left), Box::new(op_expr), Box::new(right)),
            span: self.current_span(),
            span_id: SpanId::new(0),
            ty: Type::Any, // Type would depend on the operation
            custom_completion: None,
        }
    }
    
    fn create_function_call(&self, name: String, args: Vec<Expression>) -> Expression {
        // For now, create a Call expression with placeholder data
        Expression {
            expr: Expr::Call(Box::new(Call {
                decl_id: DeclId::new(0), // Placeholder
                head: self.current_span(),
                arguments: args.into_iter().map(|arg| Argument::Positional(arg)).collect(),
                parser_info: HashMap::new(),
            })),
            span: self.current_span(),
            span_id: SpanId::new(0),
            ty: Type::Any,
            custom_completion: None,
        }
    }
    
    fn parse_if_expression(&mut self) -> Result<Expression, String> {
        // For now, parse if as a special function call
        // In the future, we might want to create a proper Block expression
        self.skip_whitespace();
        
        // Parse condition
        let condition = self.parse_or_expression()?;
        
        self.skip_whitespace();
        
        // Expect opening brace
        if self.peek_char() != Some('{') {
            return Err("Expected '{' after if condition".to_string());
        }
        self.advance();
        
        // Parse then branch as a simple expression for now
        let _then_expr = self.parse_block_body()?;
        
        self.skip_whitespace();
        
        // Check for else
        if self.peek_string("else") {
            self.advance_by(4); // skip "else"
            self.skip_whitespace();
            
            if self.peek_char() == Some('{') {
                self.advance();
                let _else_expr = self.parse_block_body()?;
            }
        }
        
        // For now, return a placeholder expression
        // In actual implementation, we'd need to generate proper control flow
        Ok(self.create_function_call("if".to_string(), vec![condition]))
    }
    
    fn parse_where_expression(&mut self) -> Result<Expression, String> {
        // Parse 'where' as a filter expression
        // where $condition acts as a filter that only allows execution when condition is true
        self.skip_whitespace();
        
        // Parse the filter condition
        let condition = self.parse_or_expression()?;
        
        // Create a where expression as a special function call
        // In code generation, this will be translated to a conditional return
        Ok(self.create_function_call("where".to_string(), vec![condition]))
    }
    
    fn parse_block_body(&mut self) -> Result<Expression, String> {
        // Parse expressions until we hit closing brace
        let mut expressions = vec![];
        
        self.skip_whitespace();
        while self.peek_char() != Some('}') && !self.is_at_end() {
            expressions.push(self.parse_or_expression()?);
            self.skip_whitespace();
        }
        
        if self.peek_char() != Some('}') {
            return Err("Expected closing '}'".to_string());
        }
        self.advance();
        
        // Return the last expression or Nothing if empty
        Ok(expressions.into_iter().last().unwrap_or_else(|| self.create_nothing_expression()))
    }

    // Utility methods
    fn skip_whitespace(&mut self) {
        while let Some(ch) = self.peek_char() {
            if ch.is_whitespace() {
                self.advance();
            } else {
                break;
            }
        }
    }

    fn peek_char(&self) -> Option<char> {
        self.source.chars().nth(self.position)
    }

    fn consume_char(&mut self, expected: char) -> bool {
        if self.peek_char() == Some(expected) {
            self.advance();
            true
        } else {
            false
        }
    }

    fn advance(&mut self) {
        if !self.is_at_end() {
            self.position += 1;
        }
    }

    fn is_at_end(&self) -> bool {
        self.position >= self.source.len()
    }

    fn current_span(&self) -> Span {
        Span::new(self.span_offset + self.position, self.span_offset + self.position)
    }
    
    fn peek_string(&self, s: &str) -> bool {
        let chars: Vec<char> = self.source[self.position..].chars().take(s.len()).collect();
        let peeked: String = chars.into_iter().collect();
        peeked == s
    }
    
    fn advance_by(&mut self, count: usize) {
        for _ in 0..count {
            if !self.is_at_end() {
                self.advance();
            }
        }
    }
}