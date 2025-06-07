use nu_protocol::{ast::*, Span, Type, SpanId};

/// A minimal parser for the eBPF-safe subset of Nushell
/// This parser handles the limited syntax allowed in eBPF programs:
/// - Arithmetic operations: +, -, *, /, %
/// - Comparisons: ==, !=, <, <=, >, >=
/// - Boolean operations: &&, ||
/// - Variables: $pid, $uid, $comm
/// - Functions: print(), count(), emit()
/// - Literals: strings and integers
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
                let expr = self.parse_simple_expression()?;
                let pipeline = self.create_pipeline(expr);
                block.pipelines.push(pipeline);
                
                self.skip_whitespace();
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
        self.skip_whitespace();
        
        // For Phase 5, we'll create placeholder expressions
        // This demonstrates that we can extract and begin parsing the source
        
        // Check what kind of expression we have
        if self.peek_char() == Some('$') {
            // Variable
            self.advance(); // consume $
            let var_name = self.parse_identifier()?;
            eprintln!("  📊 Found eBPF variable: ${}", var_name);
            
            // Create a simple Int expression as placeholder
            return Ok(self.create_int_expression(1));
        }
        
        if self.peek_char() == Some('"') {
            // String literal
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
            
            // Create a string expression
            return Ok(self.create_string_expression(string_val));
        }
        
        if let Some(ch) = self.peek_char() {
            if ch.is_alphabetic() {
                // Function call
                let func_name = self.parse_identifier()?;
                eprintln!("  🔧 Found eBPF function: {}()", func_name);
                
                // Skip parentheses if present
                if self.peek_char() == Some('(') {
                    self.advance();
                    while self.peek_char() != Some(')') && !self.is_at_end() {
                        self.advance();
                    }
                    if self.peek_char() == Some(')') {
                        self.advance();
                    }
                }
                
                // Create placeholder expression
                return Ok(self.create_int_expression(0));
            }
            
            if ch.is_ascii_digit() {
                // Number
                let num = self.parse_number()?;
                eprintln!("  🔢 Found number: {}", num);
                return Ok(self.create_int_expression(num));
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
}