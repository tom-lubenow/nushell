# Nushell Internals Reference for eBPF Integration

This document provides a quick reference to Nushell's internal structure, focusing on areas relevant to eBPF integration.

## Key Crates and Modules

### Core Architecture
```
nushell/
├── src/
│   └── main.rs                 # Main entry point
├── crates/
│   ├── nu-cli/                 # Command-line interface
│   ├── nu-command/             # Built-in commands
│   ├── nu-engine/              # Evaluation engine
│   ├── nu-parser/              # Parser and AST
│   ├── nu-protocol/            # Core data structures
│   ├── nu-plugin/              # Plugin system
│   └── nu-std/                 # Standard library
```

### Critical for eBPF Integration

#### 1. `nu-protocol` - Core Data Structures
**Location**: `crates/nu-protocol/src/`

Key files:
- `ast/` - Abstract Syntax Tree definitions
- `value.rs` - Value types and structures
- `engine/` - Engine state and context
- `ir/` - Intermediate representation (if present)

**Important Types**:
```rust
// Core value types
pub enum Value {
    Bool { val: bool, span: Span },
    Int { val: i64, span: Span },
    String { val: String, span: Span },
    Block { val: BlockId, span: Span },
    Closure { val: Closure, span: Span },
    // ... other types
}

// Block representation
pub struct Block {
    pub signature: Box<Signature>,
    pub pipelines: Vec<Pipeline>,
    pub captures: Vec<VarId>,
    pub redirect_env: bool,
    pub span: Span,
}

// Closure representation
pub struct Closure {
    pub block_id: BlockId,
    pub captures: Vec<(VarId, Value)>,
}
```

#### 2. `nu-parser` - Parser and AST
**Location**: `crates/nu-parser/src/`

Key files:
- `parser.rs` - Main parser logic
- `parse_keywords.rs` - Keyword parsing (if, for, etc.)
- `lex.rs` - Lexical analysis
- `lite_parser.rs` - Lightweight parsing

**Important for eBPF**:
- How closures `{|param| body}` are parsed
- Expression parsing and AST generation
- Block and pipeline structure

#### 3. `nu-engine` - Evaluation Engine
**Location**: `crates/nu-engine/src/`

Key files:
- `eval.rs` - Expression evaluation
- `call_ext.rs` - Command calling extensions
- `closure.rs` - Closure evaluation
- `stack.rs` - Variable stack management

**Important for eBPF**:
- How closures are evaluated
- Variable scoping and capture
- Expression evaluation pipeline

#### 4. `nu-command` - Built-in Commands
**Location**: `crates/nu-command/src/`

Key directories:
- `core/` - Core commands
- `filters/` - Data filtering commands
- `system/` - System interaction commands

**Reference for eBPF Commands**:
- Study existing command implementations
- Understand parameter parsing and validation
- Learn output formatting patterns

## AST Structure Analysis

### Closure Representation
Closures in Nushell are represented as:
1. **Block**: Contains the code structure
2. **Captures**: Variables captured from outer scope
3. **Signature**: Parameter definitions

```rust
// Example: {|x| $x + 1}
Closure {
    block_id: BlockId(123),
    captures: vec![], // No captures in this example
}

Block {
    signature: Signature {
        name: "",
        usage: "",
        required_positional: vec![
            PositionalArg {
                name: "x".to_string(),
                desc: "".to_string(),
                shape: SyntaxShape::Any,
                var_id: Some(VarId(456)),
            }
        ],
        // ...
    },
    pipelines: vec![
        Pipeline {
            elements: vec![
                PipelineElement {
                    pipe: None,
                    expr: Expression {
                        expr: Expr::BinaryOp {
                            lhs: Box::new(Expression {
                                expr: Expr::Var(VarId(456)), // $x
                                // ...
                            }),
                            op: Operator::Math(Math::Plus),
                            rhs: Box::new(Expression {
                                expr: Expr::Int(1),
                                // ...
                            }),
                        },
                        // ...
                    },
                    redirection: None,
                }
            ]
        }
    ],
    // ...
}
```

### Expression Types
Key expression types for eBPF transpilation:

```rust
pub enum Expr {
    Bool(bool),
    Int(i64),
    Float(f64),
    Binary(Vec<u8>),
    String(String),
    Var(VarId),
    VarDecl(VarId),
    Call(Box<Call>),
    BinaryOp {
        lhs: Box<Expression>,
        op: Operator,
        rhs: Box<Expression>,
    },
    UnaryNot {
        expr: Box<Expression>,
    },
    Block(BlockId),
    Closure(BlockId),
    // ... many more
}
```

## Plugin System Integration

### Plugin Architecture
**Location**: `crates/nu-plugin/src/`

Key concepts:
- Plugins communicate via JSON-RPC
- Commands are registered with signatures
- Input/output uses Nushell's Value types

### Creating eBPF Commands
Our eBPF commands will likely be implemented as:
1. **Built-in commands** (integrated into nu-command)
2. **Plugin commands** (separate binary)

**Built-in approach** (recommended):
- Add to `crates/nu-command/src/`
- Register in command registry
- Direct access to AST and engine

**Plugin approach**:
- Separate `nu_plugin_ebpf` crate
- JSON-RPC communication
- More isolated but harder AST access

## Research Tasks

### Phase 1: Understanding the AST
1. **Study closure parsing**:
   ```bash
   # In Nushell REPL
   ast "{|x| $x + 1}"
   ```

2. **Examine expression structure**:
   ```bash
   # Look at different expression types
   ast "if true { 1 } else { 2 }"
   ast "$x + $y * 2"
   ast "some_function($arg)"
   ```

3. **Analyze block structure**:
   ```bash
   # Study block representation
   ast "{ let x = 1; $x + 2 }"
   ```

### Phase 1: Code Exploration
1. **Trace closure evaluation**:
   - Set breakpoints in `nu-engine/src/closure.rs`
   - Follow execution path for simple closures
   - Understand variable capture mechanism

2. **Study command implementation**:
   - Look at `crates/nu-command/src/filters/where_.rs`
   - Understand how commands receive and process closures
   - Learn parameter validation patterns

3. **Examine AST construction**:
   - Trace parsing in `nu-parser/src/parser.rs`
   - Understand how `{|param| body}` becomes AST nodes
   - Study expression parsing for operators

## eBPF Integration Points

### 1. Command Registration
```rust
// In nu-command/src/default_context.rs
pub fn create_default_context() -> EngineState {
    let mut engine_state = EngineState::new();
    
    // Add eBPF commands
    bind_command! {
        engine_state,
        BpfKprobe,
        BpfTracepoint,
        BpfUprobe,
        // ...
    };
    
    engine_state
}
```

### 2. Command Implementation
```rust
// Example structure for bpf_kprobe command
#[derive(Clone)]
pub struct BpfKprobe;

impl Command for BpfKprobe {
    fn name(&self) -> &str {
        "bpf_kprobe"
    }

    fn signature(&self) -> Signature {
        Signature::build("bpf_kprobe")
            .required("function", SyntaxShape::String, "Kernel function to probe")
            .required("closure", SyntaxShape::Closure(None), "eBPF program logic")
    }

    fn run(
        &self,
        engine_state: &EngineState,
        stack: &mut Stack,
        call: &Call,
        input: PipelineData,
    ) -> Result<PipelineData, ShellError> {
        // 1. Extract function name and closure from call
        // 2. Get closure's Block from engine_state
        // 3. Analyze Block AST for eBPF compatibility
        // 4. Generate Rust eBPF code
        // 5. Compile and load with Aya
        // 6. Return streaming output
    }
}
```

### 3. AST Analysis for eBPF
```rust
fn analyze_ebpf_block(block: &Block, engine_state: &EngineState) -> Result<EbpfProgram, EbpfError> {
    // Validate eBPF constraints:
    // - No loops
    // - Limited expressions
    // - Only allowed built-ins
    
    for pipeline in &block.pipelines {
        for element in &pipeline.elements {
            match &element.expr.expr {
                Expr::Call(call) => {
                    // Check if call is eBPF-compatible
                    validate_ebpf_call(call)?;
                }
                Expr::BinaryOp { lhs, op, rhs } => {
                    // Validate binary operations
                    validate_ebpf_binop(lhs, op, rhs)?;
                }
                // ... handle other expression types
            }
        }
    }
    
    // Generate eBPF code
    generate_ebpf_rust_code(block)
}
```

## Next Steps

1. **Set up development environment** with container_setup.sh
2. **Build Nushell** and explore with debugger
3. **Create simple test closures** and examine their AST
4. **Implement basic command structure** for bpf_kprobe
5. **Design AST → Rust code generation pipeline**

## Useful Debug Commands

```bash
# In Nushell REPL
ast "your_expression_here"           # Show AST structure
view ir "your_expression_here"       # Show IR (if available)
help commands | where category == "core"  # List core commands
$nu.scope.commands | where name =~ "ast"  # Find AST-related commands
```

## References

- [Nushell Architecture](https://github.com/nushell/nushell/blob/main/docs/ARCHITECTURE.md)
- [Plugin Development Guide](https://www.nushell.sh/book/plugins.html)
- [AST Explorer](https://github.com/nushell/nushell/blob/main/crates/nu-cli/src/commands/debug/ast.rs)

---

**Note**: This is a living document. Update as we learn more about Nushell's internals during the research phase. 