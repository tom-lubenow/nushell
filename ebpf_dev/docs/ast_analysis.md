# AST Analysis for eBPF Subset

This document summarizes how closures and expressions are represented in the Nushell
abstract syntax tree (AST) and lists the nodes that will be supported for the first
iteration of the eBPF code generator.

## Closure Representation

Closures are parsed into [`Block`] structures and wrapped by [`Expr::Closure`].
A `Block` stores the pipeline list, captures and optional signature:

```rust
pub struct Block {
    pub signature: Box<Signature>,
    pub pipelines: Vec<Pipeline>,
    pub captures: Vec<(VarId, Span)>,
    pub redirect_env: bool,
    pub ir_block: Option<IrBlock>,
    pub span: Option<Span>,
}
```
【F:crates/nu-protocol/src/ast/block.rs†L6-L17】

The parser converts `{|param| ...}` syntax to a `Closure` expression. The logic
is implemented in `parse_closure_expression` which creates the block, handles the
parameter signature and records the block ID:

```rust
pub fn parse_closure_expression(
    working_set: &mut StateWorkingSet,
    shape: &SyntaxShape,
    span: Span,
) -> Expression {
    ...
    let block_id = working_set.add_block(Arc::new(output));
    Expression::new(working_set, Expr::Closure(block_id), span, Type::Closure)
}
```
【F:crates/nu-parser/src/parser.rs†L4924-L5046】

At runtime a closure value is represented by `engine::Closure` storing the block
ID and captured variables:

```rust
pub struct Closure {
    pub block_id: BlockId,
    pub captures: Vec<(VarId, Value)>,
}
```
【F:crates/nu-protocol/src/engine/closure.rs†L8-L13】

The value layer includes a corresponding variant so closures can travel through
pipelines:

```rust
pub enum Value {
    ...
    Closure {
        val: Box<Closure>,
        #[serde(rename = "span")]
        internal_span: Span,
    },
    ...
}
```
【F:crates/nu-protocol/src/value/mod.rs†L100-L121】

## Expression Representation

Expressions are defined by the [`Expr`] enum. Relevant variants include literals,
variables, operators and control flow constructs:

```rust
pub enum Expr {
    Range(Box<Range>),
    Var(VarId),
    VarDecl(VarId),
    Call(Box<Call>),
    Operator(Operator),
    UnaryNot(Box<Expression>),
    BinaryOp(Box<Expression>, Box<Expression>, Box<Expression>),
    Subexpression(BlockId),
    Block(BlockId),
    Closure(BlockId),
    MatchBlock(Vec<(MatchPattern, Expression)>),
    List(Vec<ListItem>),
    Table(Table),
    Record(Vec<RecordItem>),
    ...
}
```
【F:crates/nu-protocol/src/ast/expr.rs†L20-L49】

The general expression parser (`parse_expression`) dispatches to specific
handlers depending on the token sequence, supporting assignments, arithmetic and
command calls:

```rust
pub fn parse_expression(working_set: &mut StateWorkingSet, spans: &[Span]) -> Expression {
    ...
    let output = if spans[pos..]
        .iter()
        .any(|span| is_assignment_operator(working_set.get_span_contents(*span)))
    {
        parse_assignment_expression(working_set, &spans[pos..])
    } else if is_math_expression_like(working_set, spans[pos]) {
        parse_math_expression(working_set, &spans[pos..], None)
    } else {
        ...
        parse_call(working_set, &spans[pos..], spans[0])
    };
    ...
}
```
【F:crates/nu-parser/src/parser.rs†L5748-L5887】

## Initial eBPF AST Subset

The first version of the eBPF backend will handle a restricted set of AST nodes
based on the constraints outlined in `IMPLEMENTATION_PLAN.md`. Supported nodes
include:

- **Literals**: `Expr::Int`, `Expr::Bool` (numeric and boolean constants).
- **Variables**: `Expr::Var`, `Expr::VarDecl` for simple bindings.
- **Binary Operations**: `Expr::BinaryOp` with `Operator::Math`, `Operator::Comparison`
  and bitwise/boolean operators.
- **Unary Not**: `Expr::UnaryNot` for logical negation.
- **Conditionals**: `if` expressions parsed as `Expr::Block` structures with
  two pipelines (true/false branches).
- **Simple Calls**: `Expr::Call` to built-in eBPF helpers (e.g. `send`, `count`).
- **Lists and Records**: Basic literals via `Expr::List` and `Expr::Record` when
  they map to fixed-size structures.
- **Closures/Blocks**: Passed to eBPF commands using `Expr::Closure`.

Unsupported constructs for the initial phase include loops (`for`, `while`),
external command execution and complex pipeline redirection. Those nodes will be
rejected during analysis.

## References

- [`nu-protocol/src/value`](../../crates/nu-protocol/src/value) — core `Value`
  enum including closures.
- [`nu-protocol/src/ast`](../../crates/nu-protocol/src/ast) — AST definitions.
- [`nu-parser/src/parser.rs`](../../crates/nu-parser/src/parser.rs) — expression
  and closure parsing logic.

This overview should serve as a starting point when mapping Nushell AST nodes to
Rust eBPF code.
