//! Optimization passes for MIR
//!
//! This module provides a pass infrastructure for transforming MIR code.
//! Passes can be run individually or composed through the PassManager.
//!
//! ## Available Passes
//!
//! - **DCE** (Dead Code Elimination): Removes unused instructions and unreachable blocks
//! - **ConstFold** (Constant Folding): Evaluates constant expressions at compile time
//! - **StrengthReduce**: Converts expensive operations to cheaper equivalents

mod dce;
mod const_fold;

pub use dce::DeadCodeElimination;
pub use const_fold::ConstantFolding;

use super::cfg::CFG;
use super::mir::MirFunction;

/// Trait for MIR optimization passes
pub trait MirPass {
    /// Name of the pass for debugging/logging
    fn name(&self) -> &str;

    /// Run the pass on a function
    ///
    /// Returns true if the function was modified, false otherwise.
    /// This is used by the PassManager to determine when to stop iterating.
    fn run(&self, func: &mut MirFunction, cfg: &CFG) -> bool;
}

/// Manages and runs optimization passes
pub struct PassManager {
    passes: Vec<Box<dyn MirPass>>,
    /// Maximum iterations to prevent infinite loops
    max_iterations: usize,
}

impl PassManager {
    /// Create a new pass manager
    pub fn new() -> Self {
        Self {
            passes: Vec::new(),
            max_iterations: 10,
        }
    }

    /// Add a pass to the manager
    pub fn add_pass<P: MirPass + 'static>(&mut self, pass: P) {
        self.passes.push(Box::new(pass));
    }

    /// Set maximum iterations
    pub fn with_max_iterations(mut self, max: usize) -> Self {
        self.max_iterations = max;
        self
    }

    /// Run all passes until fixed point
    ///
    /// Returns the total number of modifications made.
    pub fn run(&self, func: &mut MirFunction) -> usize {
        let mut total_changes = 0;

        for iteration in 0..self.max_iterations {
            let mut changed = false;

            // Rebuild CFG for each iteration (passes may change the graph)
            let cfg = CFG::build(func);

            for pass in &self.passes {
                if pass.run(func, &cfg) {
                    changed = true;
                    total_changes += 1;
                }
            }

            if !changed {
                break;
            }

            // Prevent runaway optimization
            if iteration == self.max_iterations - 1 {
                eprintln!(
                    "PassManager: reached max iterations ({}), stopping",
                    self.max_iterations
                );
            }
        }

        total_changes
    }

    /// Run a single pass (useful for testing)
    pub fn run_pass<P: MirPass>(&self, pass: &P, func: &mut MirFunction) -> bool {
        let cfg = CFG::build(func);
        pass.run(func, &cfg)
    }
}

impl Default for PassManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Create a default set of optimization passes
pub fn default_passes() -> PassManager {
    let mut pm = PassManager::new();
    pm.add_pass(ConstantFolding);
    pm.add_pass(DeadCodeElimination);
    pm
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler::mir::{MirInst, MirValue};

    fn make_simple_function() -> MirFunction {
        let mut func = MirFunction::new();
        let bb0 = func.alloc_block();
        func.entry = bb0;

        let v0 = func.alloc_vreg();
        let v1 = func.alloc_vreg();

        func.block_mut(bb0).instructions.push(MirInst::Copy {
            dst: v0,
            src: MirValue::Const(42),
        });
        func.block_mut(bb0).instructions.push(MirInst::Copy {
            dst: v1,
            src: MirValue::VReg(v0),
        });
        func.block_mut(bb0).terminator = MirInst::Return {
            val: Some(MirValue::VReg(v1)),
        };

        func
    }

    #[test]
    fn test_pass_manager_creation() {
        let pm = PassManager::new();
        assert!(pm.passes.is_empty());
    }

    #[test]
    fn test_default_passes() {
        let pm = default_passes();
        assert!(!pm.passes.is_empty());
    }

    #[test]
    fn test_run_passes() {
        let pm = default_passes();
        let mut func = make_simple_function();

        // Should run without error
        let _changes = pm.run(&mut func);

        // Function should still be valid
        assert!(!func.blocks.is_empty());
        assert!(func.block(func.entry).terminator.is_terminator());
    }
}
