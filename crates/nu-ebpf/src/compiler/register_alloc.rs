//! Register allocation for eBPF compilation
//!
//! Manages mapping from Nushell registers/variables to eBPF registers,
//! with LRU-based spilling to stack when registers are exhausted.

use std::collections::HashMap;

use nu_protocol::{RegId, VarId};

use super::instruction::EbpfReg;
use super::CompileError;

/// Where a value is currently stored
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueLocation {
    /// Value is in an eBPF register
    Register(EbpfReg),
    /// Value is spilled to stack at this offset (relative to R10)
    Spilled(i16),
}

/// Identifier for a value (either a Nushell register or variable)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValueKey {
    Reg(u32),
    Var(usize),
}

impl ValueKey {
    pub fn from_reg(reg: RegId) -> Self {
        ValueKey::Reg(reg.get())
    }

    pub fn from_var(var: VarId) -> Self {
        ValueKey::Var(var.get())
    }
}

/// Action needed when accessing a register
#[derive(Debug)]
pub enum RegAction {
    /// Value is already in this register, no action needed
    Ready(EbpfReg),
    /// Value needs to be reloaded from stack into this register
    Reload { reg: EbpfReg, stack_offset: i16 },
}

/// Action needed when allocating a register for writing
#[derive(Debug)]
pub enum AllocAction {
    /// Register is free, just use it
    Free(EbpfReg),
    /// Need to spill this value first, then use the register
    Spill {
        reg: EbpfReg,
        victim_key: ValueKey,
        /// Caller must provide a stack offset for the spill
        needs_stack_slot: bool,
    },
}

/// Maps Nushell register IDs to eBPF registers with spilling support
pub struct RegisterAllocator {
    /// Where each value currently lives
    locations: HashMap<ValueKey, ValueLocation>,
    /// Which eBPF register holds which value (reverse mapping)
    register_contents: HashMap<EbpfReg, ValueKey>,
    /// LRU order of registers (front = least recently used)
    lru_order: Vec<EbpfReg>,
    /// Available callee-saved registers
    available_regs: Vec<EbpfReg>,
}

impl RegisterAllocator {
    pub fn new() -> Self {
        // R6, R7, R8 are available (R9 reserved for context, R0-R5 for calls)
        let available_regs = vec![EbpfReg::R6, EbpfReg::R7, EbpfReg::R8];
        Self {
            locations: HashMap::new(),
            register_contents: HashMap::new(),
            lru_order: Vec::new(),
            available_regs,
        }
    }

    /// Mark a register as most recently used
    fn touch(&mut self, reg: EbpfReg) {
        self.lru_order.retain(|&r| r != reg);
        self.lru_order.push(reg);
    }

    /// Get a free register, or None if all are in use
    fn get_free_register(&self) -> Option<EbpfReg> {
        for reg in &self.available_regs {
            if !self.register_contents.contains_key(reg) {
                return Some(*reg);
            }
        }
        None
    }

    /// Get the least recently used register and its current owner
    fn get_lru(&self) -> Option<(EbpfReg, ValueKey)> {
        for &reg in &self.lru_order {
            if let Some(&key) = self.register_contents.get(&reg) {
                return Some((reg, key));
            }
        }
        // Fallback: just pick the first occupied register
        self.register_contents.iter().next().map(|(&r, &k)| (r, k))
    }

    /// Get a register for reading a value (may need reload from stack)
    pub fn get(&mut self, reg: RegId) -> Result<RegAction, CompileError> {
        let key = ValueKey::Reg(reg.get());
        self.get_value(key, || format!("Register %{} not allocated", reg.get()))
    }

    /// Get a register for reading a variable (may need reload from stack)
    pub fn get_var(&mut self, var_id: VarId) -> Result<RegAction, CompileError> {
        let key = ValueKey::Var(var_id.get());
        self.get_value(key, || format!("Variable ${} not allocated", var_id.get()))
    }

    fn get_value(
        &mut self,
        key: ValueKey,
        err_msg: impl FnOnce() -> String,
    ) -> Result<RegAction, CompileError> {
        match self.locations.get(&key).copied() {
            Some(ValueLocation::Register(reg)) => {
                self.touch(reg);
                Ok(RegAction::Ready(reg))
            }
            Some(ValueLocation::Spilled(offset)) => {
                // Need to reload - but we might need to spill something first
                // For now, return the reload action; caller handles getting a register
                // We'll allocate the register in the get_or_alloc path
                Err(CompileError::UnsupportedInstruction(format!(
                    "Value at stack offset {} needs reload (internal)",
                    offset
                )))
            }
            None => Err(CompileError::UnsupportedInstruction(err_msg())),
        }
    }

    /// Check if a value is spilled and needs reload
    pub fn needs_reload(&self, reg: RegId) -> Option<i16> {
        let key = ValueKey::Reg(reg.get());
        match self.locations.get(&key) {
            Some(ValueLocation::Spilled(offset)) => Some(*offset),
            _ => None,
        }
    }

    /// Check if a variable is spilled and needs reload
    pub fn var_needs_reload(&self, var_id: VarId) -> Option<i16> {
        let key = ValueKey::Var(var_id.get());
        match self.locations.get(&key) {
            Some(ValueLocation::Spilled(offset)) => Some(*offset),
            _ => None,
        }
    }

    /// Allocate a register for writing to a Nushell register
    pub fn get_or_alloc(&mut self, reg: RegId) -> Result<AllocAction, CompileError> {
        let key = ValueKey::Reg(reg.get());
        self.alloc_for_write(key)
    }

    /// Allocate a register for writing to a Nushell variable
    pub fn get_or_alloc_var(&mut self, var_id: VarId) -> Result<AllocAction, CompileError> {
        let key = ValueKey::Var(var_id.get());
        self.alloc_for_write(key)
    }

    fn alloc_for_write(&mut self, key: ValueKey) -> Result<AllocAction, CompileError> {
        // If this value already has a register, reuse it
        if let Some(ValueLocation::Register(reg)) = self.locations.get(&key).copied() {
            self.touch(reg);
            return Ok(AllocAction::Free(reg));
        }

        // Try to get a free register
        if let Some(reg) = self.get_free_register() {
            // If value was spilled, it's being overwritten - remove spill location
            self.locations.remove(&key);

            self.locations.insert(key, ValueLocation::Register(reg));
            self.register_contents.insert(reg, key);
            self.touch(reg);
            return Ok(AllocAction::Free(reg));
        }

        // No free register - need to spill
        let (victim_reg, victim_key) = self.get_lru().ok_or(CompileError::RegisterExhaustion)?;

        // Update victim to show it will be spilled (caller provides offset)
        // For now we just mark that spilling is needed
        Ok(AllocAction::Spill {
            reg: victim_reg,
            victim_key,
            needs_stack_slot: true,
        })
    }

    /// Complete a spill operation after the caller has allocated a stack slot
    pub fn complete_spill(
        &mut self,
        victim_key: ValueKey,
        victim_reg: EbpfReg,
        stack_offset: i16,
        new_key: ValueKey,
    ) {
        // Move victim to stack
        self.locations
            .insert(victim_key, ValueLocation::Spilled(stack_offset));
        self.register_contents.remove(&victim_reg);

        // Assign register to new key
        self.locations
            .insert(new_key, ValueLocation::Register(victim_reg));
        self.register_contents.insert(victim_reg, new_key);
        self.touch(victim_reg);
    }

    /// Complete a reload operation
    pub fn complete_reload(&mut self, key: ValueKey, reg: EbpfReg) {
        self.locations.insert(key, ValueLocation::Register(reg));
        self.register_contents.insert(reg, key);
        self.touch(reg);
    }

    /// Get the current register for a value, if it's in a register
    #[allow(dead_code)]
    pub fn current_register(&self, reg: RegId) -> Option<EbpfReg> {
        let key = ValueKey::Reg(reg.get());
        match self.locations.get(&key) {
            Some(ValueLocation::Register(r)) => Some(*r),
            _ => None,
        }
    }

    /// Get the current register for a variable, if it's in a register
    #[allow(dead_code)]
    pub fn current_var_register(&self, var_id: VarId) -> Option<EbpfReg> {
        let key = ValueKey::Var(var_id.get());
        match self.locations.get(&key) {
            Some(ValueLocation::Register(r)) => Some(*r),
            _ => None,
        }
    }
}

impl Default for RegisterAllocator {
    fn default() -> Self {
        Self::new()
    }
}
