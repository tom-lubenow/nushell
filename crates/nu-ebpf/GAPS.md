  NOT Supported (Major Gaps)

  1. String Interpolation - MIR infrastructure in place, code generation pending
  # Won't work yet:
  $"pid: ($ctx.pid)"
  # Has: StringAppend/IntToString MIR instructions, IR-to-MIR lowering
  # Needs: eBPF code generation for string concatenation

  2. Environment Variables - Not supported (with clear error message)
  # Won't work (eBPF runs in kernel, no access to user environment):
  $env.PATH
  # Error: "Environment variable access is not supported in eBPF"

  3. Named Arguments/Flags - Infrastructure in place
  # Now tracked during compilation:
  some-cmd --verbose   # Flag tracked
  count --per-cpu      # Named arg tracked
  # Not all commands use them yet - extend lower_call as needed

  4. Match Expressions - Expanded support
  # Now works:
  match $x {
      0 => "zero"
      1 | 2 => "small"   # Or patterns
      $y => $y           # Variable binding
      _ => "other"       # Wildcard
  }
  # Not yet: record/list destructuring patterns

  5. Cell Path Updates - UpsertCellPath missing
  # Won't work:
  $record.field = 42

  6. Closures as Values - Can't pass closures around
  # Won't work:
  let f = {|x| $x + 1 }
  $items | each $f

  7. Tables - Built on lists, so don't work
  # Won't work:
  [[name, age]; [Alice, 30]]

  8. Pipelines with Multiple Commands
  # Limited support - some built-ins only:
  $ctx.pid | count   # Works
  $ctx.pid | where { $in > 100 } | count  # Won't work
