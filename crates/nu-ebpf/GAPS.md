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

  5. Cell Path Updates - Not supported (with clear error message)
  # Won't work (eBPF records are built once then emitted):
  $record.field = 42
  # Error: "Cell path update (.field = ...) is not supported in eBPF"
  # Workaround: Build record with correct value initially

  6. Closures as Values - Not supported (with clear error message)
  # Won't work (eBPF can't dynamically dispatch):
  let f = {|x| $x + 1 }
  do $f 5
  # Error: "Closures as first-class values are not supported in eBPF"
  # Workaround: Use inline closures (e.g., `$items | each { $in + 1 }`)

  7. Tables - Now supported (tables are lists of records)
  # Should work (uses list + record infrastructure):
  [[name, age]; [Alice, 30]]
  # Limited by stack size (~10-15 rows max depending on record size)

  8. Pipelines with Multiple Commands
  # Limited support - single terminal command only:
  $ctx.pid | count                        # Works
  $ctx.pid | emit                         # Works
  { pid: $ctx.pid } | emit                # Works

  # Chained commands don't work yet:
  $ctx.pid | where { $in > 100 } | count  # Won't work
  $items | each { $in * 2 } | emit        # Won't work

  # To add: implement pipeline chaining in lower_call for
  # transformation commands (where, each, filter, etc.)
