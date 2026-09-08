# Advanced Usage

## Reuse Unreachable Code Locations

Patcherex2 can be used to reuse unreachable code locations in the binary.
Register them before calling `apply_patches()`:

```python
for function in session.binary_analyzer.get_unused_funcs():
    session.allocation_manager.add_free_space(function.addr, function.size, "RX")
```

`get_unused_funcs()` returns typed `FunctionInfo` values. Their `end` property is derived
from `addr + size`.

## Pre- and Post-function Hooks

When the first argument to `InsertFunctionPatch` is an address, `prefunc` and
`postfunc` supply assembly that runs immediately before and after the inserted function call:

```python
session.patches.append(
    InsertFunctionPatch(
        0xDEADBEEF,
        "int foo(int a) { return bar(); }",
        prefunc="mov rdi, 0x10",
        postfunc="mov rdi, rax",
    )
)
```

At `0xDEADBEEF`, the pre-function hook executes before `foo`; the post-function hook
executes after it returns. Hooks can prepare arguments or consume a return value.

## Saving and Restoring Context

`InsertInstructionPatch` and address-based `InsertFunctionPatch` can preserve the
architecture's configured register context around inserted code:

```python
session.patches.append(InsertInstructionPatch(0xDEADBEEF, "push rbp", save_context=True))
```

Assembly patches may alternatively place `SAVE_CONTEXT` and `RESTORE_CONTEXT` macros at
specific positions in their source.
