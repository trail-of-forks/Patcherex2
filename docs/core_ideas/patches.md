# Patches

A patch is any object implementing the `Patch` protocol: it exposes an
`apply(session)` method. Add patches to `PatchSession.patches` in dependency order,
then apply and save them:

```python
from patcherex2 import InsertDataPatch, InsertInstructionPatch, PatchSession
from patcherex2.targets import ELF_AMD64_LINUX

with PatchSession.load_binary("program", target=ELF_AMD64_LINUX) as session:
    session.patches.append(InsertDataPatch("message", b"Hello\0"))
    session.patches.append(InsertInstructionPatch(0x401000, "lea rdi, [<message>]"))
    session.apply_patches()
    session.save_binary()
```

The built-in patches operate at four levels:

| Level | Insert | Modify | Remove |
|---|---|---|---|
| Data | `InsertDataPatch` | `ModifyDataPatch` | `RemoveDataPatch` |
| Instruction | `InsertInstructionPatch` | `ModifyInstructionPatch` | `RemoveInstructionPatch` |
| Function | `InsertFunctionPatch` | `ModifyFunctionPatch` | — |
| Raw bytes | — | `ModifyRawBytesPatch` | — |

There is no `RemoveFunctionPatch`. To disable a function, replace it with an
appropriate implementation or modify its instructions explicitly.

## Address Kinds

Most instruction, function, and data-modification patches accept runtime memory
addresses. They use the selected `BinaryAnalyzer` to translate those addresses into
file offsets.

`ModifyRawBytesPatch` makes the distinction explicit with `AddressType.MEMORY` and
`AddressType.FILE`:

```python
ModifyRawBytesPatch(0x401000, b"\x90", addr_type=AddressType.MEMORY)
ModifyRawBytesPatch(0x200, b"\x00", addr_type=AddressType.FILE)
```

An integer passed to `InsertDataPatch` is a file offset and updates the image there.
A string instead allocates new writable storage and registers the string as a patch
symbol.

## Data Patches

`InsertDataPatch(name, data)` allocates initialized writable data and exposes its
runtime address under `name`. `InsertDataPatch(file_offset, data)` writes at an
existing file offset.

`ModifyDataPatch(memory_address, data)` overwrites data at an existing runtime
address. `RemoveDataPatch(memory_address, size)` replaces the selected bytes with
zeroes; it does not shrink the image.

## Instruction Patches

`InsertInstructionPatch(memory_address, assembly)` installs a trampoline at the
given runtime address and places the new instructions in executable storage. Passing
a name instead creates a named executable block without installing a trampoline.

By default the source language is `InstructionPatchLanguage.ASM`. C micropatches use
`InstructionPatchLanguage.C` and an optional `InsertInstructionPatch.CConfig`:

```python
InsertInstructionPatch(
    0x401000,
    "rdi += 1;",
    language=InstructionPatchLanguage.C,
    c_config=InsertInstructionPatch.CConfig(scratch_regs=["r10", "r11"]),
)
```

`ModifyInstructionPatch(memory_address, assembly)` overwrites decoded instructions,
padding with architecture NOPs when necessary. `RemoveInstructionPatch` replaces
either a decoded instruction count or an exact byte count with NOPs:

```python
RemoveInstructionPatch(0x401000, num_instr=2)
RemoveInstructionPatch(0x401000, num_bytes=8)
```

Specify only one of `num_instr` and `num_bytes`. When neither is supplied, one
instruction is removed.

## Function Patches

`InsertFunctionPatch(name, c_source)` compiles a new named function into executable
storage. Passing a runtime address instead installs a call to the new function at
that address. Address-based insertion also supports `prefunc`, `postfunc`, and
`save_context` options.

`ModifyFunctionPatch(name_or_address, c_source)` replaces an existing function. If
the compiled replacement does not fit in the original extent, Patcherex2 allocates a
detour target and replaces the function entry with a jump.

## Symbol References

In patch assembly, `<name>` is replaced with the address of a symbol. The name may
refer to content inserted by an earlier patch, a mapped symbol reported by the binary
analyzer, or an explicit entry passed through `symbols=`.

```python
session.patches.append(InsertDataPatch("message", b"Hello, world!\0"))
session.patches.append(InsertInstructionPatch(0x401000, "lea rdi, [<message>]\ncall <puts>"))
```

Patch order matters: `message` must be registered before a later patch can resolve
it. A missing symbol raises `UnresolvedSymbolError`.

!!! warning "Deprecated symbol syntax"
    The legacy `{name}` form still works but emits a warning. Braces conflict with
    assembly constructs such as ARM register lists (`push {r7}`). Use `<name>` for
    symbol references.
