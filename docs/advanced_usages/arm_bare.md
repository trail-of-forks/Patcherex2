# ARM Bare-Metal Targets

`ARM_ELF_BARE` and `ARM_RAW_BARE` require the caller to identify memory that may be used
for patches. Patcherex2 does not infer free device memory from an ELF or raw image.

Ranges use Python's half-open convention: `range(start, end)` includes `start` and
excludes `end`. Multiple discontiguous ranges are supported. They must not overlap.

```python
from patcherex2 import (
    ArmBareMetalRuntimeConfig,
    BareMetalAddressSpace,
    ComponentOverrides,
    PatchSession,
    TargetConfig,
)
from patcherex2.targets import ARM_ELF_BARE
from patcherex2.components.placement_strategies import ElfExplicitPlacement, RawExplicitPlacement

with PatchSession.load_binary(
    "firmware.elf",
    target=ARM_ELF_BARE,
    config=TargetConfig(
        overrides=ComponentOverrides(
            placement=ElfExplicitPlacement(
                BareMetalAddressSpace(
                    unused_flash=(
                        range(0x0005F12C, 0x00060000),
                        range(0x00070000, 0x00400000),
                    ),
                    unused_ram=(range(0x2000C240, 0x20010000),),
                )
            ),
            load_model=ArmBareMetalRuntimeConfig(insert_points=[0x80]).build(),
        )
    ),
) as session:
    ...
```

For ELF inputs, existing `PT_LOAD` headers are used to reject configured ranges that
overlap the load image (`p_paddr` through `p_filesz`) or runtime memory (`p_vaddr`
through `p_memsz`). They are not used to discover additional free space. New loadable
segments and matching sections are emitted when patches allocate new storage. Section
flags mirror the allocation: executable storage receives `SHF_EXECINSTR`, writable
storage receives `SHF_WRITE`, and all mapped storage receives `SHF_ALLOC`.

Raw images additionally require `image_base`, which maps a flash address to a file
offset, and accept an optional `fill_byte` used when the patched image grows:

```python
from patcherex2 import ArmRawImageConfig
from patcherex2.targets import ARM_RAW_BARE

with PatchSession.load_binary(
    "firmware.bin",
    target=ARM_RAW_BARE,
    config=TargetConfig(
        overrides=ComponentOverrides(
            image=ArmRawImageConfig(
                image_base=0x08000000,
                fill_byte=0xFF,
            ),
            placement=BareMetalAddressSpace(
                unused_flash=(range(0x08040000, 0x08080000),),
                unused_ram=(range(0x20010000, 0x20020000),),
            )),
            load_model=ArmBareMetalRuntimeConfig(insert_points=[0x08000100]).build(),
        )
    ),
) as session:
    ...
```

`insert_points` may be empty when only executable flash is allocated. At least one
insert point is required if a patch allocates initialized RAM, because startup code
must copy those bytes from flash to their runtime address.

The target combines independent layers: `ARM_BARE` supplies architecture tooling,
`BareMetalElfImageBackend` or `ArmRawImageBackend` owns the file representation,
`ElfExplicitPlacement` or `RawExplicitPlacement` owns address selection, and
`ArmBareMetalLoadModel` owns ARM runtime initialization.

`ARM_MIMXRT1052_ELF` uses the same backend and explicit placement/runtime configuration
as `ARM_ELF_BARE`. The board target no longer infers writable space from device capacity.
