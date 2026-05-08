
import sys
import re
from patcherex2 import *
from patcherex2.targets.elf_arm_bare import ElfArmBare
from elftools.elf.elffile import ELFFile

def is_arm32_non_pie(binary_path: str) -> tuple[bool, dict]:
    """
    Check if the binary is ARM32 and non-PIE (position-independent executable).
    Returns (is_arm32_non_pie, elf_info_dict)

    elf_info_dict contains:
        - e_machine: Machine architecture
        - e_type: Object file type (ET_EXEC for non-PIE, ET_DYN for PIE)
        - segments: List of PT_LOAD segments with their addresses
    """
    try:
        with open(binary_path, 'rb') as f:
            elf = ELFFile(f)
            header = elf.header

            # Check if ARM32 (EM_ARM = 0x28 = 40)
            is_arm = header['e_machine'] == 'EM_ARM'

            # Check if non-PIE (ET_EXEC = 2, PIE binaries are ET_DYN = 3)
            is_non_pie = header['e_type'] == 'ET_EXEC'

            # Gather segment information for memory region detection
            segments = []
            for segment in elf.iter_segments():
                if segment['p_type'] == 'PT_LOAD':
                    segments.append({
                        'p_vaddr': segment['p_vaddr'],
                        'p_memsz': segment['p_memsz'],
                        'p_flags': segment['p_flags'],
                    })

            elf_info = {
                'e_machine': header['e_machine'],
                'e_type': header['e_type'],
                'segments': segments,
            }

            return (is_arm and is_non_pie, elf_info)
    except Exception as e:
        print(f"Warning: Could not analyze binary format: {e}")
        return (False, {})

def detect_memory_regions(elf_info: dict) -> tuple[int, int, int, int]:
    """
    Detect flash and RAM memory regions from ELF segments.
    Returns (flash_start, flash_end, ram_start, ram_end)

    Heuristic:
    - Flash (RX): Low addresses, typically 0x08000000 or 0x00000000 range
    - RAM (RW): Higher addresses, typically 0x20000000 range
    """
    segments = elf_info.get('segments', [])

    if not segments:
        # Default values for typical ARM Cortex-M
        return (0x08000000, 0x08100000, 0x20000000, 0x20010000)

    # Separate segments by flags (executable vs writable)
    flash_regions = []
    ram_regions = []

    for seg in segments:
        vaddr = seg['p_vaddr']
        end_addr = vaddr + seg['p_memsz']
        flags = seg['p_flags']

        # PF_X (executable) = 0x1, PF_W (writable) = 0x2, PF_R (readable) = 0x4
        is_executable = flags & 0x1
        is_writable = flags & 0x2

        if is_executable and not is_writable:
            # RX segment -> Flash
            flash_regions.append((vaddr, end_addr))
        elif is_writable and not is_executable:
            # RW segment -> RAM
            ram_regions.append((vaddr, end_addr))

    # Find the extents
    if flash_regions:
        flash_start = min(addr for addr, _ in flash_regions)
        flash_end = max(addr for _, addr in flash_regions)
        # Add some extra space for patches
        flash_end += 0x100000  # Add 1MB
    else:
        flash_start = 0x08000000
        flash_end = 0x08100000

    if ram_regions:
        ram_start = min(addr for addr, _ in ram_regions)
        ram_end = max(addr for _, addr in ram_regions)
        # Add some extra space
        ram_end += 0x10000  # Add 64KB
    else:
        ram_start = 0x20000000
        ram_end = 0x20010000

    return (flash_start, flash_end, ram_start, ram_end)

def extract_functions_from_llvm_ir(llvm_ir_content: str) -> dict[str, str]:
    """
    Extract all function definitions from LLVM IR content along with their dependencies.
    Returns a dictionary mapping function names to their complete definitions including
    required global variables, declarations, type definitions, and metadata.
    """
    functions = {}

    # Extract module-level components
    # Type definitions (e.g., %struct.foo = type { i32, i8 })
    type_defs = re.findall(
        r'^%[\w.]+ = type\s+(?:opaque|<?\{[^}]*\}>?).*$',
        llvm_ir_content,
        re.MULTILINE
    )

    # Global variables (e.g., @.str = private constant [10 x i8] c"FW_CONFIG\00")
    global_vars = re.findall(
        r'^@[\w.]+ = (?:private |internal |external |global )?(?:constant |global).*$',
        llvm_ir_content,
        re.MULTILINE
    )

    # Function declarations (e.g., declare void @arm_bl2_plat_arch_setup())
    declarations = re.findall(
        r'^declare.*?@\w+\([^)]*\).*?(?:\n|$)',
        llvm_ir_content,
        re.MULTILINE | re.DOTALL
    )

    # Attributes (e.g., attributes #0 = { convergent })
    attributes = re.findall(
        r'^attributes #\d+ = \{[^}]+\}',
        llvm_ir_content,
        re.MULTILINE
    )

    # Debug metadata (all lines starting with !)
    metadata_lines = re.findall(
        r'^![\w.]+ = .*$',
        llvm_ir_content,
        re.MULTILINE
    )

    # Pattern to match function definitions in LLVM IR
    # Matches from 'define' to the closing brace, handling nested braces.
    # `(?:\w+\s+)*` covers any number of linkage / visibility / return-type
    # tokens between `define` and `@funcname` (e.g. `define internal i32 @foo`
    # has two words — `internal` and `i32` — before the name).
    pattern = r'define\s+(?:dso_local\s+)?(?:\w+\s+)*@(\w+)\([^)]*\)[^{]*\{(?:[^{}]*|\{[^{}]*\})*\}'

    # First pass: collect all function signatures from definitions as a map
    # This allows functions to reference each other
    local_function_decls_map = {}
    for match in re.finditer(pattern, llvm_ir_content, re.MULTILINE | re.DOTALL):
        func_name = match.group(1)
        func_signature = match.group(0)
        # Extract just the function signature (everything before the opening brace)
        sig_match = re.match(r'(define\s+(?:dso_local\s+)?(?:\w+\s+)*@\w+\([^)]*\)[^{]*)', func_signature)
        if sig_match:
            signature = sig_match.group(1)
            # Convert 'define' to 'declare' and strip attributes to create a declaration
            # Remove everything after the closing paren and attributes reference
            decl_match = re.match(r'define\s+(?:dso_local\s+)?(.*?@\w+\([^)]*\))', signature)
            if decl_match:
                body = decl_match.group(1)
                # LLVM forbids linkage keywords on `declare` (those only apply
                # to definitions). Strip them so patterns like
                # `define internal void @foo(...)` become
                # `declare void @foo(...)` instead of
                # `declare internal void @foo(...)` (an LLVM parse error).
                body = re.sub(
                    r'^(?:private|internal|available_externally|linkonce(?:_odr)?'
                    r'|weak(?:_odr)?|common|appending|extern_weak|external)\s+',
                    '',
                    body,
                )
                declaration = f"declare {body}"
                local_function_decls_map[func_name] = declaration

    suffix = (
        '\n\n' + '\n'.join(attributes) +
        '\n\n' + '\n'.join(metadata_lines)
    )

    for match in re.finditer(pattern, llvm_ir_content, re.MULTILINE | re.DOTALL):
        func_name = match.group(1)
        func_body = match.group(0)

        # Build prefix with all local function declarations EXCEPT the current function
        local_function_decls = [decl for name, decl in local_function_decls_map.items() if name != func_name]

        prefix = (
            '\n'.join(type_defs) + '\n\n' +
            '\n'.join(global_vars) + '\n\n' +
            '\n'.join(declarations) + '\n' +
            '\n'.join(local_function_decls) + '\n\n'
        )

        # Include all dependencies with the function
        complete_code = prefix + func_body + suffix
        functions[func_name] = complete_code
        print(f"Found function: {func_name}")

    return functions

def patch_binary(binary_name: str, function_mapping: dict[str, str], new_func_file: str, symbols: dict[str, int] = None):
    """
    Patch binary with multiple functions from LLVM IR file.

    Args:
        binary_name: Path to the binary to patch
        function_mapping: Dictionary mapping original function names to patch function names
        new_func_file: Path to LLVM IR file containing patch functions
        symbols: Optional symbols dictionary for compilation
    """
    try:
        with open(new_func_file, 'r', encoding='utf-8') as f:
            llvm_ir_content = f.read()

        print(f"Loaded LLVM IR from {new_func_file}")

        # Extract all functions from LLVM IR
        available_functions = extract_functions_from_llvm_ir(llvm_ir_content)

        if not available_functions:
            print("Error: No functions found in LLVM IR file")
            sys.exit(1)

        # Detect if binary is ARM32 non-PIE for flash memory allocation
        is_arm32_bare, elf_info = is_arm32_non_pie(binary_name)

        if is_arm32_bare:
            print(f"\n[INFO] Detected ARM32 non-PIE binary (bare-metal firmware)")
            print(f"       Machine: {elf_info.get('e_machine')}, Type: {elf_info.get('e_type')}")

            # Detect memory regions from segments
            flash_start, flash_end, ram_start, ram_end = detect_memory_regions(elf_info)
            print(f"       Flash region: {hex(flash_start)} - {hex(flash_end)}")
            print(f"       RAM region:   {hex(ram_start)} - {hex(ram_end)}")

            # Find insert points (entry point or first executable instruction)
            with open(binary_name, 'rb') as f:
                elf = ELFFile(f)
                entry_point = elf.header['e_entry']

                # In ARM Thumb mode, the LSB of the entry point is set to 1 to indicate Thumb mode
                # But the actual instruction address is at the even address (LSB cleared)
                # Clear the LSB to get the actual instruction address
                if entry_point & 1:
                    entry_point = entry_point & ~1  # Clear LSB for Thumb mode

                insert_points = [entry_point] if entry_point != 0 else [0x1000]
            print(f"       Insert points: {[hex(p) for p in insert_points]}")

            # Initialize Patcherex with ElfArmBare target for flash memory allocation
            load_options = {"rebase_granularity": 0x1000}
            p = Patcherex(
                binary_name,
                target_cls=ElfArmBare,
                target_opts={
                    "binary_analyzer": "angr",
                    "compiler": "clang19",
                    "binfmt_tool": "default",
                    "allocation_manager": "default"
                },
                components_opts={
                    "binfmt_tool": {
                        "flash_start": flash_start,
                        "flash_end": flash_end,
                        "ram_start": ram_start,
                        "ram_end": ram_end,
                        "insert_points": insert_points
                    }
                }
            )
            print(f"[INFO] Using ElfArmBare target with flash memory allocation (RX)")
        else:
            print(f"\n[INFO] Using standard ELF patching (auto-detected target)")
            # Initialize Patcherex with clang-19 (available in Docker)
            # Set rebase_granularity to avoid ARM relocation range issues
            load_options = {"rebase_granularity": 0x1000}
            p = Patcherex(
                binary_name,
                target_opts={
                    "binary_analyzer": "angr",
                    "compiler": "clang19"
                }
            )

        # If no mapping provided, insert all functions from patch file
        if not function_mapping:
            function_mapping = {name: name for name in available_functions.keys()}
            print(f"No function mapping provided. Will process all functions in IR file: {list(function_mapping.keys())}")
            print(f"Note: Functions will be MODIFIED if they exist in binary, or INSERTED if they don't.")

        # Validate functions and determine patch type (modify vs insert)
        print("\nValidating functions in binary...")
        patches_to_apply = []  # List of (original_func, patch_func, patch_type)

        for original_func, patch_func in function_mapping.items():
            if patch_func not in available_functions:
                print(f"Warning: Patch function '{patch_func}' not found in LLVM IR file. Skipping.")
                continue

            # Check if the original function exists in the binary
            try:
                func_info = p.binary_analyzer.get_function(original_func)
                if func_info is None:
                    # Function doesn't exist - we'll insert it as a new function
                    print(f"⊕ Function '{original_func}' not found in binary. Will insert as new function.")
                    patches_to_apply.append((original_func, patch_func, "insert"))
                else:
                    # Function exists - we'll modify it
                    print(f"✓ Found '{original_func}' in binary at {hex(func_info['addr'])} (size: {func_info['size']} bytes). Will modify.")
                    patches_to_apply.append((original_func, patch_func, "modify"))
            except Exception as e:
                print(f"Error: Failed to lookup function '{original_func}': {e}. Skipping.")
                continue

        if not patches_to_apply:
            print("\nError: No valid patches to apply")
            sys.exit(1)

        # Create patches for each function in order
        patch_count = 0
        modify_count = 0
        insert_count = 0

        print(f"\nPreparing {len(patches_to_apply)} patch(es)...")

        # IMPORTANT: Process InsertFunctionPatch first to pre-allocate symbols
        # This allows ModifyFunctionPatch to reference newly inserted functions
        insert_patches = []
        modify_patches = []

        for original_func, patch_func, patch_type in patches_to_apply:
            func_code = available_functions[patch_func]
            patch_symbols = symbols if symbols else {}

            if patch_type == "modify":
                modify_patches.append((original_func, patch_func, func_code, patch_symbols))
            else:  # insert
                insert_patches.append((original_func, patch_func, func_code, patch_symbols))

        # Add InsertFunctionPatch first - they will be applied before ModifyFunctionPatch
        # This ensures newly inserted functions are available as symbols when modifying other functions
        #
        # Determine the target's predominant code mode by sampling an existing
        # function (the first modify-patch target, or fallback to the entry
        # point). On ARM Cortex-M the entire .text is Thumb-only — without this
        # hint, InsertFunctionPatch defaults to is_thumb=False and the inserted
        # function is compiled as ARM mode, producing bytes that fault the CPU
        # the moment the call site branches into them. ModifyFunctionPatch
        # already queries is_thumb per-function; mirror that here for inserts.
        insert_is_thumb = False
        try:
            sample_addr = None
            if modify_patches:
                _orig0 = modify_patches[0][0]
                _info = p.binary_analyzer.get_function(_orig0)
                if _info and "addr" in _info:
                    sample_addr = _info["addr"]
            if sample_addr is None:
                sample_addr = p.binary_analyzer.get_entry_point()
            if sample_addr is not None:
                insert_is_thumb = bool(p.binary_analyzer.is_thumb(sample_addr))
                print(f"  Target ISA mode probe: is_thumb={insert_is_thumb} "
                      f"(sample addr={hex(sample_addr)})")
        except Exception as _exc:
            print(f"  Warning: ISA-mode probe failed ({_exc}); defaulting to ARM mode")

        print("\nAdding InsertFunctionPatch instances (will be applied first)...")
        for original_func, patch_func, func_code, patch_symbols in insert_patches:
            print(f"  Preparing InsertFunctionPatch: {original_func} (new function)")
            insert_compile_opts = {
                "extension": ".ll",
                "load_options": load_options
            }
            p.patches.append(
                InsertFunctionPatch(
                    original_func,
                    func_code,
                    symbols=patch_symbols,
                    is_thumb=insert_is_thumb,
                    compile_opts=insert_compile_opts
                )
            )
            insert_count += 1
            patch_count += 1

        print("\nAdding ModifyFunctionPatch instances (will be applied after inserts)...")
        for original_func, patch_func, func_code, patch_symbols in modify_patches:
            # Get original function info to print size before patching
            try:
                func_info = p.binary_analyzer.get_function(original_func)
                if func_info:
                    print(f"  Preparing ModifyFunctionPatch: {original_func} -> {patch_func} (original size: {func_info['size']} bytes)")
                else:
                    print(f"  Preparing ModifyFunctionPatch: {original_func} -> {patch_func}")
            except:
                print(f"  Preparing ModifyFunctionPatch: {original_func} -> {patch_func}")
            modify_compile_opts = {
                "extension": ".ll",
                "load_options": load_options
            }
            p.patches.append(
                ModifyFunctionPatch(
                    original_func,
                    func_code,
                    symbols=patch_symbols,
                    compile_opts=modify_compile_opts
                )
            )
            modify_count += 1
            patch_count += 1

        if patch_count == 0:
            print("Error: No valid patches to apply")
            sys.exit(1)

        print(f"\nApplying {patch_count} patch(es) sequentially...")
        print(f"  - {modify_count} function(s) modified")
        print(f"  - {insert_count} function(s) inserted")
        p.apply_patches()

        output_name = f"{binary_name}_patched"
        p.save_binary(output_name)

        print(f"\nPatched binary saved as {output_name}")
        print(f"Successfully applied {patch_count} patch(es) ({modify_count} modified, {insert_count} inserted)")

    except Exception as e:
        print(f"Error occurred: {e!r}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

def parse_function_mapping(mapping_str: str) -> dict[str, str]:
    """
    Parse function mapping string in format: original1:patch1,original2:patch2
    Returns dictionary mapping original function names to patch function names.
    """
    mapping = {}
    if not mapping_str:
        return mapping

    pairs = mapping_str.split(',')
    for pair in pairs:
        pair = pair.strip()
        if ':' in pair:
            original, patch = pair.split(':', 1)
            mapping[original.strip()] = patch.strip()
        else:
            # If no colon, assume same name for both
            mapping[pair] = pair

    return mapping

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <binary> <new_function_file> [function_mapping] [symbols]")
        print(f"\nBehavior:")
        print(f"  - When function_mapping is OMITTED: ALL functions in the IR file are processed")
        print(f"  - When function_mapping is PROVIDED: Only specified functions are processed")
        print(f"  - Existing functions in binary → MODIFIED with patch")
        print(f"  - Non-existing functions → INSERTED as new functions")
        print(f"\nARM32 Non-PIE (Bare-Metal Firmware) Detection:")
        print(f"  - Automatically detects ARM32 non-PIE binaries (e.g., firmware)")
        print(f"  - Uses ElfArmBare target with flash memory allocation")
        print(f"  - Flash regions get RX (Read-Execute) permissions")
        print(f"  - RAM regions get RW (Read-Write) permissions")
        print(f"  - Memory regions auto-detected from ELF segments")
        print(f"\nExamples:")
        print(f"  # Process ALL functions in IR file (auto-detect):")
        print(f"  {sys.argv[0]} binary.elf patches.ll")
        print(f"  ")
        print(f"  # Patch single specific function:")
        print(f"  {sys.argv[0]} binary.elf patches.ll func_name")
        print(f"  ")
        print(f"  # Patch multiple specific functions:")
        print(f"  {sys.argv[0]} binary.elf patches.ll func1,func2,func3")
        print(f"  ")
        print(f"  # Patch with name mapping (original:patch format):")
        print(f"  {sys.argv[0]} binary.elf patches.ll 'orig_func1:patch_func1,orig_func2:patch_func2'")
        print(f"  ")
        print(f"  # With symbols for compilation:")
        print(f"  {sys.argv[0]} binary.elf patches.ll func_name 'config_base=0x4028888,other_sym=0x1234'")
        print(f"  ")
        print(f"  # ARM32 bare-metal firmware patching (auto-detected):")
        print(f"  {sys.argv[0]} firmware.elf patch_functions.ll")
        sys.exit(1)

    binary_name = sys.argv[1]
    new_func_file = sys.argv[2]

    # Parse function mapping if provided
    function_mapping = {}
    if len(sys.argv) >= 4:
        function_mapping = parse_function_mapping(sys.argv[3])

    # Parse symbols if provided (format: symbol1=addr1,symbol2=addr2)
    symbols = {}
    if len(sys.argv) >= 5:
        symbol_pairs = sys.argv[4].split(',')
        for pair in symbol_pairs:
            if '=' in pair:
                name, addr = pair.split('=', 1)
                symbols[name.strip()] = int(addr.strip(), 0)  # 0 base handles hex/dec

    patch_binary(binary_name, function_mapping, new_func_file, symbols)

if __name__ == "__main__":
    main()
