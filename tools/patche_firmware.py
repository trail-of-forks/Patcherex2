
import sys
import re
from patcherex2 import *

def extract_functions_from_llvm_ir(llvm_ir_content: str) -> dict[str, str]:
    """
    Extract all function definitions from LLVM IR content.
    Returns a dictionary mapping function names to their complete definitions.
    """
    functions = {}

    # Pattern to match function definitions in LLVM IR
    # Matches from 'define' to the closing brace, handling nested braces
    pattern = r'define\s+(?:dso_local\s+)?(?:\w+\s+)?@(\w+)\([^)]*\)[^{]*\{(?:[^{}]*|\{[^{}]*\})*\}'

    for match in re.finditer(pattern, llvm_ir_content, re.MULTILINE | re.DOTALL):
        func_name = match.group(1)
        func_body = match.group(0)
        functions[func_name] = func_body
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

        # Initialize Patcherex
        p = Patcherex(binary_name, target_opts={"binary_analyzer": "angr"})

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
        for original_func, patch_func, patch_type in patches_to_apply:
            func_code = available_functions[patch_func]
            patch_symbols = symbols if symbols else {}

            if patch_type == "modify":
                print(f"Preparing ModifyFunctionPatch: {original_func} -> {patch_func}")
                p.patches.append(
                    ModifyFunctionPatch(
                        original_func,
                        func_code,
                        symbols=patch_symbols,
                        extension=".ll"
                    )
                )
                modify_count += 1
            else:  # insert
                print(f"Preparing InsertFunctionPatch: {original_func} (new function)")
                p.patches.append(
                    InsertFunctionPatch(
                        original_func,
                        func_code,
                        symbols=patch_symbols,
                        compile_opts={"extension": ".ll"}
                    )
                )
                insert_count += 1

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
