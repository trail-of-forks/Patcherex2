
import sys
from patcherex2 import *

def patch_binary(binary_name: str, function_name: str, new_func_file: str):
    try:
        with open(new_func_file, 'r', encoding='utf-8') as f:
            new_func_str = f.read()
        
        print(f"Loaded new function definition from {new_func_file}")
        
        # Initialize Patcherex and apply patch
        p = Patcherex(binary_name)
        p.patches.append(ModifyFunctionPatch(function_name, new_func_str, extension=".ll"))
        p.apply_patches()
        
        output_name = f"{binary_name}_patched"
        p.save_binary(output_name)
        
        print(f"Patched binary saved as {output_name}")
    except Exception as e:
        print(f"Error occurred: {e!r}")
        sys.exit(1)

def main():    
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <binary> <function_name> <new_function_file>")
        sys.exit(1)
    
    binary_name = sys.argv[1]
    function_name = sys.argv[2]
    new_func_file = sys.argv[3]
    
    patch_binary(binary_name, function_name, new_func_file)

if __name__ == "__main__":
    main()
