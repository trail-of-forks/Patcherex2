#!/bin/bash

set -e

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
output_dir="${script_dir}/outs"
mkdir -p "${output_dir}"

usage() {
    echo "Usage: $0 <binary_file> <patch_file> [function_mapping] [symbols]"
    echo ""
    echo "Behavior:"
    echo "  - If function_mapping is omitted, ALL functions in the patch file are processed"
    echo "  - Existing functions in binary are MODIFIED"
    echo "  - Non-existing functions are INSERTED as new functions"
    echo ""
    echo "Arguments:"
    echo "  binary_file       - Path to the binary to patch"
    echo "  patch_file        - Path to LLVM IR file with patch functions"
    echo "  function_mapping  - (Optional) Function mapping in format:"
    echo "                      'original_func' for single function"
    echo "                      'func1,func2,func3' for multiple functions"
    echo "                      'orig1:patch1,orig2:patch2' for name mapping"
    echo "                      If omitted, processes ALL functions in IR file"
    echo "  symbols           - (Optional) Symbol definitions in format:"
    echo "                      'symbol1=0x12345,symbol2=67890'"
    echo ""
    echo "Examples:"
    echo "  # Process ALL functions in patch file (modify existing, insert new):"
    echo "  $0 firmware.elf patches.ll"
    echo ""
    echo "  # Patch single function:"
    echo "  $0 firmware.elf patches.ll my_function"
    echo ""
    echo "  # Patch multiple specific functions:"
    echo "  $0 firmware.elf patches.ll 'func1,func2,func3'"
    echo ""
    echo "  # Patch with name mapping:"
    echo "  $0 firmware.elf patches.ll 'original_func:patched_func'"
    echo ""
    echo "  # Patch with symbols:"
    echo "  $0 firmware.elf patches.ll 'my_func' 'config_base=0x4028888'"
    exit 1
}

# Validate arguments
if [ $# -lt 2 ]; then
    echo "Error: Insufficient arguments."
    usage
fi

binary_file="$1"
patch_file="$2"
function_mapping="${3:-}"
symbols="${4:-}"

# Validate files exist
if [ ! -f "${binary_file}" ]; then
    echo "Error: Binary file '${binary_file}' not found."
    exit 1
fi

if [ ! -f "${patch_file}" ]; then
    echo "Error: Patch file '${patch_file}' not found."
    exit 1
fi

binary_basename=$(basename "${binary_file}")
patch_basename=$(basename "${patch_file}")

echo "Copying files to output directory..."
cp "${binary_file}" "${output_dir}/"
cp "${patch_file}" "${output_dir}/"

echo "Building Docker image..."
docker build -t patcherex-builder "${script_dir}"

# Build the Python command
python_cmd="python /patcherex2/tools/patche_firmware.py /workdir/${binary_basename} /workdir/${patch_basename}"

if [ -n "${function_mapping}" ]; then
    python_cmd="${python_cmd} '${function_mapping}'"
fi

if [ -n "${symbols}" ]; then
    python_cmd="${python_cmd} '${symbols}'"
fi

echo "Running patcher..."
echo "Command: ${python_cmd}"

docker run --rm \
  -v "${output_dir}:/workdir" \
  patcherex-builder \
  bash -c "${python_cmd}"

echo ""
echo "Patching complete! Output in: ${output_dir}/"
