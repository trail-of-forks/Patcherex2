#!/bin/bash

set -e

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
output_dir="${script_dir}/outs"
mkdir -p "${output_dir}"

usage() {
    echo "Usage: $0 <binary_file> <function_name> <patch_file>"
    echo "Example: $0 bl2.elf bl2_plat_arch_setup lifted.ll"
    exit 1
}

# Validate arguments
if [ $# -ne 3 ]; then
    echo "Error: Incorrect number of arguments."
    usage
fi

binary_file="$1"
function_name="$2"
patch_file="$3"

cp ${binary_file} ${output_dir}
cp ${patch_file} ${output_dir}


docker build -t patcherex-builder ${script_dir}

docker run -rm \
  -v "${script_dir}/outs:/workdir" \
  patcherex-builder \
  bash -c "python /patcherex2/tools/patche_firmware.py /workdir/bl2.elf bl2_plat_arch_setup /workdir/lifted.ll"
