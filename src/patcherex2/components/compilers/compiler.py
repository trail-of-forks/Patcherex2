from __future__ import annotations

import logging
import os
import subprocess
import tempfile

import cle
from elftools.elf.elffile import ELFFile

logger = logging.getLogger(__name__)


class Compiler:
    def __init__(self, p) -> None:
        self.p = p
        # preserve_none is a special attribute flag to allow us to control more registers as input to a C function
        # This feature is used for a C instruction patch
        self.preserve_none = False

    def compile(
        self,
        code: str,
        base=0,
        symbols: dict[str, int] | None = None, 
        extension: str = ".c",
        extra_compiler_flags: list[str] | None = None,
        linker_script: str | None = None,
        **kwargs,
    ) -> bytes:
        if symbols is None:
            symbols = {}
        if extra_compiler_flags is None:
            extra_compiler_flags = []
        td = tempfile.mkdtemp()
        try:
            print(f"tmpdir: {td}")
            code_name = f"code{extension}"
            # source file
            with open(os.path.join(td, code_name), "w") as f:
                f.write(code)

            # compile to object file
            try:
                args = (
                    [self._compiler]
                    + self._compiler_flags
                    + extra_compiler_flags
                    + [
                        "-c",
                        os.path.join(td, code_name),
                        "-o",
                        os.path.join(td, "obj.o"),
                    ]
                )
                print(args)
                subprocess.run(args, check=True, capture_output=True)
            except subprocess.CalledProcessError as e:
                logger.error(e.stderr.decode("utf-8"))
                raise e

            if not linker_script:
                # linker script
                _symbols = {}
                _symbols.update(self.p.symbols)
                _symbols.update(self.p.binary_analyzer.get_all_symbols())
                _symbols.update(symbols)

            # TODO: shouldn't put .rodata in .text, but otherwise switch case jump table won't work
            # Note that even we don't include .rodata here, cle might still include it if there is
            # no gap between .text and .rodata
            with open(os.path.join(td, "obj.o"), "rb") as f:
                linker_script_rodata_sections = " ".join(
                    [
                        f". = ALIGN({section['sh_addralign']}); *({section.name})"
                        for section in ELFFile(f).iter_sections()
                        if section.name.startswith(".rodata")
                    ]
                )
            #print(linker_script_rodata_sections)
            linker_script_symbols = "".join(
                f"{name} = {hex(addr)};" for name, addr in _symbols.items()
            )

            #linker_script_bss_symbols = " *(.bss) config_base = 0x4027508;"


            linker_script = f"SECTIONS {{ .patcherex2 : SUBALIGN(0) {{ . = {hex(base)}; *(.text) {linker_script_rodata_sections} {linker_script_symbols}}} }}"
            #print(linker_script)
            with open(os.path.join(td, "linker.ld"), "w") as f:
                f.write(linker_script)

            # link object file
            try:
                args = [self._linker] + [
                    "-relocatable",
                    os.path.join(td, "obj.o"),
                    "-T",
                    os.path.join(td, "linker.ld"),
                    "-o",
                    os.path.join(td, "obj_linked.o"),
                ]
                print(args)
                result = subprocess.run(args, check=True, capture_output=True)
                logger.debug(f"Linker stdout: {result.stdout.decode('utf-8')}")
                logger.debug(f"Linker stderr: {result.stderr.decode('utf-8')}")
            except subprocess.CalledProcessError as e:
                logger.error(f"Linker command failed: {' '.join(args)}")
                logger.error(f"Linker stdout: {e.stdout.decode('utf-8') if e.stdout else '(empty)'}")
                logger.error(f"Linker stderr: {e.stderr.decode('utf-8') if e.stderr else '(empty)'}")
                logger.error(f"Return code: {e.returncode}")
                logger.error(f"Temp directory (preserved): {td}")
                raise e

            # extract compiled code
            # Get load_options from kwargs if provided
            load_options = kwargs.get("load_options", {})
            main_opts = {"base_addr": 0x0}
            # Extract rebase_granularity separately as it's a Loader parameter, not main_opts
            rebase_granularity = load_options.get("rebase_granularity", 0x1000)
            # Remove rebase_granularity from load_options before updating main_opts
            load_options_for_main = {k: v for k, v in load_options.items() if k != "rebase_granularity"}
            main_opts.update(load_options_for_main)
            ld = cle.Loader(
                os.path.join(td, "obj_linked.o"),
                main_opts=main_opts,
                rebase_granularity=rebase_granularity
            )

            patcherex2_section = next(
                (s for s in ld.main_object.sections if s.name == ".patcherex2"), None
            )
            compiled_start = ld.all_objects[0].entry + base

            compiled = ld.memory.load(
                compiled_start,
                patcherex2_section.memsize - compiled_start,
            )
        finally:
            pass  # Keep temporary directory for debugging
        return compiled
