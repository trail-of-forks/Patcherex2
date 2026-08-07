class Target:
    target_classes = []

    #: ELF machine (``e_machine``), class (``EI_CLASS``) and data encoding
    #: (``EI_DATA``) that compiled patch code for this target must have. Used by
    #: :meth:`patcherex2.components.compilers.compiler.Compiler.check_object_arch`
    #: to reject an object built for the wrong architecture instead of writing it
    #: into the binary. ``None`` disables the check.
    expected_object_arch = None

    def __init__(self, p, binary_path):
        self.binary_path = binary_path
        self.p = p

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        # dedup so importlib.reload doesn't double-register
        if cls not in cls.target_classes:
            cls.target_classes.append(cls)

    def is_pie(self):
        """Whether the binary being patched is position-independent.

        Patch code compiled as PIC reaches extern data through the GOT, but the
        linker script in
        :meth:`patcherex2.components.compilers.compiler.Compiler.compile`
        defines symbols taken from the target as absolute addresses. Resolving
        a GOT-relative relocation against one of those makes the patch load
        *from* the datum's address instead of using it. Non-PIE targets
        therefore compile with ``-fno-pic``.

        The converse matters too: on a PIE binary ``-fno-pic`` makes the patch's
        own rodata references absolute, which is wrong once the patch is
        relocated, so PIE targets keep the default PIC codegen.
        """
        from elftools.elf.elffile import ELFFile

        try:
            with open(self.binary_path, "rb") as f:
                return ELFFile(f).header["e_type"] == "ET_DYN"
        except Exception:
            # Not an ELF, or unreadable: assume the conservative PIC default.
            return True

    def pic_compiler_flags(self, extra=()):
        """``-fno-pic`` (plus ``extra``) for non-PIE binaries, nothing for PIE.

        :param extra: Further flags needed alongside ``-fno-pic`` on this
            architecture, such as ``-mno-abicalls`` on MIPS.
        """
        if self.is_pie():
            return []
        return ["-fno-pic", *extra]

    @classmethod
    def detect_target(cls, p, binary_path):
        for target_class in cls.target_classes:
            if target_class.detect_target(binary_path):
                return target_class(p, binary_path)
        raise ValueError("Unknown target")

    def get_component(self, component_type, component_name, component_opts=None):
        if component_opts is None:
            component_opts = {}
        return getattr(self, f"get_{component_type}")(component_name, **component_opts)
