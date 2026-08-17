class ArchInfo:
    """Defines shared architecture properties and jump reachability."""

    jmp_max_distance: int | None = None

    @classmethod
    def is_jump_reachable(cls, source_addr: int, target_addr: int) -> bool:
        if cls.jmp_max_distance is None:
            return True
        return abs(target_addr - source_addr) <= cls.jmp_max_distance
