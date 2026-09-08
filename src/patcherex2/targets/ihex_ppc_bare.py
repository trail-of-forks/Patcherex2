from patcherex2.targets.profiles import (
    IHEX_IMAGE,
    PPC_VLE_BARE,
    ppc_vle_analyzer_factory,
)
from patcherex2.targets.target import TargetDefinition

PPC_VLE_IHEX_BARE = TargetDefinition(
    name="ppc-vle-ihex-bare",
    architecture=PPC_VLE_BARE,
    image=IHEX_IMAGE,
    analyzer=ppc_vle_analyzer_factory(),
)
