"""The earlier name of the `aeos` package, kept so existing imports keep working.

`import aeos_receipts` and `from aeos_receipts.log import ReceiptLog` give the same
objects as `import aeos` and `from aeos.log import ReceiptLog`. New code should import
`aeos`.
"""
import importlib
import pkgutil
import sys

import aeos
from aeos import *  # noqa: F401,F403

for _info in pkgutil.walk_packages(aeos.__path__, "aeos."):
    if _info.name.endswith("__main__"):
        continue
    sys.modules["aeos_receipts" + _info.name[len("aeos"):]] = importlib.import_module(_info.name)
