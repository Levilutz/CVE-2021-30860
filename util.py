"""Generic utilities."""

import os
import shutil
from typing import List


def run_cmd_list(command: List[str]) -> str:
    """Convert list of args into single command, run, and get results."""
    return os.popen(" ".join(command)).read()


def wipe_dir(path: str) -> bool:
    """Wipe a path if it exists, return whether it existed."""
    if os.path.exists(path):
        shutil.rmtree(path)
        return True
    return False


def eqbound(text, width=80, character="="):
    """Bound text with equal signs."""
    if len(text) >= width:
        return text

    eq = width - len(text) - 2
    eq_r, eq_l = eq // 2, eq - (eq // 2)

    return (character * eq_l) + " " + text + " " + (character * eq_r)
