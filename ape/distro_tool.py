#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Development shim: the real implementation lives in the installable package
# src/suse_distro_blockchain/distro_tool.py (console script `distro_tool`).
# Kept so `python3 ape/distro_tool.py ...` keeps working in the source tree.

import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "src")
)

from suse_distro_blockchain.distro_tool import main

if __name__ == "__main__":
    sys.exit(main())
