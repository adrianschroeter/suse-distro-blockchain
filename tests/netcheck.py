# SPDX-License-Identifier: GPL-3.0-or-later
"""Shared test helper for tests that talk to a live network.

The RPM build runs the test suite without network access, so every test that
sends an RPC request is decorated with requires_network and is skipped when
SUSE_DISTRO_TEST_OFFLINE is set. Run the suite offline with:

    SUSE_DISTRO_TEST_OFFLINE=1 python3 -m unittest discover -s tests -t .

or, equivalently, "make test-offline".

Everything else in the suite runs fully offline: contracts are executed with
boa, and the chain is provided in-process by eth-tester.
"""

import os
import unittest

_TRUTHY = ("0", "no", "false", "off", "")


def _offline():
    return os.environ.get("SUSE_DISTRO_TEST_OFFLINE", "").strip().lower() not in _TRUTHY


OFFLINE = _offline()

requires_network = unittest.skipIf(
    OFFLINE, "SUSE_DISTRO_TEST_OFFLINE is set, skipping tests that need a network")
