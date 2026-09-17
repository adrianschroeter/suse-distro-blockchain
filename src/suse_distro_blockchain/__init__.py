# SPDX-License-Identifier: GPL-3.0-or-later
"""openSUSE distro attestation tooling.

Installed console scripts:

* ``suse-distro-check`` - verify the installed repository state against the
  distro attestation contract (reads ``/etc/suse-distro-check.conf``).
* ``distro_tool`` - register / attest products and builds, and deploy the
  contract itself.
"""

__version__ = "0.0.2"
