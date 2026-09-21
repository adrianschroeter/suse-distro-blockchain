# SPDX-License-Identifier: GPL-3.0-or-later
"""Unit tests for the distro_tool argument validation."""

import unittest

from suse_distro_blockchain import distro_tool

DIGEST = "6a8998a33df6164d29d545c1bb8d9dd5a3595206d993b1a43c54de9aa33d8feb"


class ValidateVerificationTest(unittest.TestCase):
    def test_bare_hex_is_accepted(self):
        self.assertEqual(distro_tool.validate_verification("abc123"), "abc123")

    def test_oci_digest_is_lowercased(self):
        self.assertEqual(
            distro_tool.validate_verification("sha256:" + DIGEST.upper()),
            "sha256:" + DIGEST,
        )

    def test_non_hex_is_rejected(self):
        with self.assertRaises(SystemExit):
            distro_tool.validate_verification("sha256:" + DIGEST + "!")


class ValidateOciVerificationTest(unittest.TestCase):
    def test_bare_sha256_gets_prefix(self):
        self.assertEqual(distro_tool.validate_oci_verification(DIGEST), "sha256:" + DIGEST)

    def test_prefixed_digest_is_canonicalized(self):
        self.assertEqual(
            distro_tool.validate_oci_verification("sha256:" + DIGEST.upper()),
            "sha256:" + DIGEST,
        )

    def test_short_digest_is_rejected(self):
        with self.assertRaises(SystemExit):
            distro_tool.validate_oci_verification("deadbeef")

    def test_other_algorithm_is_rejected(self):
        with self.assertRaises(SystemExit):
            distro_tool.validate_oci_verification("md5:" + DIGEST)


if __name__ == "__main__":
    unittest.main()
