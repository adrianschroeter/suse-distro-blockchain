# SPDX-License-Identifier: GPL-3.0-or-later
"""Unit tests for the spodman argument handling."""

import os
import tempfile
import unittest
from unittest import mock

from suse_distro_blockchain import spodman_shim


class FindSubcommandTest(unittest.TestCase):
    def test_plain(self):
        self.assertEqual(spodman_shim.find_subcommand(["run", "alpine"]), (0, "run"))

    def test_skips_global_value_options(self):
        self.assertEqual(
            spodman_shim.find_subcommand(["--log-level", "debug", "--root", "/x", "pull", "alpine"]),
            (4, "pull"))

    def test_skips_global_flag_with_equals(self):
        self.assertEqual(spodman_shim.find_subcommand(["--log-level=debug", "run", "alpine"]), (1, "run"))

    def test_no_subcommand(self):
        self.assertEqual(spodman_shim.find_subcommand(["--version"]), (None, None))


class FindImageIndexTest(unittest.TestCase):
    def test_run_with_flags(self):
        args = ["-it", "--rm", "alpine", "sh"]
        self.assertEqual(spodman_shim.find_image_index("run", args), 2)

    def test_run_with_value_options(self):
        args = ["-e", "FOO=bar", "-v", "/a:/b", "--name", "web", "alpine"]
        self.assertEqual(spodman_shim.find_image_index("run", args), 6)

    def test_pull_with_option_value(self):
        self.assertEqual(spodman_shim.find_image_index("pull", ["--arch", "amd64", "alpine"]), 2)

    def test_pull_with_equals_option(self):
        self.assertEqual(spodman_shim.find_image_index("pull", ["--arch=amd64", "alpine"]), 1)

    def test_short_option_with_attached_value(self):
        args = ["-w/app", "alpine"]
        self.assertEqual(spodman_shim.find_image_index("run", args), 1)

    def test_no_image(self):
        self.assertIsNone(spodman_shim.find_image_index("run", ["--rm"]))


class PullPolicyTest(unittest.TestCase):
    def test_equals_form(self):
        self.assertEqual(spodman_shim.pull_policy(["--pull=never", "alpine"]), "never")

    def test_separate_form(self):
        self.assertEqual(spodman_shim.pull_policy(["--pull", "never", "alpine"]), "never")

    def test_absent(self):
        self.assertIsNone(spodman_shim.pull_policy(["alpine"]))


class LocalReferenceTest(unittest.TestCase):
    def test_local_paths_and_ids(self):
        for ref in ("/tmp/img", "./img", "~user/img", "abcdef012345"):
            self.assertTrue(spodman_shim._is_local_reference(ref), ref)

    def test_local_transports(self):
        self.assertTrue(spodman_shim._is_local_reference("containers-storage:localhost/img"))

    def test_remote_references(self):
        for ref in ("alpine", "registry.example/ns/img:tag", "registry.example/img@sha256:" + "0" * 64):
            self.assertFalse(spodman_shim._is_local_reference(ref), ref)


class FindRealPodmanTest(unittest.TestCase):
    def test_skips_self_and_returns_other(self):
        with tempfile.TemporaryDirectory() as directory:
            self_path = os.path.join(directory, "shim")
            real = os.path.join(directory, "podman")
            open(self_path, "w").close()
            open(real, "w").close()
            with mock.patch.dict(os.environ, {"PATH": directory}, clear=False):
                os.environ.pop("PODMAN_REAL", None)
                self.assertEqual(spodman_shim.find_real_podman(self_path), real)

    def test_only_self_returns_none(self):
        with tempfile.TemporaryDirectory() as directory:
            self_path = os.path.join(directory, "podman")
            open(self_path, "w").close()
            with mock.patch.dict(os.environ, {"PATH": directory}, clear=False):
                os.environ.pop("PODMAN_REAL", None)
                os.environ["SUSE_DISTRO_SPODMAN_SELF"] = self_path
                self.assertIsNone(spodman_shim.find_real_podman(self_path))


class VerifyReferenceTest(unittest.TestCase):
    def test_success_returns_pinned_ref(self):
        proc = mock.Mock(returncode=0, stdout="[OK] registration: ok\nimg@sha256:" + "a" * 64 + "\n",
                         stderr="")
        with mock.patch.object(spodman_shim.subprocess, "run", return_value=proc):
            code, pinned = spodman_shim.verify_reference("img:tag")
        self.assertEqual(code, 0)
        self.assertEqual(pinned, "img@sha256:" + "a" * 64)

    def test_failure_propagates_exit_code(self):
        proc = mock.Mock(returncode=1, stdout="[ERROR] registration: nope\n", stderr="")
        with mock.patch.object(spodman_shim.subprocess, "run", return_value=proc):
            code, pinned = spodman_shim.verify_reference("img:tag")
        self.assertEqual(code, 1)
        self.assertIsNone(pinned)


if __name__ == "__main__":
    unittest.main()
