# SPDX-License-Identifier: GPL-3.0-or-later
"""Unit tests for the shared repository metadata verification."""

import hashlib
import io
import os
import tempfile
import unittest
from unittest import mock

from suse_distro_blockchain import metadata
from suse_distro_blockchain import oci_check
from suse_distro_blockchain import repoverify


REPOMD = """<?xml version="1.0" encoding="UTF-8"?>
<repomd xmlns="http://linux.duke.edu/metadata/repo">
  <data type="filelists">
    <checksum type="sha256">deadbeef</checksum>
  </data>
  <data type="primary">
    <checksum type="sha512">abc123</checksum>
  </data>
</repomd>
"""

VERIFICATION = "abc123"
GIT_REF = "8a645f5782b507202c75ee7fbeaf7bb21d34dd5c2eda4118bb76a31a39226e30"


class FakeFunction:
    def __init__(self, value):
        self.value = value

    def call(self):
        return self.value


class FakeContract:
    """Minimal stand-in for a web3 contract with the read-only views we use."""

    def __init__(self, build=(0, 0, 0), product=("", "", False), current=""):
        self._build = build
        self._product = product
        self._current = current

    @property
    def functions(self):
        return self

    def get_product_build(self, verification):
        return FakeFunction(self._build)

    def get_product(self, product_id):
        return FakeFunction(self._product)

    def current_product_build(self, name, kind):
        return FakeFunction(self._current)


def make_policy(**overrides):
    values = dict(metadata.DEFAULT_POLICY)
    values["signed"] = "ignore"  # environment dependent; covered explicitly below
    values.update(overrides)
    return metadata.Policy("test", values, managed=True)


def registered_contract(attestation=metadata.ATTESTATION_APPROVED, critical=False,
                        kind=metadata.BUILD_KINDS["rpmmd"], current=VERIFICATION):
    return FakeContract(
        build=(1, kind, attestation),
        product=("example-1", GIT_REF, critical),
        current=current,
    )


def level_of(results, name):
    for result in results:
        if result.name == name:
            return result.level
    return None


class ReadPrimaryChecksumTest(unittest.TestCase):
    def _write(self, text):
        fd, path = tempfile.mkstemp(suffix=".xml")
        with os.fdopen(fd, "w") as handle:
            handle.write(text)
        self.addCleanup(os.unlink, path)
        return path

    def test_picks_primary_not_filelists(self):
        ctype, value = metadata.read_primary_checksum(self._write(REPOMD))
        self.assertEqual((ctype, value), ("sha512", "abc123"))

    def test_missing_primary_raises(self):
        with self.assertRaises(ValueError):
            metadata.read_primary_checksum(self._write("<repomd/>"))

    def test_oversized_checksum_raises(self):
        text = "<repomd><data type='primary'><checksum type='sha512'>%s</checksum></data></repomd>" % ("a" * 129)
        with self.assertRaises(ValueError):
            metadata.read_primary_checksum(self._write(text))


class PolicyTest(unittest.TestCase):
    def test_defaults_applied(self):
        conf = {"defaults": {"current_build": "reject"}}
        policy = metadata.resolve_policy(conf, "repo-oss")
        self.assertFalse(policy.managed)
        self.assertEqual(policy.level("current_build"), "reject")
        self.assertEqual(policy.level("registered"), metadata.REJECT)
        self.assertEqual(policy.level("kind"), metadata.WARN)

    def test_repo_section_overrides_defaults_and_sets_managed(self):
        conf = {
            "defaults": {"registered": "warn"},
            "repo:repo-oss": {"registered": "reject", "min_attestation": "approved", "network": "hoodi"},
        }
        policy = metadata.resolve_policy(conf, "repo-oss")
        self.assertTrue(policy.managed)
        self.assertEqual(policy.level("registered"), "reject")
        self.assertEqual(policy.values["min_attestation"], "approved")
        self.assertEqual(policy.values["network"], "hoodi")

    def test_invalid_value_keeps_default_and_reports_issue(self):
        conf = {"repo:repo-oss": {"current_build": "explode"}}
        policy = metadata.resolve_policy(conf, "repo-oss")
        self.assertEqual(policy.level("current_build"), metadata.WARN)
        self.assertEqual(len(policy.issues), 1)

    def test_alias_lookup_is_case_insensitive(self):
        conf = {"repo:Repo-OSS": {"kind": "reject"}}
        policy = metadata.resolve_policy(conf, "repo-oss")
        self.assertTrue(policy.managed)

    def test_resolve_network_uses_main(self):
        conf = {
            "main": {"network": "hoodi"},
            "hoodi": {"http_provider": "http://localhost:8545", "chainid": "560048", "contract": "0xabc"},
        }
        net = metadata.resolve_network(conf, make_policy())
        self.assertEqual(net["network"], "hoodi")
        self.assertEqual(net["http_provider"], "http://localhost:8545")


class ShippedConfTest(unittest.TestCase):
    """The packaged config must parse without issues and carry sane defaults."""

    def test_shipped_defaults_are_valid(self):
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "suse-distro-check.conf")
        conf = metadata.load_conf(path)
        policy = metadata.resolve_policy(conf, "")
        self.assertEqual(policy.issues, [])
        self.assertEqual(policy.level("unmanaged"), "allow")
        self.assertEqual(policy.level("registered"), metadata.REJECT)
        self.assertEqual(policy.level("critical_issues"), metadata.REJECT)
        self.assertEqual(policy.level("rpc_error"), metadata.REJECT)
        self.assertEqual(policy.level("current_build"), metadata.WARN)
        self.assertEqual(policy.level("signed"), "ignore")
        self.assertEqual(policy.values["min_attestation"], "outstanding")

    def test_shipped_conf_has_valid_oci_defaults(self):
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "suse-distro-check.conf")
        conf = metadata.load_conf(path)
        policy = metadata.resolve_oci_policy(conf, "registry.example/opensuse/leap")
        self.assertFalse(policy.managed)  # only commented examples ship
        self.assertEqual(policy.issues, [])
        self.assertEqual(policy.level("unmanaged"), "allow")


class VerifyBuildTest(unittest.TestCase):
    def test_approved_registered_build_passes(self):
        results = metadata.verify_build(VERIFICATION, registered_contract(), make_policy())
        self.assertEqual(metadata.worst(results), metadata.OK)
        self.assertEqual(level_of(results, "registration"), metadata.OK)
        self.assertEqual(level_of(results, "verification"), metadata.OK)

    def test_unregistered_is_reject_by_default(self):
        contract = FakeContract(build=(0, 0, 0))
        results = metadata.verify_build(VERIFICATION, contract, make_policy())
        self.assertEqual(metadata.worst(results), metadata.REJECT)
        self.assertEqual(level_of(results, "registration"), metadata.REJECT)

    def test_critical_issues_are_reject_by_default(self):
        contract = registered_contract(critical=True)
        results = metadata.verify_build(VERIFICATION, contract, make_policy())
        self.assertEqual(level_of(results, "critical_issues"), metadata.REJECT)

    def test_rejected_attestation_always_fails(self):
        contract = registered_contract(attestation=metadata.ATTESTATION_REJECTED)
        results = metadata.verify_build(VERIFICATION, contract, make_policy())
        self.assertEqual(level_of(results, "verification"), metadata.REJECT)

    def test_outstanding_below_minimum_is_warn(self):
        contract = registered_contract(attestation=metadata.ATTESTATION_OUTSTANDING)
        results = metadata.verify_build(VERIFICATION, contract, make_policy(min_attestation="approved"))
        self.assertEqual(level_of(results, "verification"), metadata.WARN)

    def test_outstanding_accepted_by_default(self):
        contract = registered_contract(attestation=metadata.ATTESTATION_OUTSTANDING)
        results = metadata.verify_build(VERIFICATION, contract, make_policy())
        self.assertEqual(level_of(results, "verification"), metadata.OK)

    def test_current_mismatch_is_warn_by_default_and_configurable(self):
        contract = registered_contract(current="other")
        self.assertEqual(level_of(metadata.verify_build(VERIFICATION, contract, make_policy()), "current_build"),
                         metadata.WARN)
        self.assertEqual(level_of(metadata.verify_build(VERIFICATION, contract, make_policy(current_build="reject")),
                                  "current_build"), metadata.REJECT)

    def test_kind_mismatch_warns(self):
        contract = registered_contract(kind=metadata.BUILD_KINDS["product"])
        self.assertEqual(level_of(metadata.verify_build(VERIFICATION, contract, make_policy()), "kind"),
                         metadata.WARN)

    def test_ignore_disables_check(self):
        contract = registered_contract(critical=True)
        results = metadata.verify_build(VERIFICATION, contract, make_policy(critical_issues="ignore"))
        self.assertIsNone(level_of(results, "critical_issues"))

    def test_signed_check(self):
        contract = registered_contract()
        results = metadata.verify_build(VERIFICATION, contract, make_policy(signed="ignore"))
        self.assertIsNone(level_of(results, "signed"))
        results = metadata.verify_build(VERIFICATION, contract, make_policy(signed="warn"), fsig_path=None)
        self.assertEqual(level_of(results, "signed"), metadata.WARN)


class VerifyRepomdTest(unittest.TestCase):
    def _write(self, text):
        fd, path = tempfile.mkstemp(suffix=".xml")
        with os.fdopen(fd, "w") as handle:
            handle.write(text)
        self.addCleanup(os.unlink, path)
        return path

    def test_verifies_via_mocked_provider(self):
        conf = {"hoodi": {"http_provider": "http://localhost:8545", "chainid": "560048",
                          "contract": "0x02724c2d1e76Ea3A24247A48F959532cDb152Fb6"}}
        with mock.patch.object(metadata, "connect_provider", return_value=object()), \
             mock.patch.object(metadata, "contract_at", return_value=registered_contract()):
            results = metadata.verify_repomd(self._write(REPOMD), make_policy(network="hoodi"), conf)
        self.assertEqual(metadata.worst(results), metadata.OK)

    def test_rpc_error_is_reject_by_default(self):
        conf = {"hoodi": {"http_provider": "http://localhost:8545", "chainid": "560048", "contract": "0xabc"}}
        with mock.patch.object(metadata, "connect_provider", side_effect=ConnectionError("down")):
            results = metadata.verify_repomd(self._write(REPOMD), make_policy(network="hoodi"), conf)
        self.assertEqual(metadata.worst(results), metadata.REJECT)
        self.assertEqual(level_of(results, "rpc_error"), metadata.REJECT)

    def test_rpc_error_can_be_ignored(self):
        conf = {"hoodi": {"http_provider": "http://localhost:8545", "chainid": "560048", "contract": "0xabc"}}
        with mock.patch.object(metadata, "connect_provider", side_effect=ConnectionError("down")):
            results = metadata.verify_repomd(self._write(REPOMD), make_policy(network="hoodi", rpc_error="ignore"), conf)
        self.assertEqual(metadata.worst(results), metadata.OK)


class RepoverifyMainTest(unittest.TestCase):
    def _conf(self, text):
        fd, path = tempfile.mkstemp(suffix=".conf")
        with os.fdopen(fd, "w") as handle:
            handle.write(text)
        self.addCleanup(os.unlink, path)
        return path

    def _repomd(self):
        fd, path = tempfile.mkstemp(suffix=".xml")
        with os.fdopen(fd, "w") as handle:
            handle.write(REPOMD)
        self.addCleanup(os.unlink, path)
        return path

    def test_unmanaged_repo_is_allowed(self):
        conf = self._conf("[defaults]\nunmanaged = allow\n")
        rc = repoverify.main(["--ralias", "something-else", "--file", self._repomd(), "--conf", conf])
        self.assertEqual(rc, 0)

    def test_managed_repo_rejects_unregistered(self):
        conf = self._conf(
            "[defaults]\n"
            "[hoodi]\nhttp_provider=http://localhost:8545\nchainid=560048\ncontract=0xabc\n"
            "[repo:repo-oss]\nnetwork=hoodi\n"
        )
        with mock.patch.object(metadata, "connect_provider", return_value=object()), \
             mock.patch.object(metadata, "contract_at", return_value=FakeContract(build=(0, 0, 0))):
            rc = repoverify.main(["--ralias", "repo-oss", "--file", self._repomd(), "--conf", conf])
        self.assertEqual(rc, 1)

    def test_missing_master_index_is_skipped(self):
        conf = self._conf("[defaults]\n[repo:repo-oss]\nnetwork=hoodi\n")
        rc = repoverify.main(["--ralias", "repo-oss", "--file", "/nonexistent/repomd.xml", "--conf", conf])
        self.assertEqual(rc, 0)


class OciReferenceTest(unittest.TestCase):
    def test_scope_strips_tag_digest_and_transport(self):
        digest = "sha256:" + "0" * 64
        self.assertEqual(metadata.oci_scope("docker://registry.example/ns/img:1.0"),
                         "registry.example/ns/img")
        self.assertEqual(metadata.oci_scope(f"registry.example/ns/img@{digest}"),
                         "registry.example/ns/img")
        self.assertEqual(metadata.oci_scope("localhost:5000/ns/img"), "localhost:5000/ns/img")
        self.assertEqual(metadata.oci_scope("localhost:5000/ns/img:tag"), "localhost:5000/ns/img")
        self.assertEqual(metadata.oci_scope("alpine"), "alpine")

    def test_resolve_embedded_digest_is_returned_unchanged(self):
        digest = "sha256:" + "a" * 64
        ref, resolved = metadata.resolve_oci_digest(f"registry.example/img@{digest}")
        self.assertEqual(resolved, digest)
        self.assertEqual(ref, "registry.example/img")

    def test_resolve_hashes_raw_manifest(self):
        raw = b'{"schemaVersion":2}'
        ref, digest = metadata.resolve_oci_digest("registry.example/img:tag", raw_reader=lambda r: raw)
        self.assertEqual(ref, "registry.example/img:tag")
        self.assertEqual(digest, "sha256:" + hashlib.sha256(raw).hexdigest())

    def test_resolve_rejects_bad_digest_reference(self):
        with self.assertRaises(ValueError):
            metadata.resolve_oci_digest("registry.example/img@sha256:nothex")

    def test_missing_skopeo_is_reported(self):
        with mock.patch.object(metadata.subprocess, "run", side_effect=FileNotFoundError):
            with self.assertRaises(RuntimeError):
                metadata.resolve_oci_digest("registry.example/img:tag")


class OciPolicyTest(unittest.TestCase):
    def test_prefix_match_and_longest_wins(self):
        conf = {
            "defaults": {"registered": "warn"},
            "oci:registry.example": {"kind": "reject"},
            "oci:registry.example/ns": {"registered": "reject"},
        }
        policy = metadata.resolve_oci_policy(conf, "registry.example/ns/img")
        self.assertTrue(policy.managed)
        self.assertEqual(policy.level("registered"), "reject")  # more specific section
        self.assertEqual(policy.level("kind"), "reject")  # inherited from the parent prefix

    def test_unmanaged_without_section(self):
        policy = metadata.resolve_oci_policy({"defaults": {}}, "registry.example/ns/img")
        self.assertFalse(policy.managed)
        self.assertEqual(policy.level("unmanaged"), "allow")

    def test_scope_prefix_is_not_partial_component(self):
        conf = {"oci:registry.example/ns": {}}
        self.assertFalse(metadata.resolve_oci_policy(conf, "registry.example/other/img").managed)

    def test_invalid_value_reports_issue(self):
        conf = {"oci:registry.example": {"min_attestation": "maybe"}}
        policy = metadata.resolve_oci_policy(conf, "registry.example/img")
        self.assertEqual(len(policy.issues), 1)

    def test_section_lookup_is_case_insensitive(self):
        conf = {"oci:Registry.Example": {"kind": "reject"}}
        self.assertTrue(metadata.resolve_oci_policy(conf, "registry.example/img").managed)


class VerifyOciTest(unittest.TestCase):
    RAW = b'{"schemaVersion":2}'
    DIGEST = "sha256:" + hashlib.sha256(RAW).hexdigest()

    def _conf(self):
        return {"hoodi": {"http_provider": "http://localhost:8545", "chainid": "560048",
                          "contract": "0x02724c2d1e76Ea3A24247A48F959532cDb152Fb6"}}

    def test_registered_oci_image_passes(self):
        contract = FakeContract(
            build=(1, metadata.BUILD_KINDS["oci_container"], metadata.ATTESTATION_APPROVED),
            product=("opensuse-leap", GIT_REF, False),
            current=self.DIGEST,
        )
        with mock.patch.object(metadata, "connect_contract", return_value=contract):
            digest, results = metadata.verify_oci(
                "registry.example/img:tag", make_policy(), self._conf(),
                raw_reader=lambda r: self.RAW)
        self.assertEqual(digest, self.DIGEST)
        self.assertEqual(metadata.worst(results), metadata.OK)
        self.assertEqual(level_of(results, "kind"), metadata.OK)

    def test_wrong_kind_warns(self):
        contract = FakeContract(
            build=(1, metadata.BUILD_KINDS["rpmmd"], metadata.ATTESTATION_APPROVED),
            product=("opensuse-leap", GIT_REF, False),
            current=self.DIGEST,
        )
        with mock.patch.object(metadata, "connect_contract", return_value=contract):
            _digest, results = metadata.verify_oci(
                "registry.example/img:tag", make_policy(), self._conf(),
                raw_reader=lambda r: self.RAW)
        self.assertEqual(level_of(results, "kind"), metadata.WARN)

    def test_unregistered_image_rejects(self):
        with mock.patch.object(metadata, "connect_contract", return_value=FakeContract(build=(0, 0, 0))):
            _digest, results = metadata.verify_oci(
                "registry.example/img:tag", make_policy(), self._conf(),
                raw_reader=lambda r: self.RAW)
        self.assertEqual(metadata.worst(results), metadata.REJECT)
        self.assertEqual(level_of(results, "registration"), metadata.REJECT)

    def test_resolution_failure_rejects(self):
        def boom(_ref):
            raise RuntimeError("no skopeo")

        digest, results = metadata.verify_oci(
            "registry.example/img:tag", make_policy(), self._conf(), raw_reader=boom)
        self.assertEqual(digest, "")
        self.assertEqual(level_of(results, "reference"), metadata.REJECT)


class OciCheckMainTest(unittest.TestCase):
    def _conf(self, text):
        fd, path = tempfile.mkstemp(suffix=".conf")
        with os.fdopen(fd, "w") as handle:
            handle.write(text)
        self.addCleanup(os.unlink, path)
        return path

    def _managed_conf(self):
        return self._conf(
            "[defaults]\n"
            "[oci:registry.example]\nnetwork=hoodi\n"
            "[hoodi]\nhttp_provider=http://localhost:8545\nchainid=560048\ncontract=0xabc\n"
        )

    def test_unmanaged_scope_with_managed_only_returns_3(self):
        conf = self._conf("[defaults]\nunmanaged = allow\n")
        rc = oci_check.main(["--managed-only", "--conf", conf, "registry.example/img:tag"])
        self.assertEqual(rc, oci_check.UNMANAGED)

    def test_managed_unregistered_image_rejects(self):
        with mock.patch.object(metadata, "_skopeo_inspect_raw", return_value=b"raw"), \
             mock.patch.object(metadata, "connect_contract", return_value=FakeContract(build=(0, 0, 0))):
            rc = oci_check.main(["--conf", self._managed_conf(), "registry.example/img:tag"])
        self.assertEqual(rc, 1)

    def test_managed_registered_image_prints_pinned_ref(self):
        digest = "sha256:" + hashlib.sha256(b"raw").hexdigest()
        contract = FakeContract(
            build=(1, metadata.BUILD_KINDS["oci_container"], metadata.ATTESTATION_APPROVED),
            product=("opensuse-leap", GIT_REF, False),
            current=digest,
        )
        out = io.StringIO()
        with mock.patch.object(metadata, "_skopeo_inspect_raw", return_value=b"raw"), \
             mock.patch.object(metadata, "connect_contract", return_value=contract), \
             mock.patch("sys.stdout", new=out):
            rc = oci_check.main(["--print-ref", "--conf", self._managed_conf(),
                                 "registry.example/img:tag"])
        self.assertEqual(rc, 0)
        self.assertIn(f"registry.example/img@{digest}", out.getvalue())


if __name__ == "__main__":
    unittest.main()
