# SPDX-License-Identifier: GPL-3.0-or-later
"""Unit tests for the shared repository metadata verification."""

import contextlib
import hashlib
import io
import os
import tempfile
import unittest
from unittest import mock

from web3 import Web3

from suse_distro_blockchain import metadata
from suse_distro_blockchain import oci_check
from suse_distro_blockchain import repoverify

try:
    from eth_tester import EthereumTester  # noqa: F401 - availability probe only
    _HAVE_TESTER = True
except ImportError:  # pragma: nocover - depends on the test environment
    _HAVE_TESTER = False

try:
    from suse_distro_blockchain.distro_contract import CONTRACT_BYTECODE as _CONTRACT_BYTECODE
except ImportError:  # pragma: nocover - contract is a build artifact
    _CONTRACT_BYTECODE = None
    _HAVE_TESTER = False


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

# the packaged config lives in the repository root, one level above tests/
SHIPPED_CONF = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            os.pardir, "suse-distro-check.conf")


class FakeFunction:
    def __init__(self, value, exc=None):
        self.value = value
        self.exc = exc
        self.calls = []

    def call(self, *args, **kwargs):
        self.calls.append(kwargs)
        if self.exc is not None:
            raise self.exc
        return self.value


class FakeContract:
    """Minimal stand-in for a web3 contract with the read-only views we use."""

    def __init__(self, build=(0, 0, 0), product=("", "", False), current="", exc=None):
        self._build = build
        self._product = product
        self._current = current
        self._exc = exc
        self.seen = []

    @property
    def functions(self):
        return self

    def get_product_build(self, verification):
        return self._record(FakeFunction(self._build, self._exc))

    def get_product(self, product_id):
        return self._record(FakeFunction(self._product, self._exc))

    def current_product_build(self, name, kind):
        return self._record(FakeFunction(self._current, self._exc))

    def _record(self, function):
        self.seen.append(function)
        return function


def endpoints(*contracts, block=4711):
    """The endpoint set connect_contracts() returns, without doing any RPC."""
    return metadata.ChainClients(
        clients=[(f"http://node{index}:8545", contract)
                 for index, contract in enumerate(contracts)],
        block=block,
        chain_id=560048,
        pin=len(contracts) > 1,
    )


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


def message_of(results, name):
    for result in results:
        if result.name == name:
            return result.message
    return ""


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
        path = SHIPPED_CONF
        conf = metadata.load_conf(path)
        policy = metadata.resolve_policy(conf, "")
        self.assertEqual(policy.issues, [])
        self.assertEqual(policy.level("unmanaged"), "allow")
        self.assertEqual(policy.level("registered"), metadata.REJECT)
        self.assertEqual(policy.level("critical_issues"), metadata.REJECT)
        self.assertEqual(policy.level("rpc_error"), metadata.REJECT)
        self.assertEqual(policy.level("consensus"), metadata.REJECT)
        self.assertEqual(policy.level("current_build"), metadata.WARN)
        self.assertEqual(policy.level("signed"), "ignore")
        self.assertEqual(policy.values["min_attestation"], "outstanding")

    def test_shipped_conf_has_valid_oci_defaults(self):
        path = SHIPPED_CONF
        conf = metadata.load_conf(path)
        policy = metadata.resolve_oci_policy(conf, "registry.example/opensuse/leap")
        self.assertFalse(policy.managed)  # only commented examples ship
        self.assertEqual(policy.issues, [])
        self.assertEqual(policy.level("unmanaged"), "allow")

    def test_shipped_conf_cross_checks_the_hoodi_endpoints(self):
        conf = metadata.load_conf(SHIPPED_CONF)
        urls = metadata.provider_urls(conf["hoodi"])
        self.assertGreaterEqual(len(urls), 2)
        self.assertEqual(conf["hoodi"]["chainid"], "560048")
        for url in urls:
            self.assertTrue(url.startswith("https://"), url)


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

    def test_rejected_attestation_fails_by_default(self):
        contract = registered_contract(attestation=metadata.ATTESTATION_REJECTED)
        results = metadata.verify_build(VERIFICATION, contract, make_policy())
        self.assertEqual(level_of(results, "verification"), metadata.REJECT)

    def test_rejected_attestation_warns_when_check_is_off(self):
        contract = registered_contract(attestation=metadata.ATTESTATION_REJECTED)
        results = metadata.verify_build(VERIFICATION, contract, make_policy(min_attestation="off"))
        self.assertEqual(level_of(results, "verification"), metadata.WARN)
        self.assertEqual(metadata.worst(results), metadata.WARN)

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

    def _managed_conf(self, defaults=""):
        return self._conf(
            f"[defaults]\n{defaults}"
            "[hoodi]\nhttp_provider=http://localhost:8545\nchainid=560048\n"
            "contract=0x02724c2d1e76Ea3A24247A48F959532cDb152Fb6\n"
            "[repo:repo-oss]\nnetwork=hoodi\n"
        )

    def _run(self, conf, *extra):
        out = io.StringIO()
        with mock.patch.object(metadata, "connect_provider", return_value=object()), \
             mock.patch.object(metadata, "contract_at", return_value=registered_contract()), \
             mock.patch("sys.stdout", new=out), mock.patch("sys.stderr", new=io.StringIO()):
            rc = repoverify.main(["--ralias", "repo-oss", "--file", self._repomd(),
                                  "--conf", conf, *extra])
        return rc, out.getvalue()

    def test_accepted_repo_always_reports_the_build_state(self):
        rc, report = self._run(self._managed_conf())
        self.assertEqual(rc, 0)
        for name in metadata.BUILD_STATE_CHECKS:
            self.assertIn(f"] {name}: ", report)
        # the product, the current build, the security level and the attestation
        self.assertIn("'example-1'", report)
        self.assertIn("repository is the current build", report)
        self.assertIn("no known critical security issues", report)
        self.assertIn("reproducibility verification is approved", report)
        # registration and kind are only reported when they fail
        self.assertNotIn("] registration: ", report)
        self.assertNotIn("] kind: ", report)

    def test_repo_build_state_report_flags_a_stale_build_and_known_issues(self):
        conf = self._managed_conf("critical_issues=warn\ncurrent_build=warn\n")
        contract = FakeContract(
            build=(1, metadata.BUILD_KINDS["rpmmd"], metadata.ATTESTATION_APPROVED),
            product=("example-1", GIT_REF, True),
            current="stale",
        )
        out = io.StringIO()
        with mock.patch.object(metadata, "connect_provider", return_value=object()), \
             mock.patch.object(metadata, "contract_at", return_value=contract), \
             mock.patch("sys.stdout", new=out), mock.patch("sys.stderr", new=io.StringIO()):
            rc = repoverify.main(["--ralias", "repo-oss", "--file", self._repomd(), "--conf", conf])
        self.assertEqual(rc, 0)
        report = out.getvalue()
        self.assertIn("a different build is current", report)
        self.assertIn("known critical security issues", report)

    def test_repo_endpoint_cross_check_stays_behind_verbose(self):
        conf = self._managed_conf()
        cross_checked = endpoints(registered_contract(), registered_contract())
        out = io.StringIO()
        with mock.patch.object(metadata, "connect_contracts", return_value=cross_checked), \
             mock.patch("sys.stdout", new=out), mock.patch("sys.stderr", new=io.StringIO()):
            repoverify.main(["--ralias", "repo-oss", "--file", self._repomd(), "--conf", conf])
        self.assertNotIn("consensus", out.getvalue())
        out = io.StringIO()
        with mock.patch.object(metadata, "connect_contracts", return_value=cross_checked), \
             mock.patch("sys.stdout", new=out), mock.patch("sys.stderr", new=io.StringIO()):
            repoverify.main(["-v", "--ralias", "repo-oss", "--file", self._repomd(), "--conf", conf])
        self.assertIn("consensus", out.getvalue())
        self.assertIn("block 4711", out.getvalue())


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
        with mock.patch.object(metadata, "connect_contracts", return_value=endpoints(contract)):
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
        with mock.patch.object(metadata, "connect_contracts", return_value=endpoints(contract)):
            _digest, results = metadata.verify_oci(
                "registry.example/img:tag", make_policy(), self._conf(),
                raw_reader=lambda r: self.RAW)
        self.assertEqual(level_of(results, "kind"), metadata.WARN)

    def test_unregistered_image_rejects(self):
        with mock.patch.object(metadata, "connect_contracts", return_value=endpoints(FakeContract(build=(0, 0, 0)))):
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
             mock.patch.object(metadata, "connect_contracts", return_value=endpoints(FakeContract(build=(0, 0, 0)))):
            rc = oci_check.main(["--conf", self._managed_conf(), "registry.example/img:tag"])
        self.assertEqual(rc, 1)

    def test_managed_registered_image_prints_pinned_ref(self):
        digest = "sha256:" + hashlib.sha256(b"raw").hexdigest()
        contract = FakeContract(
            build=(1, metadata.BUILD_KINDS["oci_container"], metadata.ATTESTATION_APPROVED),
            product=("opensuse-leap", GIT_REF, False),
            current=digest,
        )
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(metadata, "_skopeo_inspect_raw", return_value=b"raw"), \
             mock.patch.object(metadata, "connect_contracts", return_value=endpoints(contract)), \
             mock.patch("sys.stdout", new=out), mock.patch("sys.stderr", new=err):
            rc = oci_check.main(["--print-ref", "--conf", self._managed_conf(),
                                 "registry.example/img:tag"])
        self.assertEqual(rc, 0)
        self.assertIn(f"registry.example/img@{digest}", out.getvalue())
        # the build state is reported on stderr, stdout stays machine readable
        self.assertIn("] current_build: ", err.getvalue())
        self.assertIn("] product: ", err.getvalue())
        self.assertNotIn("] registration: ", err.getvalue())
        self.assertNotIn("] kind: ", err.getvalue())

    def test_accepted_image_always_reports_the_build_state(self):
        digest = "sha256:" + hashlib.sha256(b"raw").hexdigest()
        contract = FakeContract(
            build=(1, metadata.BUILD_KINDS["oci_container"], metadata.ATTESTATION_APPROVED),
            product=("opensuse-leap", GIT_REF, False),
            current=digest,
        )
        out = io.StringIO()
        with mock.patch.object(metadata, "_skopeo_inspect_raw", return_value=b"raw"), \
             mock.patch.object(metadata, "connect_contracts", return_value=endpoints(contract)), \
             mock.patch("sys.stdout", new=out):
            rc = oci_check.main(["--conf", self._managed_conf(), "registry.example/img:tag"])
        self.assertEqual(rc, 0)
        report = out.getvalue()
        for name in metadata.BUILD_STATE_CHECKS:
            self.assertIn(f"] {name}: ", report)
        # the product, the current build, the security level and the attestation
        self.assertIn("'opensuse-leap'", report)
        self.assertIn("repository is the current build", report)
        self.assertIn("no known critical security issues", report)
        self.assertIn("reproducibility verification is approved", report)
        # registration and kind are only reported when they fail
        self.assertNotIn("] registration: ", report)
        self.assertNotIn("] kind: ", report)

    def test_build_state_report_flags_a_stale_image_and_known_issues(self):
        digest = "sha256:" + hashlib.sha256(b"raw").hexdigest()
        contract = FakeContract(
            build=(1, metadata.BUILD_KINDS["oci_container"], metadata.ATTESTATION_APPROVED),
            product=("opensuse-leap", GIT_REF, True),
            current="sha256:" + "1" * 64,
        )
        conf = self._conf(
            "[defaults]\ncritical_issues=warn\ncurrent_build=warn\n"
            "[oci:registry.example]\nnetwork=hoodi\n"
            "[hoodi]\nhttp_provider=http://localhost:8545\nchainid=560048\ncontract=0xabc\n"
        )
        out = io.StringIO()
        with mock.patch.object(metadata, "_skopeo_inspect_raw", return_value=b"raw"), \
             mock.patch.object(metadata, "connect_contracts", return_value=endpoints(contract)), \
             mock.patch("sys.stdout", new=out):
            rc = oci_check.main(["--conf", conf, "registry.example/img:tag"])
        self.assertEqual(rc, 0)
        report = out.getvalue()
        self.assertIn("a different build is current", report)
        self.assertIn("known critical security issues", report)
        self.assertNotIn(digest, report)

    def test_endpoint_cross_check_stays_behind_verbose(self):
        contract = FakeContract(
            build=(1, metadata.BUILD_KINDS["oci_container"], metadata.ATTESTATION_APPROVED),
            product=("opensuse-leap", GIT_REF, False),
            current="sha256:" + hashlib.sha256(b"raw").hexdigest(),
        )
        cross_checked = endpoints(contract, contract)
        out = io.StringIO()
        with mock.patch.object(metadata, "_skopeo_inspect_raw", return_value=b"raw"), \
             mock.patch.object(metadata, "connect_contracts", return_value=cross_checked), \
             mock.patch("sys.stdout", new=out):
            oci_check.main(["--conf", self._managed_conf(), "registry.example/img:tag"])
        self.assertNotIn("consensus", out.getvalue())
        out = io.StringIO()
        with mock.patch.object(metadata, "_skopeo_inspect_raw", return_value=b"raw"), \
             mock.patch.object(metadata, "connect_contracts", return_value=cross_checked), \
             mock.patch("sys.stdout", new=out), mock.patch("sys.stderr", new=io.StringIO()):
            oci_check.main(["-v", "--conf", self._managed_conf(), "registry.example/img:tag"])
        self.assertIn("consensus", out.getvalue())
        self.assertIn("block 4711", out.getvalue())

    def test_print_ref_keeps_stdout_clean_and_warns_on_stderr(self):
        digest = "sha256:" + hashlib.sha256(b"raw").hexdigest()
        contract = FakeContract(
            build=(1, metadata.BUILD_KINDS["oci_container"], metadata.ATTESTATION_OUTSTANDING),
            product=("opensuse-leap", GIT_REF, False),
            current=digest,
        )
        conf = self._conf(
            "[defaults]\nmin_attestation=approved\n"
            "[oci:registry.example]\nnetwork=hoodi\n"
            "[hoodi]\nhttp_provider=http://localhost:8545\nchainid=560048\ncontract=0xabc\n"
        )
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(metadata, "_skopeo_inspect_raw", return_value=b"raw"), \
             mock.patch.object(metadata, "connect_contracts", return_value=endpoints(contract)), \
             mock.patch("sys.stdout", new=out), mock.patch("sys.stderr", new=err):
            rc = oci_check.main(["--print-ref", "--conf", conf, "registry.example/img:tag"])
        self.assertEqual(rc, 0)
        self.assertEqual(out.getvalue().strip(), f"registry.example/img@{digest}")
        self.assertIn("verification", err.getvalue())
        self.assertIn("warn", err.getvalue())


class FakeEth:
    def __init__(self, chain_id, block_number):
        self.chain_id = chain_id
        self.block_number = block_number


class FakeW3:
    def __init__(self, chain_id=560048, block_number=4711):
        self.eth = FakeEth(chain_id, block_number)


@contextlib.contextmanager
def fake_endpoints(providers):
    """Patch connect_provider/contract_at; maps URL to FakeW3 or an exception."""
    contracts = {}

    def fake_connect(url, chain_id=None, timeout=10.0):
        entry = providers[url]
        if isinstance(entry, Exception):
            raise entry
        return entry

    def fake_contract_at(w3, address):
        return contracts.setdefault(id(w3), FakeContract())

    with mock.patch.object(metadata, "connect_provider", side_effect=fake_connect), \
         mock.patch.object(metadata, "contract_at", side_effect=fake_contract_at):
        yield contracts


class ProviderUrlsTest(unittest.TestCase):
    def test_single_url(self):
        self.assertEqual(metadata.provider_urls({"http_provider": "http://a:8545"}), ["http://a:8545"])

    def test_comma_separated_list(self):
        net = {"http_provider": "http://a:8545,http://b:8545,http://c:8545"}
        self.assertEqual(metadata.provider_urls(net),
                         ["http://a:8545", "http://b:8545", "http://c:8545"])

    def test_whitespace_and_newlines_are_separators(self):
        net = {"http_provider": "http://a:8545,\n  http://b:8545 \n"}
        self.assertEqual(metadata.provider_urls(net), ["http://a:8545", "http://b:8545"])

    def test_empty_entries_and_duplicates_are_dropped(self):
        net = {"http_provider": ",http://a:8545,,http://a:8545,"}
        self.assertEqual(metadata.provider_urls(net), ["http://a:8545"])

    def test_missing_or_empty_value(self):
        self.assertEqual(metadata.provider_urls({}), [])
        self.assertEqual(metadata.provider_urls({"http_provider": "  "}), [])


class ConnectContractsTest(unittest.TestCase):
    NET = {
        "network": "hoodi",
        "http_provider": "",
        "chainid": "560048",
        "contract": "0x02724c2d1e76Ea3A24247A48F959532cDb152Fb6",
    }

    def net(self, *urls, **overrides):
        return dict(self.NET, http_provider=",".join(urls), **overrides)

    def test_every_endpoint_is_connected_in_order(self):
        providers = {
            "http://a": FakeW3(block_number=100),
            "http://b": FakeW3(block_number=98),
            "http://c": FakeW3(block_number=99),
        }
        with fake_endpoints(providers) as contracts:
            clients = metadata.connect_contracts(self.net("http://a", "http://b", "http://c"))
        self.assertEqual([url for url, _contract in clients.clients],
                         ["http://a", "http://b", "http://c"])
        self.assertEqual(clients.errors, [])
        self.assertEqual(len(contracts), 3)
        self.assertTrue(clients.pin)
        self.assertTrue(clients.cross_checked)

    def test_reads_are_pinned_to_the_lowest_block(self):
        providers = {"http://a": FakeW3(block_number=100), "http://b": FakeW3(block_number=98)}
        with fake_endpoints(providers) as contracts:
            clients = metadata.connect_contracts(self.net("http://a", "http://b"))
        self.assertEqual(clients.block, 98)
        clients.call("get_product", 1)
        for contract in contracts.values():
            self.assertEqual(contract.seen[0].calls, [{"block_identifier": 98}])

    def test_unreachable_endpoint_is_reported_not_raised(self):
        providers = {"http://a": FakeW3(), "http://b": ConnectionError("connection refused")}
        with fake_endpoints(providers):
            clients = metadata.connect_contracts(self.net("http://a", "http://b"))
        self.assertEqual(len(clients.clients), 1)
        self.assertEqual(clients.errors[0][0], "http://b")
        self.assertIn("connection refused", str(clients.errors[0][1]))
        self.assertIn("1 of 2 RPC endpoints failed", clients.failure_message())

    def test_endpoint_with_another_chain_is_dropped(self):
        providers = {"http://a": FakeW3(chain_id=560048), "http://b": FakeW3(chain_id=1)}
        with fake_endpoints(providers):
            clients = metadata.connect_contracts(self.net("http://a", "http://b", chainid=""))
        self.assertEqual(len(clients.clients), 1)
        self.assertIn("chain id 1 differs from 560048", clients.failure_message())

    def test_single_endpoint_is_not_pinned(self):
        with fake_endpoints({"http://a": FakeW3(block_number=100)}) as contracts:
            clients = metadata.connect_contracts(self.net("http://a"))
        self.assertFalse(clients.pin)
        self.assertFalse(clients.cross_checked)
        clients.call("get_product", 1)
        for contract in contracts.values():
            self.assertEqual(contract.seen[0].calls, [{}])

    def test_all_endpoints_down(self):
        providers = {"http://a": ConnectionError("x"), "http://b": ConnectionError("y")}
        with fake_endpoints(providers):
            clients = metadata.connect_contracts(self.net("http://a", "http://b"))
        self.assertEqual(clients.clients, [])
        with self.assertRaises(metadata.ProviderUnavailable):
            clients.call("get_product", 1)
        with self.assertRaises(metadata.ProviderUnavailable):
            clients.single  # noqa: B018 - the property raises on purpose

    def test_no_provider_configured(self):
        with self.assertRaises(ValueError):
            metadata.connect_contracts(dict(self.NET))

    def test_invalid_address_fails_before_any_rpc_call(self):
        connect = mock.Mock()
        with mock.patch.object(metadata, "connect_provider", connect):
            with self.assertRaises(ValueError):
                metadata.connect_contracts(self.net("http://a", contract="nonsense"))
        connect.assert_not_called()


class ChainClientsTest(unittest.TestCase):
    def test_agreeing_answers_are_returned(self):
        clients = endpoints(registered_contract(), registered_contract())
        self.assertEqual(clients.call("get_product_build", VERIFICATION), (1, 1, 2))
        self.assertIn("2 RPC endpoints", clients.consensus_message())

    def test_disagreeing_answers_raise(self):
        second = registered_contract(current="somethingelse")
        clients = endpoints(registered_contract(), second)
        with self.assertRaises(metadata.ProviderDisagreement) as caught:
            clients.call("current_product_build", "example-1", 1)
        self.assertIn("disagree", str(caught.exception))
        self.assertIn("somethingelse", str(caught.exception))

    def test_endpoint_failing_a_call_raises_unavailable(self):
        clients = endpoints(registered_contract(), FakeContract(exc=RuntimeError("node gone")))
        with self.assertRaises(metadata.ProviderUnavailable) as caught:
            clients.call("get_product_build", VERIFICATION)
        self.assertIn("node gone", str(caught.exception))

    def test_clients_of_wraps_a_single_contract(self):
        contract = registered_contract()
        clients = metadata.clients_of(contract)
        self.assertIs(clients.single, contract)
        self.assertFalse(clients.cross_checked)
        self.assertIs(metadata.clients_of(clients), clients)

    def test_empty_set_reports_no_endpoint(self):
        with self.assertRaises(metadata.ProviderUnavailable):
            metadata.ChainClients().call("get_product", 1)


class CrossCheckTest(unittest.TestCase):
    def test_agreeing_endpoints_report_consensus(self):
        clients = endpoints(registered_contract(), registered_contract())
        results = metadata.verify_build(VERIFICATION, clients, make_policy())
        self.assertEqual(metadata.worst(results), metadata.OK)
        self.assertEqual(level_of(results, "consensus"), metadata.OK)
        self.assertIn("2 RPC endpoints", message_of(results, "consensus"))
        self.assertIn("block 4711", message_of(results, "consensus"))

    def test_disagreeing_endpoints_reject(self):
        clients = endpoints(registered_contract(), registered_contract(current="other"))
        results = metadata.verify_build(VERIFICATION, clients, make_policy())
        self.assertEqual(level_of(results, "consensus"), metadata.REJECT)
        self.assertEqual(metadata.worst(results), metadata.REJECT)
        self.assertIsNone(level_of(results, "current_build"))

    def test_disagreement_level_is_configurable(self):
        clients = endpoints(registered_contract(), registered_contract(current="other"))
        results = metadata.verify_build(VERIFICATION, clients, make_policy(consensus="warn"))
        self.assertEqual(level_of(results, "consensus"), metadata.WARN)

    def test_consensus_check_can_be_ignored(self):
        clients = endpoints(registered_contract(), registered_contract(current="other"))
        results = metadata.verify_build(VERIFICATION, clients, make_policy(consensus="ignore"))
        self.assertEqual(level_of(results, "consensus"), metadata.OK)
        self.assertIn("ignored", message_of(results, "consensus"))

    def test_unreachable_endpoint_fails_even_with_a_healthy_one(self):
        clients = metadata.ChainClients(
            clients=[("http://a", registered_contract())],
            errors=[("http://b", ConnectionError("down"))],
            block=4711, chain_id=560048, pin=True)
        results = metadata.verify_build(VERIFICATION, clients, make_policy())
        self.assertEqual(level_of(results, "rpc_error"), metadata.REJECT)
        self.assertIn("down", message_of(results, "rpc_error"))
        self.assertIsNone(level_of(results, "registration"))

    def test_unreachable_endpoint_can_be_ignored(self):
        clients = metadata.ChainClients(
            clients=[("http://a", registered_contract())],
            errors=[("http://b", ConnectionError("down"))],
            block=4711, chain_id=560048, pin=True)
        results = metadata.verify_build(VERIFICATION, clients, make_policy(rpc_error="ignore"))
        self.assertEqual(level_of(results, "rpc_error"), metadata.OK)
        self.assertIsNone(level_of(results, "registration"))

    def test_endpoint_failing_mid_check_is_an_rpc_error(self):
        clients = endpoints(registered_contract(), FakeContract(exc=RuntimeError("node gone")))
        results = metadata.verify_build(VERIFICATION, clients, make_policy())
        self.assertEqual(level_of(results, "rpc_error"), metadata.REJECT)
        self.assertIn("node gone", message_of(results, "rpc_error"))

    def test_single_contract_has_no_consensus_check(self):
        results = metadata.verify_build(VERIFICATION, registered_contract(), make_policy())
        self.assertIsNone(level_of(results, "consensus"))
        self.assertEqual(metadata.worst(results), metadata.OK)


@unittest.skipUnless(_HAVE_TESTER, "eth_tester is not available")
class RealChainCrossCheckTest(unittest.TestCase):
    """Cross-checking against a real web3 provider, not a fake contract."""

    def test_two_clients_of_one_chain_agree_at_a_pinned_block(self):
        from eth_account import Account
        from eth_tester import EthereumTester
        from web3.providers.eth_tester import EthereumTesterProvider

        tester = EthereumTester()
        w3a = Web3(EthereumTesterProvider(tester))
        w3b = Web3(EthereumTesterProvider(tester))
        # the pre-funded first account of eth-tester, a well-known public test key
        account = Account.from_key("0x" + "00" * 31 + "01")
        self.assertEqual(account.address, tester.get_accounts()[0])
        deploy = {
            "from": account.address,
            "data": _CONTRACT_BYTECODE,
            "gas": 6_000_000,
            "gasPrice": w3a.eth.gas_price,
            "nonce": w3a.eth.get_transaction_count(account.address),
            "chainId": w3a.eth.chain_id,
        }
        signed = Account.sign_transaction(deploy, account.key)
        receipt = w3a.eth.wait_for_transaction_receipt(
            w3a.eth.send_raw_transaction(signed.raw_transaction))
        address = receipt["contractAddress"]
        tester.mine_blocks(2)
        block = w3a.eth.block_number
        first = metadata.contract_at(w3a, address)
        second = metadata.contract_at(w3b, address)
        clients = metadata.ChainClients(
            clients=[("a", first), ("b", second)], block=block,
            chain_id=w3a.eth.chain_id, pin=True)

        self.assertEqual(clients.call("get_product_counter"), 0)
        self.assertEqual(clients.call("current_product_build", "nope", 1), "")
        self.assertEqual(clients.call("get_product_counter"),
                         first.functions.get_product_counter().call(block_identifier=block))
        self.assertIn("2 RPC endpoints", clients.consensus_message())


if __name__ == "__main__":
    unittest.main()
