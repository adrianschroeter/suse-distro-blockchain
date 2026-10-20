# SPDX-License-Identifier: GPL-3.0-or-later
"""Unit tests for the distro_tool argument validation and SPDX SBOM parsing."""

import argparse
import contextlib
import io
import json
import tempfile
import unittest
from unittest import mock

from suse_distro_blockchain import distro_tool
from web3.exceptions import MethodUnavailable, TimeExhausted, Web3RPCError

DIGEST = "6a8998a33df6164d29d545c1bb8d9dd5a3595206d993b1a43c54de9aa33d8feb"
MD5 = "e36b8dcaaf3e3f0b676be182ffdb44dd"
OTHER_MD5 = "4d2f00d54aade3a65ca2ac15633d87e6"
PRIMARY = (
    "06661f5daffb168ec395509906cca2bb73d296dfd12166d2b35e92b9152107673"
    "6f134fdea08227dd073d179df4dd1fc4af70a8703938046d0c409bb9c07771a"
)
SECONDARY = (
    "1293447d449ae67d41fbadfdd7205813651010d098eefdef173d74e05c92e907d"
    "170a6126bb0d4b5a4dd87b6d5415ffbf50e828f81fa35b6ed3d259f7872b3d2"
)
DISTURL = (
    "obs://build.opensuse.org/openSUSE:Leap:16.1:Products/product/"
    f"{MD5}-000productcompose:leap_oss"
)
LEAP_ROOT = "Leap-16.1-aarch64-ppc64le-s390x-x86_64-Build50.2"


def spdx2(root_name=LEAP_ROOT, root_refs=None, packages=(), root_version=None):
    """SPDX 2.x document as emitted by obs-build generate_sbom."""
    root = {
        "name": root_name,
        "SPDXID": "SPDXRef-DOCUMENT-ROOT",
        "primaryPackagePurpose": "LIBRARY",
    }
    if root_refs is not None:
        root["externalRefs"] = root_refs
    if root_version is not None:
        root["versionInfo"] = root_version
    return {
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": root_name,
        "packages": [root] + list(packages),
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relatedSpdxElement": "SPDXRef-DOCUMENT-ROOT",
                "relationshipType": "DESCRIBES",
            }
        ],
    }


def spdx3(root_name=LEAP_ROOT, root_refs=None, packages=(), root_version=None):
    """SPDX 3.x document as emitted by obs-build generate_sbom."""
    root = {
        "spdxId": "http://open-build-service.org/spdx/x-specv3/root",
        "type": "software_Package",
        "name": root_name,
        "software_primaryPurpose": "library",
    }
    if root_refs is not None:
        root["externalRef"] = root_refs
    if root_version is not None:
        root["software_packageVersion"] = root_version
    graph = [
        {"spdxId": "http://open-build-service.org/spdx/x-specv3/document0", "type": "SpdxDocument"},
        root,
        {
            "spdxId": "http://open-build-service.org/spdx/x-specv3/rel0",
            "type": "Relationship",
            "relationshipType": "describes",
            "from": "http://open-build-service.org/spdx/x-specv3/document0",
            "to": [root["spdxId"]],
        },
    ]
    graph.extend(packages)
    return {"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld", "@graph": graph}


def repository_pkg(checksum, purpose="INSTALL"):
    return {
        "name": "repository",
        "SPDXID": "SPDXRef-Package-rpmmd-repository-" + checksum[:8],
        "versionInfo": checksum,
        "sourceInfo": "acquired package info from repomd.xml",
        "primaryPackagePurpose": purpose,
    }


def disturl_ref(v2=True, url=DISTURL):
    if v2:
        return {"referenceCategory": "OTHER", "referenceType": "obs-disturl", "referenceLocator": url}
    return {"type": "ExternalRef", "externalRefType": "other", "comment": "obs-disturl", "locator": [url]}


def vcs_ref(url, v2=True):
    if v2:
        return {"referenceCategory": "OTHER", "referenceType": "vcs", "referenceLocator": url}
    return {"type": "ExternalRef", "externalRefType": "vcs", "locator": [url]}


def rpm_pkg():
    """A regular rpm package, with refs that must never be used as anchor."""
    return {
        "name": "0ad",
        "SPDXID": "SPDXRef-Package-rpm-0ad-6352522dc070634d8f9f719850a298a4",
        "versionInfo": "0.27.0-bp161.1.11",
        "sourceInfo": "acquired package info from RPM DB",
        "externalRefs": [
            {
                "referenceCategory": "OTHER",
                "referenceType": "vcs",
                "referenceLocator": "https://src.opensuse.org/pool/0ad?trackingbranch=leap-16.1#" + DIGEST,
            },
            disturl_ref(url="obs://build.opensuse.org/openSUSE:Backports:SLE-16.1/standard/" + OTHER_MD5 + "-0ad"),
        ],
    }


def release_pkg():
    """The release package of the product, marking a product medium SBOM."""
    return {
        "name": "Leap-release",
        "SPDXID": "SPDXRef-Package-rpm-Leap-release",
        "versionInfo": "16.1",
        "sourceInfo": "acquired package info from RPM DB",
    }


class SecurityLevelTest(unittest.TestCase):
    def test_names_map_to_the_vyper_flag_values(self):
        for name, value in (("not_set", 1), ("low", 2), ("moderate", 4),
                            ("important", 8), ("critical", 16)):
            self.assertEqual(distro_tool.parse_security_level(name), (value, name))

    def test_values_are_accepted_too(self):
        self.assertEqual(distro_tool.parse_security_level("8"), (8, "important"))
        self.assertEqual(distro_tool.parse_security_level("CRITICAL"), (16, "critical"))

    def test_unwritten_slot_is_named(self):
        self.assertEqual(distro_tool.SECURITY_LEVEL_NAMES[0], "not_set")

    def test_unknown_level_is_rejected(self):
        for bad in ("severe", "3", ""):
            with self.assertRaises(SystemExit):
                distro_tool.parse_security_level(bad)


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


class ValidateProductRefTest(unittest.TestCase):
    def test_obs_md5_is_accepted(self):
        self.assertEqual(distro_tool.validate_product_ref(MD5), MD5)

    def test_git_sha_is_accepted(self):
        self.assertEqual(distro_tool.validate_product_ref(DIGEST.upper()), DIGEST)

    def test_empty_is_rejected(self):
        with self.assertRaises(SystemExit):
            distro_tool.validate_product_ref("")

    def test_too_long_is_rejected(self):
        with self.assertRaises(SystemExit):
            distro_tool.validate_product_ref("a" * 65)

    def test_non_hex_is_rejected(self):
        with self.assertRaises(SystemExit):
            distro_tool.validate_product_ref("Leap-16.1")


class SpdxRootTest(unittest.TestCase):
    def test_spdx2_document_root_package(self):
        doc = spdx2(packages=[rpm_pkg()])
        self.assertEqual(distro_tool._spdx_root(doc)["SPDXID"], "SPDXRef-DOCUMENT-ROOT")

    def test_spdx2_document_describes(self):
        doc = spdx2()
        doc["packages"][0]["SPDXID"] = "SPDXRef-Package-payload-1"
        doc["documentDescribes"] = ["SPDXRef-Package-payload-1"]
        self.assertEqual(distro_tool._spdx_root(doc)["SPDXID"], "SPDXRef-Package-payload-1")

    def test_spdx3_describes_relationship(self):
        doc = spdx3()
        root = distro_tool._spdx_root(doc)
        self.assertEqual(root["name"], LEAP_ROOT)
        self.assertEqual(root["type"], "software_Package")

    def test_spdx3_relationship_type_is_case_insensitive(self):
        doc = spdx3()
        for e in doc["@graph"]:
            if e.get("type") == "Relationship":
                e["relationshipType"] = "DESCRIBES"
        self.assertEqual(distro_tool._spdx_root(doc)["name"], LEAP_ROOT)

    def test_missing_root_is_an_error(self):
        doc = spdx2()
        doc["packages"] = [rpm_pkg()]
        with self.assertRaises(SystemExit):
            distro_tool._spdx_root(doc)
        doc = spdx3()
        doc["@graph"] = [e for e in doc["@graph"] if e.get("type") != "Relationship"]
        with self.assertRaises(SystemExit):
            distro_tool._spdx_root(doc)


class SpdxRefsTest(unittest.TestCase):
    def test_spdx2_refs(self):
        root = distro_tool._spdx_root(spdx2(root_refs=[disturl_ref(), vcs_ref("https://x/y#" + DIGEST)]))
        self.assertEqual(
            distro_tool._spdx_refs(root),
            [("obs-disturl", DISTURL, None), ("vcs", "https://x/y#" + DIGEST, None)],
        )

    def test_spdx3_locator_is_a_list(self):
        doc = spdx3(root_refs=[disturl_ref(v2=False), vcs_ref("https://x/y#" + DIGEST, v2=False)])
        root = distro_tool._spdx_root(doc)
        self.assertEqual(
            distro_tool._spdx_refs(root),
            [
                ("obs-disturl", DISTURL, "obs-disturl"),
                ("vcs", "https://x/y#" + DIGEST, None),
            ],
        )


class ProductNameTest(unittest.TestCase):
    def test_arch_and_build_suffix_is_stripped(self):
        root = distro_tool._spdx_root(spdx2())
        self.assertEqual(distro_tool.product_name(root), "Leap-16.1")

    def test_name_without_build_suffix_is_kept(self):
        root = distro_tool._spdx_root(spdx2(root_name="DVD1"))
        self.assertEqual(distro_tool.product_name(root), "DVD1")

    def test_single_arch_and_build_suffix(self):
        root = distro_tool._spdx_root(spdx2(root_name="Leap-16.1-x86_64-Build50.2"))
        self.assertEqual(distro_tool.product_name(root), "Leap-16.1")

    def test_name_with_uppercase_words_is_kept(self):
        root = distro_tool._spdx_root(spdx2(root_name="openSUSE-Leap-DVD-x86_64-Build1234.1"))
        self.assertEqual(distro_tool.product_name(root), "openSUSE-Leap-DVD")

    def test_build_without_arches(self):
        root = distro_tool._spdx_root(spdx2(root_name="Tumbleweed-20260924-Build1.2"))
        self.assertEqual(distro_tool.product_name(root), "Tumbleweed-20260924")

    def test_name_is_required(self):
        with self.assertRaises(SystemExit):
            distro_tool.product_name({})


class ProductRefTest(unittest.TestCase):
    def test_disturl_md5_fallback(self):
        doc = spdx2(root_refs=[disturl_ref()], packages=[rpm_pkg()])
        root = distro_tool._spdx_root(doc)
        self.assertEqual(distro_tool.product_ref(root), MD5)

    def test_vcs_fragment_wins(self):
        doc = spdx2(root_refs=[vcs_ref("https://src.opensuse.org/pool/leap#" + DIGEST), disturl_ref()])
        root = distro_tool._spdx_root(doc)
        self.assertEqual(distro_tool.product_ref(root), DIGEST)

    def test_vcs_without_fragment_falls_back_to_disturl(self):
        doc = spdx2(root_refs=[vcs_ref("https://src.opensuse.org/pool/leap"), disturl_ref()])
        root = distro_tool._spdx_root(doc)
        self.assertEqual(distro_tool.product_ref(root), MD5)

    def test_anchor_is_lowercased(self):
        doc = spdx2(root_refs=[vcs_ref("https://src.opensuse.org/pool/leap#" + DIGEST.upper())])
        self.assertEqual(distro_tool.product_ref(distro_tool._spdx_root(doc)), DIGEST)

    def test_spdx3_disturl_fallback(self):
        doc = spdx3(root_refs=[disturl_ref(v2=False)])
        self.assertEqual(distro_tool.product_ref(distro_tool._spdx_root(doc)), MD5)

    def test_refs_of_other_packages_are_ignored(self):
        doc = spdx2(root_refs=[disturl_ref()], packages=[rpm_pkg()])
        self.assertNotEqual(distro_tool.product_ref(distro_tool._spdx_root(doc)), DIGEST)

    def test_no_anchor_is_an_error(self):
        doc = spdx2(root_refs=[vcs_ref("https://src.opensuse.org/pool/leap")])
        with self.assertRaises(SystemExit):
            distro_tool.product_ref(distro_tool._spdx_root(doc))


class RpmmdChecksumTest(unittest.TestCase):
    def test_first_repository_package_wins(self):
        doc = spdx2(
            root_refs=[disturl_ref()],
            packages=[rpm_pkg(), repository_pkg(PRIMARY), repository_pkg(SECONDARY)],
        )
        root = distro_tool._spdx_root(doc)
        self.assertEqual(distro_tool.rpmmd_checksum(doc, root), (PRIMARY, [SECONDARY]))

    def test_duplicate_repository_packages_are_collapsed(self):
        doc = spdx2(packages=[repository_pkg(PRIMARY), repository_pkg(PRIMARY)])
        self.assertEqual(distro_tool.rpmmd_checksum(doc, distro_tool._spdx_root(doc)), (PRIMARY, []))

    def test_repository_needs_install_purpose(self):
        doc = spdx2(packages=[repository_pkg(PRIMARY, purpose="LIBRARY")])
        with self.assertRaises(SystemExit):
            distro_tool.rpmmd_checksum(doc, distro_tool._spdx_root(doc))

    def test_explicit_external_ref_wins(self):
        doc = spdx2(
            root_refs=[{"referenceCategory": "OTHER", "referenceType": "rpm-md-primary-checksum", "referenceLocator": "sha512:" + SECONDARY}],
            packages=[repository_pkg(PRIMARY)],
        )
        self.assertEqual(distro_tool.rpmmd_checksum(doc, distro_tool._spdx_root(doc)), (SECONDARY, []))

    def test_explicit_external_ref_spdx3(self):
        doc = spdx3(
            root_refs=[{"type": "ExternalRef", "externalRefType": "rpm-md-primary-checksum", "locator": ["sha512:" + SECONDARY]}],
        )
        self.assertEqual(distro_tool.rpmmd_checksum(doc, distro_tool._spdx_root(doc)), (SECONDARY, []))

    def test_root_version_is_the_last_resort(self):
        doc = spdx2(root_refs=[disturl_ref()], root_version=PRIMARY)
        self.assertEqual(distro_tool.rpmmd_checksum(doc, distro_tool._spdx_root(doc)), (PRIMARY, []))

    def test_root_version_spdx3(self):
        doc = spdx3(root_refs=[disturl_ref(v2=False)], root_version=PRIMARY)
        self.assertEqual(distro_tool.rpmmd_checksum(doc, distro_tool._spdx_root(doc)), (PRIMARY, []))

    def test_plain_version_is_not_a_checksum(self):
        doc = spdx2(root_refs=[disturl_ref()], root_version="16.1")
        with self.assertRaises(SystemExit):
            distro_tool.rpmmd_checksum(doc, distro_tool._spdx_root(doc))

    def test_missing_checksum_is_an_error(self):
        doc = spdx2(root_refs=[disturl_ref()])
        with self.assertRaises(SystemExit):
            distro_tool.rpmmd_checksum(doc, distro_tool._spdx_root(doc))


class RealLeapSbomTest(unittest.TestCase):
    """The shape of an openSUSE:Leap:16.1:Products product compose SBOM."""

    def setUp(self):
        self.doc = spdx2(
            packages=[
                rpm_pkg(),
                repository_pkg(PRIMARY),
                repository_pkg(SECONDARY),
            ],
            root_refs=[disturl_ref()],
        )

    def test_derived_values(self):
        root = distro_tool._spdx_root(self.doc)
        name = distro_tool.product_name(root)
        self.assertEqual(name, "Leap-16.1")
        self.assertEqual(distro_tool.validate_product_ref(distro_tool.product_ref(root)), MD5)
        checksum, skipped = distro_tool.rpmmd_checksum(self.doc, root)
        self.assertEqual(checksum, PRIMARY)
        self.assertEqual(skipped, [SECONDARY])

    def test_values_fit_the_contract(self):
        root = distro_tool._spdx_root(self.doc)
        checksum, _skipped = distro_tool.rpmmd_checksum(self.doc, root)
        self.assertLessEqual(len(distro_tool.product_name(root)), 16)
        self.assertLessEqual(len(distro_tool.product_ref(root)), 64)
        self.assertEqual(distro_tool.validate_verification(checksum), checksum)
        self.assertEqual(distro_tool.BUILD_KINDS["rpmmd"], 1)


class ReleasePackageNameTest(unittest.TestCase):
    def test_leap_release_package_name(self):
        self.assertEqual(distro_tool.release_package_name("Leap-16.1"), "Leap-release")

    def test_tumbleweed_release_package_name(self):
        self.assertEqual(
            distro_tool.release_package_name("Tumbleweed-20260924"), "Tumbleweed-release")

    def test_single_digit_version(self):
        self.assertEqual(distro_tool.release_package_name("Leap-15"), "Leap-release")

    def test_multi_component_name_keeps_the_rest(self):
        self.assertEqual(
            distro_tool.release_package_name("openSUSE-Leap-16.1"), "openSUSE-Leap-release")

    def test_without_a_version_suffix(self):
        self.assertEqual(distro_tool.release_package_name("Tumbleweed"), "Tumbleweed-release")

    def test_release_pkg_is_found_in_the_sbom(self):
        doc = spdx2(root_refs=[disturl_ref()],
                    packages=[rpm_pkg(), repository_pkg(PRIMARY), release_pkg()])
        self.assertTrue(distro_tool._spdx_has_package(doc, "Leap-release"))
        doc2 = spdx2(root_refs=[disturl_ref()], packages=[rpm_pkg(), repository_pkg(PRIMARY)])
        self.assertFalse(distro_tool._spdx_has_package(doc2, "Leap-release"))


class RegisterKindTest(unittest.TestCase):
    """register picks the build kind from the product's release package."""

    def _sbom_path(self, doc):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(doc, f)
            return f.name

    def _args(self, path, dry_run=False):
        return distro_tool.build_parser().parse_args(
            ["register", path] + (["--dry-run"] if dry_run else []))

    def _dry_run_kind(self, doc):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            distro_tool.do_register(
                mock.Mock(), mock.Mock(), self._args(self._sbom_path(doc), dry_run=True))
        return out.getvalue()

    def test_release_package_selects_the_product_kind(self):
        doc = spdx2(root_refs=[disturl_ref()],
                    packages=[rpm_pkg(), repository_pkg(PRIMARY), release_pkg()])
        self.assertIn("kind     : product", self._dry_run_kind(doc))

    def test_without_release_package_the_kind_stays_rpmmd(self):
        doc = spdx2(root_refs=[disturl_ref()],
                    packages=[rpm_pkg(), repository_pkg(PRIMARY)])
        self.assertIn("kind     : rpmmd", self._dry_run_kind(doc))

    def test_product_kind_is_registered_on_chain(self):
        doc = spdx2(root_refs=[disturl_ref()],
                    packages=[rpm_pkg(), repository_pkg(PRIMARY), release_pkg()])
        contract = mock.Mock()
        contract.functions.get_product_build.return_value.call.return_value = (0, 0, 0, 0)
        with mock.patch.object(distro_tool, "get_signer", return_value=mock.Mock()), \
             mock.patch.object(distro_tool, "_require_any_role"), \
             mock.patch.object(distro_tool, "_find_product", return_value=(1, False)), \
             mock.patch.object(distro_tool, "prompt", return_value=True), \
             mock.patch.object(distro_tool, "send_tx"), \
             contextlib.redirect_stdout(io.StringIO()):
            distro_tool.do_register(mock.Mock(), contract, self._args(self._sbom_path(doc)))
        contract.functions.add_product_build.assert_called_once_with(
            MD5, distro_tool.BUILD_KINDS["product"], PRIMARY)

    def test_rpmmd_kind_is_registered_without_release_package(self):
        doc = spdx2(root_refs=[disturl_ref()],
                    packages=[rpm_pkg(), repository_pkg(PRIMARY)])
        contract = mock.Mock()
        contract.functions.get_product_build.return_value.call.return_value = (0, 0, 0, 0)
        with mock.patch.object(distro_tool, "get_signer", return_value=mock.Mock()), \
             mock.patch.object(distro_tool, "_require_any_role"), \
             mock.patch.object(distro_tool, "_find_product", return_value=(1, False)), \
             mock.patch.object(distro_tool, "prompt", return_value=True), \
             mock.patch.object(distro_tool, "send_tx"), \
             contextlib.redirect_stdout(io.StringIO()):
            distro_tool.do_register(mock.Mock(), contract, self._args(self._sbom_path(doc)))
        contract.functions.add_product_build.assert_called_once_with(
            MD5, distro_tool.BUILD_KINDS["rpmmd"], PRIMARY)


class LoadSbomTest(unittest.TestCase):
    def test_missing_file(self):
        with self.assertRaises(SystemExit):
            distro_tool._load_sbom("/nonexistent/sbom.json")

    def test_broken_json(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            f.write("{not json")
            path = f.name
        with self.assertRaises(SystemExit):
            distro_tool._load_sbom(path)


class RegisterCliTest(unittest.TestCase):
    def test_register_subcommand(self):
        args = distro_tool.build_parser().parse_args(["register", "sbom.json"])
        self.assertIs(args.func, distro_tool.do_register)
        self.assertEqual(args.sbom, "sbom.json")
        self.assertFalse(args.dry_run)

    def test_register_dry_run(self):
        args = distro_tool.build_parser().parse_args(["register", "sbom.json", "--dry-run"])
        self.assertTrue(args.dry_run)


class ContractCompatibilityTest(unittest.TestCase):
    """distro_tool refuses a contract whose interface it does not implement."""

    ADDRESS = "0x02724c2d1e76Ea3A24247A48F959532cDb152Fb6"

    def _contract(self, value=None, error=None):
        contract = mock.Mock()
        level = mock.Mock()
        if error is not None:
            level.call.side_effect = error
        else:
            level.call.return_value = value
        contract.functions.compatibility_level.return_value = level
        return contract

    def test_matching_level_is_accepted(self):
        contract = self._contract(distro_tool.COMPATIBILITY_LEVEL)
        self.assertIs(distro_tool.check_compatibility(contract, self.ADDRESS), contract)

    def test_newer_contract_asks_for_a_newer_tool(self):
        with self.assertRaises(SystemExit) as raised:
            distro_tool.check_compatibility(self._contract(distro_tool.COMPATIBILITY_LEVEL + 1), self.ADDRESS)
        self.assertIn("Update distro_tool", str(raised.exception))

    def test_older_contract_asks_for_a_redeploy(self):
        with self.assertRaises(SystemExit) as raised:
            distro_tool.check_compatibility(self._contract(distro_tool.COMPATIBILITY_LEVEL - 1), self.ADDRESS)
        self.assertIn("Redeploy", str(raised.exception))

    def test_contract_without_the_view_asks_for_a_redeploy(self):
        with self.assertRaises(SystemExit) as raised:
            distro_tool.check_compatibility(
                self._contract(error=ValueError("execution reverted")), self.ADDRESS)
        message = str(raised.exception)
        self.assertIn("does not provide compatibility_level()", message)
        self.assertIn("Redeploy", message)

    def test_get_contract_addr_checks_the_level(self):
        w3 = mock.Mock()
        w3.eth.get_code.return_value = b"\x60"
        w3.eth.contract.return_value = self._contract(distro_tool.COMPATIBILITY_LEVEL)
        with mock.patch.object(distro_tool.Web3, "is_address", return_value=True), \
             mock.patch.object(distro_tool.Web3, "to_checksum_address", return_value=self.ADDRESS), \
             mock.patch.dict(distro_tool.os.environ, {}, clear=True):
            args = mock.Mock(contract=self.ADDRESS, network="hoodi", conf="/dev/null")
            contract = distro_tool.get_contract_addr(w3, args)
        w3.eth.contract.assert_called_once_with(address=self.ADDRESS, abi=distro_tool.CONTRACT_ABI)
        self.assertIs(contract, w3.eth.contract.return_value)

    def test_an_address_without_code_is_not_blamed_on_the_version(self):
        w3 = mock.Mock()
        w3.eth.get_code.return_value = b""
        with mock.patch.object(distro_tool.Web3, "is_address", return_value=True), \
             mock.patch.object(distro_tool.Web3, "to_checksum_address", return_value=self.ADDRESS), \
             mock.patch.dict(distro_tool.os.environ, {}, clear=True):
            args = mock.Mock(contract=self.ADDRESS, network="hoodi", conf="/dev/null")
            with self.assertRaises(SystemExit) as raised:
                distro_tool.get_contract_addr(w3, args)
        message = str(raised.exception)
        self.assertIn("No contract deployed at", message)
        self.assertNotIn("compatibility", message)
        w3.eth.contract.assert_not_called()


class ContractCommandTest(unittest.TestCase):
    """The contract command reports identity, roles and size of the contract."""

    ADDRESS = "0x02724c2d1e76Ea3A24247A48F959532cDb152Fb6"
    OWNER = "0x" + "aa" * 20
    CREATOR = "0x" + "bb" * 20
    VALIDATOR = "0x" + "cc" * 20
    SECURITY = "0x" + "dd" * 20

    def _contract(self):
        contract = mock.Mock(address=self.ADDRESS)
        contract.functions.compatibility_level.return_value.call.return_value = (
            distro_tool.COMPATIBILITY_LEVEL
        )
        contract.functions.foundation_owner.return_value.call.return_value = self.OWNER
        contract.functions.product_creator.return_value.call.return_value = self.CREATOR
        contract.functions.official_validator.return_value.call.return_value = self.VALIDATOR
        contract.functions.security_team.return_value.call.return_value = self.SECURITY
        contract.functions.get_product_counter.return_value.call.return_value = 3
        # next_build is the next free sequence number, so 5 means 4 builds
        contract.functions.next_build.return_value.call.return_value = 5
        return contract

    def test_contract_subcommand(self):
        args = distro_tool.build_parser().parse_args(["contract"])
        self.assertIs(args.func, distro_tool.do_contract)

    def test_roles_and_counter_subcommands_are_gone(self):
        parser = distro_tool.build_parser()
        for gone in ("roles", "counter"):
            with self.assertRaises(SystemExit), \
                    mock.patch("sys.stderr", new_callable=io.StringIO):
                parser.parse_args([gone])

    def test_reports_address_roles_and_entry_counts(self):
        args = distro_tool.build_parser().parse_args(["--network", "hoodi", "contract"])
        w3 = mock.Mock()
        w3.eth.chain_id = 560048
        with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            distro_tool.do_contract(w3, self._contract(), args)
        text = out.getvalue()
        self.assertIn("network           : hoodi (chain id 560048)", text)
        self.assertIn(f"contract          : {self.ADDRESS}", text)
        self.assertIn(
            f"compatibility     : {distro_tool.COMPATIBILITY_LEVEL} "
            f"(this tool implements level {distro_tool.COMPATIBILITY_LEVEL})",
            text,
        )
        self.assertIn(f"foundation_owner  : {self.OWNER}", text)
        self.assertIn(f"product_creator   : {self.CREATOR}", text)
        self.assertIn(f"official_validator: {self.VALIDATOR}", text)
        self.assertIn(f"security_team     : {self.SECURITY}", text)
        self.assertIn("products          : 3", text)
        self.assertIn("builds            : 4", text)

    def test_a_fresh_contract_counts_zero(self):
        args = distro_tool.build_parser().parse_args(["--network", "tester", "contract"])
        contract = self._contract()
        contract.functions.get_product_counter.return_value.call.return_value = 0
        contract.functions.next_build.return_value.call.return_value = 1
        w3 = mock.Mock()
        w3.eth.chain_id = 1337
        with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            distro_tool.do_contract(w3, contract, args)
        text = out.getvalue()
        self.assertIn("network           : tester (chain id 1337)", text)
        self.assertIn("products          : 0", text)
        self.assertIn("builds            : 0", text)


class CommandHelpTest(unittest.TestCase):
    """The help lists the commands grouped by the role the contract requires."""

    def _help(self):
        return distro_tool.build_parser().format_help()

    def _subparsers(self):
        parser = distro_tool.build_parser()
        return next(action for action in parser._actions
                    if isinstance(action, argparse._SubParsersAction))

    def test_every_registered_command_has_a_role_group(self):
        grouped = sorted(name for _role, names in distro_tool.COMMAND_ROLES
                         for name in names)
        self.assertEqual(sorted(self._subparsers().choices), grouped)

    def test_a_command_without_a_role_group_fails_loudly(self):
        # a subcommand added but not assigned to a role must not silently
        # vanish from the help
        p = argparse.ArgumentParser()
        sub = p.add_subparsers(metavar="<command>")
        sub.add_parser("stray", help="not assigned anywhere")
        with self.assertRaises(KeyError):
            distro_tool.commands_by_role(sub)

    def test_the_help_lists_every_command_under_its_role(self):
        text = self._help()
        for role, names in distro_tool.COMMAND_ROLES:
            self.assertIn(f"  {role}:", text)
            for name in names:
                self.assertIn(f"    {name} ", text)

    def test_the_read_only_commands_come_first(self):
        text = self._help()
        self.assertLess(text.index("anyone (read-only)"), text.index("foundation owner"))
        self.assertLess(text.index("foundation owner"), text.index("product builder"))
        self.assertLess(text.index("product builder"), text.index("official validator"))
        self.assertLess(text.index("official validator"), text.index("security team"))

    def test_the_commands_are_not_listed_twice(self):
        # once in the grouped epilog, not again under "positional arguments"
        text = self._help()
        self.assertEqual(text.count("    contract "), 1)
        self.assertEqual(text.count("    set-security-level "), 1)


class SetSecurityLevelCliTest(unittest.TestCase):
    VERIFICATION = "aa" * 32

    def test_set_security_level_subcommand(self):
        args = distro_tool.build_parser().parse_args(
            ["set-security-level", self.VERIFICATION, "important"])
        self.assertIs(args.func, distro_tool.do_set_security_level)
        self.assertEqual(args.verification, self.VERIFICATION)
        self.assertEqual(args.level, "important")

    def test_the_old_set_critical_command_is_gone(self):
        with self.assertRaises(SystemExit):
            distro_tool.build_parser().parse_args(["set-critical", self.VERIFICATION, "true"])

    def test_set_security_level_sends_the_flag_value(self):
        args = distro_tool.build_parser().parse_args(
            ["-y", "set-security-level", self.VERIFICATION, "moderate"])
        contract = self.contract(registered=True)
        with mock.patch.object(distro_tool, "get_signer", return_value=mock.Mock()), \
             mock.patch.object(distro_tool, "send_tx") as send:
            distro_tool.do_set_security_level(mock.Mock(), contract, args)
        contract.functions.set_security_level.assert_called_once_with(self.VERIFICATION, 4)
        self.assertEqual(send.call_count, 1)

    def test_withdrawing_a_report_sends_not_set(self):
        args = distro_tool.build_parser().parse_args(
            ["-y", "set-security-level", self.VERIFICATION, "not_set"])
        contract = self.contract(registered=True)
        with mock.patch.object(distro_tool, "get_signer", return_value=mock.Mock()), \
             mock.patch.object(distro_tool, "send_tx"):
            distro_tool.do_set_security_level(mock.Mock(), contract, args)
        contract.functions.set_security_level.assert_called_once_with(
            self.VERIFICATION, distro_tool.SECURITY_LEVELS["not_set"])

    def test_an_unregistered_build_is_refused_without_a_transaction(self):
        args = distro_tool.build_parser().parse_args(
            ["-y", "set-security-level", self.VERIFICATION, "critical"])
        contract = self.contract(registered=False)
        with mock.patch.object(distro_tool, "get_signer", return_value=mock.Mock()), \
             mock.patch.object(distro_tool, "send_tx") as send:
            with self.assertRaises(SystemExit):
                distro_tool.do_set_security_level(mock.Mock(), contract, args)
        send.assert_not_called()
        contract.functions.set_security_level.assert_not_called()

    def test_a_bogus_digest_is_rejected(self):
        args = distro_tool.build_parser().parse_args(
            ["-y", "set-security-level", "not-a-digest", "low"])
        with self.assertRaises(SystemExit):
            distro_tool.do_set_security_level(mock.Mock(), self.contract(registered=True), args)

    def contract(self, registered):
        contract = mock.Mock()
        build = (1, 1, 2, 0) if registered else (0, 0, 0, 0)
        contract.functions.get_product_build.return_value.call.return_value = build
        contract.functions.get_product.return_value.call.return_value = ("example-1", "f" * 64)
        return contract


class ShowIdSecurityHistoryTest(unittest.TestCase):
    def test_showid_prints_the_reports_of_the_product(self):
        contract = mock.Mock()
        contract.functions.get_product.return_value.call.return_value = ("example-1", "f" * 64)
        contract.functions.product_security.return_value.call.return_value = [
            ("aa" * 32, 16), ("bb" * 32, 1)]
        args = distro_tool.build_parser().parse_args(["showid", "1"])
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            distro_tool.do_showid(mock.Mock(), contract, args)
        report = out.getvalue()
        self.assertIn("aa" * 32, report)
        self.assertIn("critical", report)
        # a withdrawn report is still shown, it consumed a slot of the history
        self.assertIn("not_set", report)
        self.assertIn(str(distro_tool.MAX_SECURITY_MARKERS), report)

    def test_showid_says_so_when_nothing_was_reported(self):
        contract = mock.Mock()
        contract.functions.get_product.return_value.call.return_value = ("example-1", "f" * 64)
        contract.functions.product_security.return_value.call.return_value = []
        args = distro_tool.build_parser().parse_args(["showid", "1"])
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            distro_tool.do_showid(mock.Mock(), contract, args)
        self.assertIn("no reports", out.getvalue())


class SendTxErrorTests(unittest.TestCase):
    """RPC failures must produce one actionable message, never a traceback."""

    ADDRESS = "0x46B8f0Ca9AFD515e9E0dBba75287c0d85d522459"
    RPC = "https://sepolia-rollup.arbitrum.io/rpc"

    def rpc_error(self, message, code=-32003):
        # the shape web3 produces for a node-returned error: the response dict
        # lands in .message, the flat .user_message is generic boilerplate
        return Web3RPCError({"code": code, "message": message})

    def account(self):
        acct = mock.Mock()
        acct.address = self.ADDRESS
        acct.sign_transaction.return_value = mock.Mock(raw_transaction=b"\x01")
        return acct

    def function(self, estimate=100000):
        fn = mock.Mock()
        fn.fn_name = "add_product"
        fn.estimate_gas.return_value = estimate
        return fn

    def web3(self, send=None, receipt=None):
        w3 = mock.Mock()
        w3.eth.chain_id = 421614
        w3.eth.get_transaction_count.return_value = 3
        w3.eth.send_raw_transaction.side_effect = send
        w3.eth.wait_for_transaction_receipt.return_value = receipt
        w3.provider.endpoint_uri = self.RPC
        return w3

    def exit_message(self, fn, w3, acct=None, gas=None):
        with self.assertRaises(SystemExit) as caught:
            distro_tool.send_tx(w3, acct or self.account(), fn, gas=gas)
        return " ".join(str(caught.exception).split())

    def test_no_funds_reports_the_balance_problem_and_the_faucet(self):
        error = self.rpc_error(
            "insufficient funds for gas * price + value: have 0 want 1950624946997360")
        message = self.exit_message(self.function(), self.web3(send=error))
        self.assertIn("insufficient funds for gas * price + value", message)
        self.assertIn(self.ADDRESS, message)
        self.assertIn("does not hold enough balance", message)
        self.assertIn("https://portal.arbitrum.io", message)
        self.assertIn("RPC error -32003", message)

    def test_the_boilerplate_and_the_traceback_are_not_shown(self):
        error = self.rpc_error("insufficient funds for gas * price + value: have 0")
        message = self.exit_message(self.function(), self.web3(send=error))
        self.assertNotIn("An RPC error was returned by the node", message)
        self.assertNotIn("Traceback", message)
        self.assertNotIn("web3.exceptions", message)
        self.assertNotIn("'code':", message)

    def test_an_unfunded_account_is_caught_during_estimation(self):
        error = self.rpc_error("gas required exceeds allowance", code=-32000)
        fn = self.function()
        fn.estimate_gas.side_effect = error
        w3 = self.web3()
        message = self.exit_message(fn, w3)
        w3.eth.send_raw_transaction.assert_not_called()
        self.assertIn("does not hold enough balance", message)

    def test_a_stringified_response_is_unwrapped(self):
        # the shape web3 7.x really produces for a node-returned error
        error = Web3RPCError(
            "{'code': -32003, 'message': 'insufficient funds for gas * price + value: "
            "have 0 want 1950624946997360'}")
        message = self.exit_message(self.function(), self.web3(send=error))
        self.assertIn("insufficient funds for gas * price + value", message)
        self.assertIn("RPC error -32003", message)
        self.assertNotIn("'code':", message)
        self.assertNotIn("{", message)

    def test_a_plain_string_error_is_passed_through(self):
        error = Web3RPCError("intrinsic gas too low")
        message = self.exit_message(self.function(), self.web3(send=error))
        self.assertIn("intrinsic gas too low", message)
        self.assertIn("--gas", message)

    def test_a_contract_deployment_is_named_as_such(self):
        error = self.rpc_error("insufficient funds for gas * price + value: have 0")
        fn = self.function()
        fn.fn_name = None
        message = self.exit_message(fn, self.web3(send=error))
        self.assertIn("Deploying the contract failed", message)

    def test_a_reused_nonce_points_at_the_pending_transaction(self):
        error = self.rpc_error("nonce too low")
        message = self.exit_message(self.function(), self.web3(send=error))
        self.assertIn("already knows a transaction", message)

    def test_an_unknown_error_names_the_endpoint(self):
        error = self.rpc_error("header not found")
        message = self.exit_message(self.function(), self.web3(send=error))
        self.assertIn(self.RPC, message)
        self.assertIn("--provider", message)

    def test_an_explicit_gas_limit_skips_estimation(self):
        error = self.rpc_error("insufficient funds for gas * price + value: have 0")
        fn = self.function()
        self.exit_message(fn, self.web3(send=error), gas=2000000)
        fn.estimate_gas.assert_not_called()

    def test_a_reverted_transaction_exits_instead_of_reporting_success(self):
        receipt = {"status": 0, "gasUsed": 21000, "transactionHash": b"\xaa"}
        w3 = self.web3(receipt=receipt)
        w3.eth.send_raw_transaction.return_value = mock.Mock(hex=lambda: "0xdead")
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as caught:
            distro_tool.send_tx(w3, self.account(), self.function())
        self.assertIn("status : FAILED", out.getvalue())
        self.assertIn("mined but reverted", " ".join(str(caught.exception).split()))

    def test_a_timeout_names_the_transaction_to_look_up(self):
        w3 = self.web3()
        w3.eth.send_raw_transaction.return_value = mock.Mock(hex=lambda: "0xbeef")
        w3.eth.wait_for_transaction_receipt.side_effect = TimeExhausted("no receipt")
        with self.assertRaises(SystemExit) as caught:
            distro_tool.send_tx(w3, self.account(), self.function())
        message = " ".join(str(caught.exception).split())
        self.assertIn("0xbeef", message)
        self.assertIn("not mined", message)
        self.assertIn("pay twice", message)

    def test_a_successful_send_still_returns_the_receipt(self):
        receipt = {"status": 1, "gasUsed": 12345}
        w3 = self.web3(receipt=receipt)
        w3.eth.send_raw_transaction.return_value = mock.Mock(hex=lambda: "0xcafe")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = distro_tool.send_tx(w3, self.account(), self.function())
        self.assertIs(rc, receipt)
        self.assertIn("status : OK", out.getvalue())


class ConnectWeb3Test(unittest.TestCase):
    """A node that does not implement eth_syncing (Nitro) must still be usable."""

    RPC = "https://arb1.arbitrum.io/rpc"

    def args(self, provider="https://a.example,https://b.example", chain_id="42161"):
        return mock.Mock(provider=provider, chain_id=chain_id, network="arbitrum", conf="x")

    def web3(self, connected=True, syncing=False, chain_id=42161):
        w3 = mock.Mock()
        w3.is_connected.return_value = connected
        w3.eth = mock.Mock()
        w3.eth.chain_id = chain_id
        if syncing is None:
            # a Nitro node rejects the method, so reading the attribute raises
            type(w3.eth).syncing = mock.PropertyMock(side_effect=MethodUnavailable(
                "{'code': -32601, 'message': 'the method eth_syncing does not exist'}"))
        else:
            w3.eth.syncing = syncing
        return w3

    def connect(self, w3, args=None):
        presets = {"arbitrum": {"http_provider": "https://a.example,https://b.example",
                                "chainid": "42161"}}
        with mock.patch.object(distro_tool, "load_conf", return_value=presets), \
             mock.patch.object(distro_tool, "Web3", return_value=w3):
            return distro_tool.connect_web3(args or self.args())

    def test_a_node_without_eth_syncing_is_accepted(self):
        w3 = self.web3(syncing=None)
        w3_out, _ = self.connect(w3)
        self.assertIs(w3_out, w3)

    def test_a_syncing_node_is_refused(self):
        with self.assertRaises(SystemExit) as raised:
            self.connect(self.web3(syncing=True))
        self.assertIn("still syncing", str(raised.exception))

    def test_a_wrong_chain_is_refused(self):
        with self.assertRaises(SystemExit) as raised:
            self.connect(self.web3(chain_id=421614))
        self.assertIn("Wrong chain", str(raised.exception))

    def test_an_unreachable_endpoint_is_reported_without_a_traceback(self):
        w3 = self.web3()
        w3.is_connected.side_effect = ValueError("connection refused")
        with self.assertRaises(SystemExit) as raised:
            self.connect(w3)
        self.assertIn("connection refused", str(raised.exception))
        self.assertNotIn("Traceback", str(raised.exception))

    def test_no_provider_is_reported(self):
        with self.assertRaises(SystemExit) as raised:
            distro_tool.connect_web3(self.args(provider=""))
        self.assertIn("No provider", str(raised.exception))


class AddBuildPrecheckTest(unittest.TestCase):
    """add-build reports the failing check instead of a bare 'would revert'."""

    CREATOR = "0x46B8f0Ca9AFD515e9E0dBba75287c0d85d522459"
    OTHER = "0x000000000000000000000000000000000000dEaD"
    GIT_REF = "32c02093d0936f75935c1c405f17e776"
    VER = "aa" * 32

    def args(self):
        return distro_tool.build_parser().parse_args(
            ["-y", "add-build", self.GIT_REF, "rpmmd", self.VER])

    def acct(self, address):
        acct = mock.Mock()
        acct.address = address
        return acct

    def contract(self, product_creator, registered=False, products=()):
        c = mock.Mock()
        c.functions.product_creator.return_value.call.return_value = product_creator
        c.functions.foundation_owner.return_value.call.return_value = "0x" + "0" * 40
        c.functions.official_validator.return_value.call.return_value = "0x" + "1" * 40
        c.functions.security_team.return_value.call.return_value = "0x" + "2" * 40
        c.functions.next_product.return_value.call.return_value = len(products) + 1
        build = (1, 1, 1, 0) if registered else (0, 0, 0, 0)
        c.functions.get_product_build.return_value.call.return_value = build
        c.functions.get_product.return_value.call.side_effect = products
        return c

    def drive(self, c, signer):
        with mock.patch.object(distro_tool, "get_signer", return_value=self.acct(signer)), \
             mock.patch.object(distro_tool, "send_tx") as send:
            try:
                distro_tool.do_add_build(mock.Mock(), c, self.args())
                raised = None
            except SystemExit as e:
                raised = " ".join(str(e).split())
        return raised, send

    def test_an_already_registered_build_is_named(self):
        c = self.contract(self.CREATOR, registered=True,
                          products=[("Leap-16.0", self.GIT_REF)])
        message, send = self.drive(c, self.CREATOR)
        self.assertIn("already registered", message)
        self.assertIn("product : 1", message)
        self.assertIn("kind : rpmmd", message)
        send.assert_not_called()

    def test_a_source_without_a_product_is_named(self):
        c = self.contract(self.CREATOR, registered=False,
                          products=[("Leap-16.1", "e36b8dcaaf3e3f0b676be182ffdb44dd")])
        message, send = self.drive(c, self.CREATOR)
        self.assertIn("does not match any registered product", message)
        send.assert_not_called()

    def test_a_key_without_the_role_is_named(self):
        c = self.contract(self.CREATOR, registered=False,
                          products=[("Leap-16.0", self.GIT_REF)])
        message, send = self.drive(c, self.OTHER)
        self.assertIn("none of the required roles", message)
        self.assertIn(self.OTHER, message)
        send.assert_not_called()

    def test_a_valid_build_is_sent(self):
        c = self.contract(self.CREATOR, registered=False,
                          products=[("Leap-16.0", self.GIT_REF)])
        message, send = self.drive(c, self.CREATOR)
        self.assertIsNone(message)
        c.functions.add_product_build.assert_called_once_with(self.GIT_REF, 1, self.VER)
        send.assert_called_once()


class ResolveNetworkTest(unittest.TestCase):
    """Without --network the [main] section of the conf decides the network."""

    def _resolve(self, network, main_section):
        args = mock.Mock(network=network, conf="/etc/suse-distro-check.conf")
        with mock.patch.object(distro_tool, "load_conf", return_value=main_section):
            return distro_tool.resolve_network_name(args)

    def test_an_explicit_network_wins_over_main(self):
        self.assertEqual(
            self._resolve("hoodi", {"main": {"network": "arbitrum-sepolia"}}), "hoodi")

    def test_a_missing_network_uses_main(self):
        self.assertEqual(
            self._resolve(None, {"main": {"network": "arbitrum-sepolia"}}),
            "arbitrum-sepolia")

    def test_main_without_network_falls_back_to_sepolia(self):
        self.assertEqual(self._resolve(None, {"main": {}}), "sepolia")

    def test_no_conf_falls_back_to_sepolia(self):
        self.assertEqual(self._resolve(None, {}), "sepolia")

    def test_the_parser_no_long_hardcodes_a_default(self):
        self.assertIsNone(distro_tool.build_parser().parse_args(["contract"]).network)


if __name__ == "__main__":
    unittest.main()
