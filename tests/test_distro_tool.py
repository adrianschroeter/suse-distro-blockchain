# SPDX-License-Identifier: GPL-3.0-or-later
"""Unit tests for the distro_tool argument validation and SPDX SBOM parsing."""

import unittest
from unittest import mock

from suse_distro_blockchain import distro_tool

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
        w3.eth.contract.return_value = self._contract(distro_tool.COMPATIBILITY_LEVEL)
        with mock.patch.object(distro_tool.Web3, "is_address", return_value=True), \
             mock.patch.object(distro_tool.Web3, "to_checksum_address", return_value=self.ADDRESS), \
             mock.patch.dict(distro_tool.os.environ, {}, clear=True):
            args = mock.Mock(contract=self.ADDRESS, network="hoodi", conf="/dev/null")
            contract = distro_tool.get_contract_addr(w3, args)
        w3.eth.contract.assert_called_once_with(address=self.ADDRESS, abi=distro_tool.CONTRACT_ABI)
        self.assertIs(contract, w3.eth.contract.return_value)


class SetSecurityLevelCliTest(unittest.TestCase):
    def test_set_security_level_subcommand(self):
        args = distro_tool.build_parser().parse_args(["set-security-level", "3", "important"])
        self.assertIs(args.func, distro_tool.do_set_security_level)
        self.assertEqual(args.product_id, 3)
        self.assertEqual(args.level, "important")

    def test_the_old_set_critical_command_is_gone(self):
        with self.assertRaises(SystemExit):
            distro_tool.build_parser().parse_args(["set-critical", "3", "true"])

    def test_set_security_level_sends_the_flag_value(self):
        args = distro_tool.build_parser().parse_args(["-y", "set-security-level", "3", "moderate"])
        contract = mock.Mock()
        with mock.patch.object(distro_tool, "get_signer", return_value=mock.Mock()), \
             mock.patch.object(distro_tool, "send_tx") as send:
            distro_tool.do_set_security_level(mock.Mock(), contract, args)
        contract.functions.set_security_level.assert_called_once_with(3, 4)
        self.assertEqual(send.call_count, 1)


if __name__ == "__main__":
    unittest.main()
