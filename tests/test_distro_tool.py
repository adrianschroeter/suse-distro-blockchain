# SPDX-License-Identifier: GPL-3.0-or-later
"""Unit tests for the distro_tool argument validation and SPDX SBOM parsing."""

import unittest

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


if __name__ == "__main__":
    unittest.main()
