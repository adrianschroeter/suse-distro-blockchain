# SPDX-License-Identifier: GPL-3.0-or-later
"""Shared repository metadata verification against the distro attestation contract.

This module is used by both the ``suse-distro-check`` command line tool and the
zypp ``repoverification`` plugin. It contains no credentials and only performs
read-only contract calls.

The check performed here is on the *raw* repository metadata (``repodata/repomd.xml``)
and therefore runs before zypp converts the metadata into solv data.
"""

import configparser
import os
from xml.dom import Node
from xml.dom.minidom import parse

from web3 import Web3

try:
    from .distro_contract import CONTRACT_ABI
except ImportError:  # pragma: nocover - direct execution from a source checkout
    from distro_contract import CONTRACT_ABI


# ---------------------------------------------------------------------------
# on-chain enum values - must match ape/contracts/distro.vy
# ---------------------------------------------------------------------------
BUILD_KINDS = {"rpmmd": 1, "product": 2, "oci_container": 4}
KIND_NAMES = {v: k for k, v in BUILD_KINDS.items()}

ATTESTATION_NONE = 0
ATTESTATION_OUTSTANDING = 1
ATTESTATION_APPROVED = 2
ATTESTATION_REJECTED = 4
ATTESTATION_NAMES = {
    ATTESTATION_NONE: "none",
    ATTESTATION_OUTSTANDING: "outstanding",
    ATTESTATION_APPROVED: "approved",
    ATTESTATION_REJECTED: "rejected",
}

MAX_VERIFICATION_LEN = 128  # fits sha512 (128 hex chars)
DEFAULT_CONF = os.path.join(os.sep, "etc", "suse-distro-check.conf")

# Digest of the empty string for common algorithms. A git_ref matching one of
# these is a strong hint the registered commit is bogus/not a real commit.
EMPTY_STRING_DIGESTS = {
    "MD5": "d41d8cd98f00b204e9800998ecf8427e",
    "SHA-1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "SHA-256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
}


def default_conf_path():
    """Locate suse-distro-check.conf (env override, /etc, then source tree)."""
    env = os.environ.get("SUSE_DISTRO_CHECK_CONF")
    if env:
        return env
    if os.path.exists(DEFAULT_CONF):
        return DEFAULT_CONF
    here = os.path.dirname(os.path.abspath(__file__))
    repo = os.path.normpath(os.path.join(here, os.pardir, os.pardir, "suse-distro-check.conf"))
    if os.path.exists(repo):
        return repo
    return DEFAULT_CONF

# ---------------------------------------------------------------------------
# verdict levels
# ---------------------------------------------------------------------------
OK = "ok"
WARN = "warn"
REJECT = "reject"

LEVEL_ORDER = {OK: 0, WARN: 1, REJECT: 2}
TAG = {OK: "OK", WARN: "warn", REJECT: "ERROR"}

# terminal colors used by the reporting front ends
COLORS = {OK: "green", WARN: "yellow", REJECT: "red"}

# Level applied to a check that fails. ``ignore`` disables the check.
_LEVEL_KEYS = ("registered", "critical_issues", "rpc_error", "current_build", "kind", "signed")
_UNMANAGED_LEVELS = ("allow", "warn", "reject")
_MIN_ATTESTATION_VALUES = ("off", "outstanding", "approved")

DEFAULT_POLICY = {
    # repos without a [repo:<alias>] section:
    "unmanaged": "allow",
    # failure level per check:
    "registered": REJECT,
    "critical_issues": REJECT,
    "rpc_error": REJECT,
    "current_build": WARN,
    "kind": WARN,
    "signed": WARN,
    # minimum accepted reproducibility attestation (outstanding is accepted,
    # rejected always fails):
    "min_attestation": "outstanding",
    # optional per repo network override (section name in the config file):
    "network": "",
}

# keys that configure the network rather than the policy
_NETWORK_KEYS = ("http_provider", "chainid", "contract")


# ---------------------------------------------------------------------------
# configuration and policy
# ---------------------------------------------------------------------------
def load_conf(path):
    """Parse the config file into ``{section: {key: value}}``.

    Returns an empty mapping for a missing or unreadable file so that callers
    can fall back to a safe default instead of failing.
    """
    cp = configparser.ConfigParser(interpolation=None)
    if path and os.path.exists(path):
        cp.read(path)
    return {section: dict(cp.items(section)) for section in cp.sections()}


def repo_section(alias):
    return "repo:" + alias


def _find_repo_section(conf, alias):
    key = repo_section(alias)
    if key in conf:
        return key
    lowered = key.lower()
    for section in conf:
        if section.lower() == lowered:
            return section
    return None


def _merge_policy(values, section, issues, where):
    for raw_key, raw_val in section.items():
        key = raw_key.strip().lower()
        val = str(raw_val).strip()
        if key in _LEVEL_KEYS:
            if val in (REJECT, WARN, "ignore"):
                values[key] = val
            else:
                issues.append(f"{where}: invalid value '{val}' for '{key}' (using '{values[key]}')")
        elif key == "unmanaged":
            if val in _UNMANAGED_LEVELS:
                values["unmanaged"] = val
            else:
                issues.append(f"{where}: invalid value '{val}' for 'unmanaged' (using '{values['unmanaged']}')")
        elif key == "min_attestation":
            if val in _MIN_ATTESTATION_VALUES:
                values["min_attestation"] = val
            else:
                issues.append(
                    f"{where}: invalid value '{val}' for 'min_attestation' "
                    f"(using '{values['min_attestation']}')"
                )
        elif key == "network":
            values["network"] = val
        elif key in _NETWORK_KEYS:
            continue  # network section key, not a policy knob
        # anything else is ignored so shared sections stay valid


class Policy:
    """Resolved policy for a single repository alias."""

    def __init__(self, alias, values, managed, issues=None):
        self.alias = alias
        self.values = values
        self.managed = managed
        self.issues = list(issues or [])

    def level(self, key):
        return self.values[key]

    @property
    def unmanaged_level(self):
        return {"allow": OK, "warn": WARN, "reject": REJECT}[self.values["unmanaged"]]


def resolve_policy(conf, alias):
    """Build the effective policy for ``alias`` from [defaults] and [repo:<alias>]."""
    values = dict(DEFAULT_POLICY)
    issues = []
    _merge_policy(values, conf.get("defaults", {}), issues, "defaults")
    section = _find_repo_section(conf, alias)
    if section is not None:
        _merge_policy(values, conf[section], issues, section)
    return Policy(alias, values, section is not None, issues)


def resolve_network(conf, policy):
    """Return the network settings for a policy.

    The network is taken from the [repo:<alias>] section if given, otherwise
    from the section referenced by [main] network.
    """
    name = policy.values.get("network") or str(conf.get("main", {}).get("network", "")).strip()
    net = dict(conf.get(name, {}))
    net["network"] = name
    return net


# ---------------------------------------------------------------------------
# provider / contract helpers
# ---------------------------------------------------------------------------
def connect_provider(url, chain_id=None, timeout=10.0):
    """Connect to an http provider and optionally verify the chain id."""
    if not url:
        raise ValueError("no http_provider configured")
    w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": timeout}))
    if not w3.is_connected():
        raise ConnectionError(f"cannot connect to {url}")
    if chain_id and int(chain_id) != w3.eth.chain_id:
        raise ValueError(f"wrong chain id {w3.eth.chain_id}, expected {chain_id}")
    return w3


def contract_at(w3, address):
    """Return a contract instance for a checksummed address."""
    if not address:
        raise ValueError("no contract address configured")
    if not Web3.is_address(address):
        raise ValueError(f"invalid contract address {address!r}")
    return w3.eth.contract(address=Web3.to_checksum_address(address), abi=CONTRACT_ABI)


# ---------------------------------------------------------------------------
# checks
# ---------------------------------------------------------------------------
class Result:
    """Outcome of a single check."""

    def __init__(self, name, level, message):
        self.name = name
        self.level = level
        self.message = message

    def __str__(self):
        return f"[{TAG[self.level]}] {self.name}: {self.message}"


def worst(results):
    level = OK
    for result in results:
        if LEVEL_ORDER[result.level] > LEVEL_ORDER[level]:
            level = result.level
    return level


def unmanaged_result(policy):
    return Result(
        "unmanaged",
        policy.unmanaged_level,
        f"no policy configured for repository {policy.alias!r}",
    )


def read_primary_checksum(repomd_path):
    """Return ``(checksum_type, verification)`` of the primary metadata.

    ``verification`` is the digest registered on-chain. Raises ``ValueError``
    when no usable primary checksum is present.
    """
    xml = parse(repomd_path)
    for data in xml.getElementsByTagName("data"):
        if data.getAttribute("type") != "primary":
            continue
        for cksum in data.getElementsByTagName("checksum"):
            cksum_type = cksum.getAttribute("type")
            value = "".join(
                node.data for node in cksum.childNodes if node.nodeType == Node.TEXT_NODE
            ).strip()
            if not value:
                continue
            if not (0 < len(value) <= MAX_VERIFICATION_LEN):
                raise ValueError(f"unsupported primary checksum length: {len(value)}")
            return cksum_type, value
    raise ValueError("no primary checksum found in metadata")


def verify_build(verification, contract, policy, fsig_path=None):
    """Run all on-chain/local checks for ``verification``.

    Returns a list of :class:`Result`. Failing checks carry the level configured
    in ``policy``; disabled (``ignore``) checks are omitted.
    """
    results = []

    if policy.level("signed") != "ignore":
        signed = bool(fsig_path) and os.path.exists(fsig_path)
        if signed:
            results.append(Result("signed", OK, "repository metadata is GPG signed"))
        else:
            results.append(
                Result("signed", policy.level("signed"), "repository metadata has no GPG signature")
            )

    build = contract.functions.get_product_build(verification).call()
    product_id, kind, attestation = build[0], build[1], build[2]
    if product_id == 0:
        results.append(
            Result(
                "registered",
                policy.level("registered"),
                f"build {verification} is not registered on-chain",
            )
        )
        return results
    results.append(Result("registered", OK, f"build is registered as product #{product_id}"))

    product = contract.functions.get_product(product_id).call()
    name, git_ref, critical = product[0], product[1], product[2]
    kind_name = KIND_NAMES.get(kind, str(kind))
    results.append(Result("product", OK, f"{name!r} (git_ref {git_ref}, {kind_name})"))

    if len(git_ref) < 64:
        results.append(
            Result(
                "git_ref",
                WARN,
                f"source commit is only {len(git_ref)} hex chars, shorter than a "
                "SHA-256 checksum (64)",
            )
        )
    for algo, digest in EMPTY_STRING_DIGESTS.items():
        if len(git_ref) == len(digest) and git_ref.lower() == digest:
            results.append(
                Result(
                    "git_ref",
                    WARN,
                    f"source commit equals the {algo} digest of the empty string",
                )
            )

    if policy.level("kind") != "ignore":
        if kind == BUILD_KINDS["rpmmd"]:
            results.append(Result("kind", OK, "on-chain build kind is rpmmd"))
        else:
            results.append(
                Result(
                    "kind",
                    policy.level("kind"),
                    f"on-chain build kind is {kind_name}, expected rpmmd",
                )
            )

    if policy.level("critical_issues") != "ignore":
        if critical:
            results.append(
                Result(
                    "critical_issues",
                    policy.level("critical_issues"),
                    f"product {name!r} has known critical security issues",
                )
            )
        else:
            results.append(Result("critical_issues", OK, "no known critical security issues"))

    min_attestation = policy.values["min_attestation"]
    if min_attestation != "off":
        minimum = {
            "outstanding": ATTESTATION_OUTSTANDING,
            "approved": ATTESTATION_APPROVED,
        }[min_attestation]
        att_name = ATTESTATION_NAMES.get(attestation, str(attestation))
        if attestation == ATTESTATION_REJECTED:
            results.append(
                Result("attestation", REJECT, "reproducibility attestation is rejected")
            )
        elif attestation < minimum:
            results.append(
                Result(
                    "attestation",
                    WARN,
                    f"reproducibility attestation is {att_name}, required {min_attestation}",
                )
            )
        else:
            results.append(
                Result("attestation", OK, f"reproducibility attestation is {att_name}")
            )

    if policy.level("current_build") != "ignore":
        current = contract.functions.current_product_build(name, kind).call()
        if verification == current:
            results.append(Result("current_build", OK, "repository is the current build"))
        else:
            results.append(
                Result(
                    "current_build",
                    policy.level("current_build"),
                    f"a different build is current for {name!r} ({kind_name}): {current or '(none)'}",
                )
            )

    return results


def verify_repomd(repomd_path, policy, conf, fsig_path=None, timeout=10.0, contract_override=None):
    """Full pipeline for a ``repomd.xml`` file: returns a list of :class:`Result`."""
    try:
        _checksum_type, verification = read_primary_checksum(repomd_path)
    except Exception as exc:  # unreadable/unsupported metadata is a hard failure
        return [Result("metadata", REJECT, f"cannot read primary checksum: {exc}")]

    net = resolve_network(conf, policy)
    try:
        w3 = connect_provider(net.get("http_provider"), net.get("chainid"), timeout)
        contract = contract_at(w3, contract_override or net.get("contract"))
    except Exception as exc:
        level = policy.level("rpc_error")
        if level == "ignore":
            return [Result("rpc_error", OK, f"chain not reachable ({exc}); check ignored")]
        return [Result("rpc_error", level, f"chain not reachable for network "
                                           f"{net.get('network')!r}: {exc}")]

    try:
        return verify_build(verification, contract, policy, fsig_path)
    except Exception as exc:
        return [Result("rpc_error", policy.level("rpc_error"), f"on-chain lookup failed: {exc}")]
