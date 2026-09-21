#!/usr/bin/python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""suse-distro-check - verify the installed repository state against the contract.

This is the interactive command line front end. The same checks are available to
libzypp as a repoverification plugin (see ``suse_distro_blockchain.repoverify``
and ``plugin/suse-distro-check``), which is what enforces them during a refresh.

The command line tool only inspects the already cached metadata below
``/var/cache/zypp/raw``; it does not refresh anything.
"""

import argparse
import glob
import os
import re
import sys

from iniparse import INIConfig
from termcolor import colored

try:
    from . import metadata
    from .metadata import OK, REJECT
except ImportError:  # pragma: nocover - direct execution from a source checkout
    import metadata
    from metadata import OK, REJECT


# The command line tool reports every check and keeps the historical exit
# behaviour: a critical issue, a rejected attestation or a build that is no
# longer current fail.
CLI_POLICY = {
    "unmanaged": "allow",
    "registered": "warn",
    "critical_issues": "reject",
    "rpc_error": "reject",
    "current_build": "reject",
    "kind": "warn",
    "signed": "ignore",
    "min_attestation": "outstanding",
}


def repo_attr_defaults():
    return {
        "enabled": 0,
        "priority": 99,
        "autorefresh": 1,
        "type": "rpm-md",
        "metadata_expire": 900,
    }


def find_repomd(repo_file, attrs):
    """Return the cached repomd.xml path of an rpm-md repository, else None."""
    if attrs.get("type", "rpm-md") != "rpm-md":
        return None
    path = re.sub(r".*/", "", repo_file)
    path = re.sub(r"\.repo$", "", path)
    path = re.sub(r"^\.", "_", path)
    rpmmd = "/var/cache/zypp/raw/" + re.sub(r"[/]", "_", path)
    return rpmmd + "/repodata/repomd.xml"


def iter_repos(aliases):
    """Yield ``(repo_file, alias, attrs)`` for repositories in repos.d.

    A requested alias matches when it is a substring of the configured alias or
    vice versa, so ``suse-distro-check oss`` also picks up ``repo-oss``.
    """
    wanted = list(aliases)
    for reposdir in ("/etc/zypp/repos.d",):
        if not os.path.isdir(reposdir):
            continue
        for reponame in sorted(glob.glob("%s/*.repo" % reposdir)):
            repocfg = INIConfig(open(reponame))
            for alias in repocfg:
                if wanted and not any(w in alias or alias in w for w in wanted):
                    continue
                attrs = repo_attr_defaults()
                for key in repocfg[alias]:
                    attrs[key] = repocfg[alias][key]
                yield reponame, alias, attrs


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="suse-distro-check",
        description="Validate your repository state via the blockchain.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "aliases",
        nargs="*",
        help="aliases of repositories as defined in the zypp repo files (default: all)",
    )
    parser.add_argument("--conf", default=None,
                        help=f"config file (default: {metadata.DEFAULT_CONF})")
    parser.add_argument("--network", help="network section to use instead of [main]")
    parser.add_argument("--contract", help="contract address override")
    parser.add_argument("--timeout", type=float, default=10.0,
                        help="JSON-RPC timeout in seconds")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="also show successful checks")
    args = parser.parse_args(argv)

    conf = metadata.load_conf(args.conf or metadata.default_conf_path())

    base_policy = metadata.resolve_policy(conf, "")
    if args.network:
        base_policy.values["network"] = args.network
    net = metadata.resolve_network(conf, base_policy)
    contract_addr = args.contract or net.get("contract")

    print(f"Reaching out to {net.get('http_provider')}")
    try:
        w3 = metadata.connect_provider(net.get("http_provider"), net.get("chainid"), args.timeout)
    except Exception as exc:
        print(colored(f"ERROR: {exc}", "red"))
        return 1

    print(f"Used chain ID: {w3.eth.chain_id}, @block: {w3.eth.block_number}, contract: {contract_addr}")
    try:
        contract = metadata.contract_at(w3, contract_addr)
    except Exception as exc:
        print(colored(f"ERROR: {exc}", "red"))
        return 1

    overall = OK
    checked = 0
    matched = 0
    for repo_file, alias, attrs in iter_repos(args.aliases):
        matched += 1
        rpmmd = find_repomd(repo_file, attrs)
        if not rpmmd:
            continue
        if not os.path.exists(rpmmd):
            print(f"Warning: skipping {rpmmd}")
            continue

        print(f"\nReading {rpmmd} (alias {alias})")
        try:
            _checksum_type, verification = metadata.read_primary_checksum(rpmmd)
        except Exception as exc:
            print(colored(f"[ERROR] metadata: cannot read primary checksum: {exc}", "red"))
            overall = REJECT
            continue

        policy = metadata.Policy(alias, dict(metadata.DEFAULT_POLICY, **CLI_POLICY), managed=True)
        results = metadata.verify_build(verification, contract, policy)
        for result in results:
            if not args.verbose and result.level == OK:
                continue
            print(colored(str(result), metadata.COLORS[result.level]))
            if metadata.LEVEL_ORDER[result.level] > metadata.LEVEL_ORDER[overall]:
                overall = result.level
        checked += 1

    if args.aliases and not matched:
        print(
            colored(
                f"ERROR: no enabled repository matching {args.aliases} found in /etc/zypp/repos.d",
                "red",
            )
        )
        return 2

    if checked == 0:
        print("No matching rpm-md repository with cached metadata found.")
        return 1

    return 1 if overall == REJECT else 0


if __name__ == "__main__":  # pragma: nocover
    sys.exit(main())
