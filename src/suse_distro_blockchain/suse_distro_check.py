#!/usr/bin/python3

from web3 import Web3, EthereumTesterProvider
from iniparse import INIConfig
from optparse import OptionParser
from typing import List
from termcolor import colored

config_file = "/etc/suse-distro-check.conf"

cfg = INIConfig(open(config_file))
network='main' # not a network, but our starting point in config file. It defines the network to be used.
provider_url=''
provider=None
chainid=0
contract_address="0x0"
for alias in cfg:
    if network != alias:
        continue
    for k in cfg[alias]:
        if alias == 'main' and k == 'network':
            network = cfg[alias][k]
        if k == 'http_provider':
            provider_url = cfg[alias][k]
        if k == 'chainid':
            chainid = int(cfg[alias][k])
        if k == 'contract':
            contract_address = Web3.to_checksum_address(cfg[alias][k])

provider = Web3.HTTPProvider(provider_url)

print(f"Reaching out to {provider_url}")
w3 = Web3(provider)

if not w3.is_connected():
    print("We have no contact to our local blockchain provider")
    exit(1)

print(f"Used chain ID: {w3.eth.chain_id}, @block: {w3.eth.block_number}, contract: {contract_address}")

if w3.eth.chain_id != chainid:
    print(f"Wrong chain ID: {w3.eth.chain_id} and we expect {chainid}")
    exit(1)

if w3.eth.syncing:
    print("Ethereum is still syncing, we have no reliable data yet")
    exit(1)

# contract abi, imported from compiler output
abi = [{"stateMutability": "nonpayable", "type": "function", "name": "set_product_creator", "inputs": [{"name": "_product_creator", "type": "address"}], "outputs": []}, {"stateMutability": "nonpayable", "type": "function", "name": "set_official_validator", "inputs": [{"name": "_official_validator", "type": "address"}], "outputs": []}, {"stateMutability": "nonpayable", "type": "function", "name": "set_security_team", "inputs": [{"name": "_security_team", "type": "address"}], "outputs": []}, {"stateMutability": "nonpayable", "type": "function", "name": "add_product", "inputs": [{"name": "name", "type": "string"}, {"name": "git_ref", "type": "string"}], "outputs": [{"name": "", "type": "uint256"}]}, {"stateMutability": "nonpayable", "type": "function", "name": "add_product_build", "inputs": [{"name": "git_ref", "type": "string"}, {"name": "kind", "type": "uint8"}, {"name": "verification", "type": "string"}], "outputs": []}, {"stateMutability": "nonpayable", "type": "function", "name": "set_critical", "inputs": [{"name": "product_id", "type": "uint256"}, {"name": "critical", "type": "bool"}], "outputs": []}, {"stateMutability": "nonpayable", "type": "function", "name": "approve_attestation", "inputs": [{"name": "verification", "type": "string"}], "outputs": []}, {"stateMutability": "nonpayable", "type": "function", "name": "reject_attestation", "inputs": [{"name": "verification", "type": "string"}], "outputs": []}, {"stateMutability": "view", "type": "function", "name": "get_product", "inputs": [{"name": "product_id", "type": "uint256"}], "outputs": [{"name": "", "type": "tuple", "components": [{"name": "name", "type": "string"}, {"name": "git_ref", "type": "string"}, {"name": "known_critical_issues", "type": "bool"}]}]}, {"stateMutability": "view", "type": "function", "name": "get_product_build", "inputs": [{"name": "verification", "type": "string"}], "outputs": [{"name": "", "type": "tuple", "components": [{"name": "product_id", "type": "uint256"}, {"name": "kind", "type": "uint8"}, {"name": "attestation", "type": "uint256"}]}]}, {"stateMutability": "view", "type": "function", "name": "current_product_build", "inputs": [{"name": "name", "type": "string"}, {"name": "kind", "type": "uint8"}], "outputs": [{"name": "", "type": "string"}]}, {"stateMutability": "view", "type": "function", "name": "get_product_counter", "inputs": [], "outputs": [{"name": "", "type": "uint256"}]}, {"stateMutability": "view", "type": "function", "name": "foundation_owner", "inputs": [], "outputs": [{"name": "", "type": "address"}]}, {"stateMutability": "view", "type": "function", "name": "product_creator", "inputs": [], "outputs": [{"name": "", "type": "address"}]}, {"stateMutability": "view", "type": "function", "name": "official_validator", "inputs": [], "outputs": [{"name": "", "type": "address"}]}, {"stateMutability": "view", "type": "function", "name": "security_team", "inputs": [], "outputs": [{"name": "", "type": "address"}]}, {"stateMutability": "view", "type": "function", "name": "next_product", "inputs": [], "outputs": [{"name": "", "type": "uint256"}]}, {"stateMutability": "nonpayable", "type": "constructor", "inputs": [{"name": "_product_creator", "type": "address"}, {"name": "_official_validator", "type": "address"}, {"name": "_security_team", "type": "address"}], "outputs": []}]

contract = w3.eth.contract(address=contract_address, abi=abi)

def main(argv: List[str] = None) -> None:
    """
    Run the local check
    """

    from xml.dom.minidom import parse, parseString

    import glob
    import re
    import os
    import argparse

    parser = argparse.ArgumentParser(
        description="Validate you repository via the blockchain.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "aliases",
        nargs="+",
        help="The alias of a repository to be checked as defined in zypp repo file",
    )
    args = parser.parse_args(argv)

    repos = []
    reposdirs = [ "/etc/zypp/repos.d" ]
    exit_code = 0
    matched_aliases = []
    for reposdir in reposdirs:
      if not os.path.isdir(reposdir):
        continue
      for reponame in sorted(glob.glob('%s/*.repo' % reposdir)):
        repocfg = INIConfig(open(reponame))

        for alias in repocfg:
            if len(args.aliases) == 0:
                continue
            if not any(requested in alias or alias in requested for requested in args.aliases):
                continue
            matched_aliases.append(alias)

            repoattr = {'enabled': 0, 'priority': 99, 'autorefresh': 1, 'type': 'rpm-md', 'metadata_expire': 900}
            for k in repocfg[alias]:
                repoattr[k] = repocfg[alias][k]
            if repoattr['type'] == 'rpm-md':
                path = re.sub(r'.*/', '', reponame)
                path = re.sub(r'\.repo$', '', path)
                path = re.sub(r'^\.', '_', path)
                rpmmd = "/var/cache/zypp/raw/" + re.sub(r'[/]', '_', path)
                rpmmd += "/repodata/repomd.xml"

                if not os.path.exists(rpmmd):
                    print(f"Warning: skipping {rpmmd}")
                    exit_code = exit_code or 2
                    continue

                print(f"Reading {rpmmd}")
                xml = parse(rpmmd)

                for data in xml.getElementsByTagName("data"):
                    if data.getAttribute("type") != "primary":
                        continue
                    cksum = data.getElementsByTagName("checksum")[0]
                    cksum_type = cksum.getAttribute("type")
                    if cksum_type != "sha256" and cksum_type != "sha512":
                        print(f"Warning: skipping {rpmmd}, not supported checksum type")
                        exit_code = exit_code or 2
                        continue
                    verification = cksum.firstChild.nodeValue

                    # We have the checksum of our primary file, now ask the blockchain
                    try:
                        build = contract.functions.get_product_build(verification).call()
                    except Exception:
                        print(f"Warning: repo not registered in the blockchain with verification id {verification}")
                        exit_code = exit_code or 2
                        continue
                    # we get always an empty product atm when it is not matching
                    if build[0] == 0:
                        print(f"Warning: repo not registered in the blockchain with id {verification}")
                        exit_code = exit_code or 2
                        continue

                    product = contract.functions.get_product(build[0]).call()

                    BUILD_KIND_NAMES = {1: "rpmmd", 2: "product", 4: "oci_container"}
                    ATTESTATION_TEXT = {
                        1: ("outstanding", "yellow", "Build not yet verified by the official validator."),
                        2: ("approved", "green", "Build reproducibility verified by the official validator."),
                        4: ("rejected", "red", "Build reproducibility check REJECTED by the official validator."),
                    }

                    print()
                    print(colored("Repository hash found in blockchain contract.", color="green", attrs=["bold"]))
                    print()
                    print(f"  Product name       : {product[0]}")
                    print(f"  Source commit      : {product[1]}")

                    # Digest of the empty string, independent of the chosen hash
                    # algorithm - a strong hint the git_ref is bogus/not a real commit.
                    EMPTY_STRING_DIGESTS = {
                        "MD5": "d41d8cd98f00b204e9800998ecf8427e",
                        "SHA-1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                        "SHA-256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    }
                    if len(product[1]) < 64:
                        print(
                            colored(
                                f"  WARNING: Source commit is only {len(product[1])} hex chars, "
                                "shorter than a SHA-256 checksum (64)",
                                color="yellow",
                            )
                        )
                    for algo, digest in EMPTY_STRING_DIGESTS.items():
                        if len(product[1]) == len(digest) and product[1].lower() == digest:
                            print(
                                colored(
                                    f"  WARNING: Source commit equals the {algo} digest of the empty string",
                                    color="yellow",
                                )
                            )

                    print(f"  Build kind         : {BUILD_KIND_NAMES.get(build[1], f'unknown ({build[1]})')}")
                    print(f"  Build verification : {verification}")
                    print()

                    if product[2]:
                        print(colored("  Security level     : CRITICAL - known security issues reported", color="red", attrs=["bold"]))
                        exit_code = 1
                    else:
                        print(colored("  Security level     : OK - no known critical security issues", color="green"))

                    att_state, att_color, att_detail = ATTESTATION_TEXT.get(
                        build[2], ("invalid", "red", "Unexpected attestation value in contract.")
                    )
                    print(colored(f"  Rebuild validator  : {att_state.upper()}", color=att_color, attrs=["bold"]))
                    print(f"                       {att_detail}")
                    if build[2] == 4:
                        exit_code = 1

                    print()
                    current_verification = contract.functions.current_product_build(product[0], build[1]).call()
                    if verification == current_verification:
                        print(colored("  Repository cache state matches the registered build in the contract.", color="green"))
                    else:
                        print(colored(f"  WARNING: Contract has a different current build registered: {current_verification}", color="red"))
                        exit_code = 1
    if args.aliases and not matched_aliases:
        print(
            colored(
                f"ERROR: no enabled repository matching {args.aliases} found in {reposdir}",
                color="red",
            )
        )
        exit_code = 2
    return exit_code

if __name__ == "__main__":  # pragma: nocover
    exit(main())


