#!/usr/bin/python3

from web3 import Web3, EthereumTesterProvider
from iniparse import INIConfig
from optparse import OptionParser
from typing import List

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

print(f"Reaching our to {provider_url}")
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
abi = [{"stateMutability": "nonpayable", "type": "function", "name": "add_product", "inputs": [{"name": "name", "type": "string"}, {"name": "git_ref", "type": "string"}], "outputs": [{"name": "", "type": "uint256"}]}, {"stateMutability": "nonpayable", "type": "function", "name": "add_product_build", "inputs": [{"name": "git_ref", "type": "string"}, {"name": "kind", "type": "uint8"}, {"name": "verification", "type": "string"}], "outputs": []}, {"stateMutability": "view", "type": "function", "name": "get_product", "inputs": [{"name": "product_id", "type": "uint256"}], "outputs": [{"name": "", "type": "tuple", "components": [{"name": "name", "type": "string"}, {"name": "git_ref", "type": "string"}, {"name": "known_critical_issues", "type": "bool"}]}]}, {"stateMutability": "view", "type": "function", "name": "get_product_build", "inputs": [{"name": "verification", "type": "string"}], "outputs": [{"name": "", "type": "tuple", "components": [{"name": "product_id", "type": "uint256"}, {"name": "kind", "type": "uint8"}, {"name": "verified", "type": "bool"}]}]}, {"stateMutability": "view", "type": "function", "name": "current_product_build", "inputs": [{"name": "name", "type": "string"}, {"name": "kind", "type": "uint8"}], "outputs": [{"name": "", "type": "string"}]}, {"stateMutability": "view", "type": "function", "name": "get_product_counter", "inputs": [], "outputs": [{"name": "", "type": "uint256"}]}, {"stateMutability": "nonpayable", "type": "function", "name": "set_critical", "inputs": [{"name": "product_id", "type": "uint256"}, {"name": "critical", "type": "bool"}], "outputs": []}, {"stateMutability": "nonpayable", "type": "function", "name": "add_attestation", "inputs": [{"name": "verification", "type": "string"}], "outputs": []}, {"stateMutability": "view", "type": "function", "name": "foundation_owner", "inputs": [], "outputs": [{"name": "", "type": "address"}]}, {"stateMutability": "view", "type": "function", "name": "product_creator", "inputs": [], "outputs": [{"name": "", "type": "address"}]}, {"stateMutability": "view", "type": "function", "name": "official_validator", "inputs": [], "outputs": [{"name": "", "type": "address"}]}, {"stateMutability": "view", "type": "function", "name": "security_team", "inputs": [], "outputs": [{"name": "", "type": "address"}]}, {"stateMutability": "view", "type": "function", "name": "next_product", "inputs": [], "outputs": [{"name": "", "type": "uint256"}]}, {"stateMutability": "nonpayable", "type": "constructor", "inputs": [{"name": "_product_creator", "type": "address"}, {"name": "_official_validator", "type": "address"}, {"name": "_security_team", "type": "address"}], "outputs": []}]



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
    for reposdir in reposdirs:
      if not os.path.isdir(reposdir):
        continue
      for reponame in sorted(glob.glob('%s/*.repo' % reposdir)):
        repocfg = INIConfig(open(reponame))

        for alias in repocfg:
            if len(args.aliases) > 0 and not alias in args.aliases[0]:
                continue

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
                       continue
                   verification = cksum.firstChild.nodeValue

                   # We have the checksum of our primary file, now ask the blockchain
                   try:
                       build = contract.functions.get_product_build(verification).call()
                   except:
                       print(f"Warning: repo not registered in the block chain with verification id {verification}")
                       continue
                   # we get always an empty product atm when it is not matching
                   if build[0] == 0:
                       print(f"Warning: repo not registered in the block chain with id {verification}")
                       continue

                   product = contract.functions.get_product(build[0]).call()
                   
                   print(f"Selected product:         {product[0]}")
                   print(f"Used source SHA-256:      {product[1]}")
                   if build[1] == 0:
                       print("Build Type:               rpm-md")
                   else:
                       print("Build Type:               UNKNOWN")
                   print(f"Critical Security Issues: {product[2]}")
                   print(f"Same Rebuild Attestated:  {build[2]}")

                   print()
                   current_verification = contract.functions.current_product_build(product[0], build[1]).call()
                   if verification == current_verification:
                       print("The contract proofed your repository cache as current state :)")
                   else:
                       print(f"ERROR: The contract has different current state registered: {current_verification}")
                       exit(1)

if __name__ == "__main__":  # pragma: nocover
    main()


