#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
#
# distro_tool.py - CLI for the openSUSE distro attestation contract.
#
# This tool is safe for public git: it contains NO credentials.
# Key is read at runtime from PRIVATE_KEY env or --key-file.
#
# ABI and bytecode are generated from ape/contracts/distro.vy at build time
# into ape/distro_contract.py (a git-ignored build artifact). Regenerate with:
#   python3 ape/build_contract.py   (or: make contract-build)

import argparse, configparser, hashlib, os, sys
from web3 import Web3
from web3.exceptions import ContractLogicError
from eth_account import Account

try:
    from distro_contract import (
        CONTRACT_ABI,
        CONTRACT_BYTECODE,
        CONTRACT_SOURCE,
        CONTRACT_SHA256,
    )
except ImportError:
    sys.exit(
        "Missing build artifact ape/distro_contract.py.\n"
        "  Generate it first: python3 ape/build_contract.py   (or: make contract-build)"
    )


BUILD_KINDS = {"rpmmd": 1, "product": 2, "oci_container": 4}
ATTESTATION_NAMES = {0: "none", 1: "outstanding", 2: "approved", 4: "rejected"}

_TOOL_DIR = os.path.dirname(os.path.abspath(__file__))
CONF_PATH = os.path.join(_TOOL_DIR, os.pardir, "suse-distro-check.conf")
_CONTRACT_SOURCE_PATH = os.path.join(_TOOL_DIR, CONTRACT_SOURCE)


def check_artifacts_current():
    """Exit with rebuild guidance if the compiled artifact is stale."""
    if not os.path.exists(_CONTRACT_SOURCE_PATH):
        sys.exit(f"Contract source not found: {_CONTRACT_SOURCE_PATH}")
    h = hashlib.sha256()
    with open(_CONTRACT_SOURCE_PATH, "rb") as f:
        while True:
            block = f.read(65536)
            if not block:
                break
            h.update(block)
    if h.hexdigest() != CONTRACT_SHA256:
        sys.exit(
            "Contract source changed since ape/distro_contract.py was built.\n"
            "  Rebuild: python3 ape/build_contract.py   (or: make contract-build)"
        )


def load_conf(path):
    cp = configparser.ConfigParser()
    if os.path.exists(path):
        cp.read(path)
    return {s: dict(cp[s]) for s in cp.sections()}


def parse_kind(v):
    if v in BUILD_KINDS:
        return BUILD_KINDS[v]
    try:
        n = int(v)
    except ValueError:
        sys.exit(f"Invalid kind '{v}'. Use one of {list(BUILD_KINDS)} or 1/2/4.")
    if n not in BUILD_KINDS.values():
        sys.exit(f"Invalid kind {n}. Valid: {sorted(BUILD_KINDS.values())}")
    return n


def is_hex(s):
    return all(c in "0123456789abcdefABCDEF" for c in s)


def validate_git_ref(r):
    if not is_hex(r) or len(r) not in (40, 64):
        sys.exit("git_ref must be hex sha1 (40) or sha256 (64).")
    return r


MAX_VERIFICATION_LEN = 128  # fits sha512 (128 hex chars)


def validate_verification(v):
    if not is_hex(v) or not (0 < len(v) <= MAX_VERIFICATION_LEN):
        sys.exit(
            f"verification must be 1-{MAX_VERIFICATION_LEN} hex chars "
            "(sha512 = 128, sha256 = 64)."
        )
    return v


_TESTER = None
# Public eth-tester test key (account 0 of eth-tester/anvil). Used ONLY by
# --network tester for local development. Never holds real funds.
_DEV_KEY = "0x4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d"


def _fund_tester(w3, address):
    """Ensure the tester network account has a balance."""
    if w3.eth.get_balance(address) > 0:
        return
    tester = w3.provider.ethereum_tester
    src = tester.get_accounts()[0]
    tester.send_transaction({
        "from": src, "to": address, "value": 200 * 10**18,
        "gas": 30000, "gas_price": w3.eth.gas_price,
    })


def get_signer(w3, args):
    """Return the signer account. On the tester network a fresh account is
    created and funded automatically when no key is provided."""
    key = os.environ.get("PRIVATE_KEY")
    if not key and args.key_file:
        key = open(args.key_file).read().strip()
    if not key and args.network == "tester":
        key = _DEV_KEY
    if not key:
        return None
    key = key if key.startswith("0x") else "0x" + key
    acct = Account.from_key(key)
    if _TESTER is not None:
        _fund_tester(w3, acct.address)
    return acct


def connect_web3(args):
    global _TESTER
    if args.network == "tester":
        from eth_tester import EthereumTester
        from web3.providers.eth_tester import EthereumTesterProvider
        tester = EthereumTester()
        _TESTER = tester
        w3 = Web3(EthereumTesterProvider(tester))
        return w3, tester

    presets = load_conf(args.conf)
    net = presets.get(args.network, {})
    url = args.provider or os.environ.get("HTTP_PROVIDER_URL") or net.get("http_provider")
    if not url:
        sys.exit(f"No provider for network '{args.network}'. Use --provider or fill suse-distro-check.conf.")

    w3 = Web3(Web3.HTTPProvider(url))
    if not w3.is_connected():
        sys.exit(f"Cannot connect to {url}")
    if w3.eth.syncing:
        sys.exit("Node still syncing.")

    expected = args.chain_id or os.environ.get("CHAIN_ID") or net.get("chainid")
    if expected and int(expected) != w3.eth.chain_id:
        sys.exit(f"Wrong chain: got {w3.eth.chain_id}, expected {expected}")
    return w3, None


def get_contract_addr(w3, args):
    addr = args.contract or os.environ.get("CONTRACT_ADDRESS")
    if not addr:
        presets = load_conf(args.conf)
        addr = presets.get(args.network, {}).get("contract")
    if not addr:
        sys.exit("No contract address (use --contract / CONTRACT_ADDRESS / conf).")
    if not Web3.is_address(addr):
        sys.exit(f"Invalid address: {addr}")
    return w3.eth.contract(address=Web3.to_checksum_address(addr), abi=CONTRACT_ABI)


def send_tx(w3, acct, fn_obj, gas=None):
    if acct is None:
        sys.exit("No signing key. Set PRIVATE_KEY or --key-file.")
    sender = acct.address
    nonce = w3.eth.get_transaction_count(sender, "pending")
    if gas:
        est_gas = gas
    else:
        try:
            est_gas = int(fn_obj.estimate_gas({"from": sender}) * 1.2) + 1
        except ContractLogicError as e:
            reason = str(e).strip() or "execution reverted"
            sys.exit(
                f"Transaction would revert: {reason}\n"
                f"  function : {getattr(fn_obj, 'fn_name', '?')}\n"
                f"  from     : {sender}\n"
                "  The signing account may be missing the required role.\n"
                "  Check roles with the 'roles' command (or pass --gas to force)."
            )
        except Exception as e:
            print(f"Warning: gas estimation failed ({e}), using 200000")
            est_gas = 200000
    tx = fn_obj.build_transaction({
        "from": sender, "nonce": nonce, "chainId": w3.eth.chain_id, "gas": est_gas,
    })
    signed = acct.sign_transaction(tx)
    raw = getattr(signed, "raw_transaction", None) or getattr(signed, "rawTransaction")
    txh = w3.eth.send_raw_transaction(raw)
    rc = w3.eth.wait_for_transaction_receipt(txh)
    gas_used = rc.get("gasUsed")
    status = rc.get("status")
    print(f"tx     : {txh.hex()}")
    print(f"gas    : {gas_used}")
    print(f"status : {'OK' if status == 1 else 'FAILED'}")
    return rc


def deploy_contract(w3, acct, builder, validator, security):
    w3c = w3.eth.contract(abi=CONTRACT_ABI, bytecode=CONTRACT_BYTECODE)
    fn = w3c.constructor(builder, validator, security)
    rc = send_tx(w3, acct, fn)
    if rc.get("status") == 1:
        print(f"deployed: {rc.get('contractAddress')}")
    return rc


def prompt(args, msg):
    if args.yes or args.network == "tester":
        return True
    return input(f"{msg} [y/N] ").strip().lower() in ("y", "yes")


# -- read-only commands -------------------------------------------------------

def do_roles(w3, c, args):
    print(f"foundation_owner : {c.functions.foundation_owner().call()}")
    print(f"product_creator  : {c.functions.product_creator().call()}")
    print(f"official_validator: {c.functions.official_validator().call()}")
    print(f"security_team    : {c.functions.security_team().call()}")
    print(f"next_product     : {c.functions.next_product().call()}")


def do_counter(w3, c, args):
    print(c.functions.get_product_counter().call())


def do_show(w3, c, args):
    p = c.functions.get_product(args.product_id).call()
    print(f"id      : {args.product_id}")
    print(f"name    : {p[0]}")
    print(f"git_ref : {p[1]}")
    print(f"critical: {p[2]}")


def do_build(w3, c, args):
    b = c.functions.get_product_build(args.verification).call()
    print(f"product_id  : {b[0]}")
    print(f"kind        : {b[1]}")
    print(f"attestation : {ATTESTATION_NAMES.get(b[2], b[2])}")


def do_current(w3, c, args):
    kind = parse_kind(args.kind)
    ver = c.functions.current_product_build(args.name, kind).call()
    print(f"verification: {ver or '(none)'}")


# -- write commands -----------------------------------------------------------

def do_deploy(w3, _c, args):
    for lbl, val in [("builder", args.builder), ("validator", args.validator), ("security", args.security)]:
        if not Web3.is_address(val):
            sys.exit(f"Invalid {lbl} address: {val}")
    if not prompt(args, "Deploy new contract?"):
        sys.exit("aborted")
    acct = get_signer(w3, args)
    if acct is None:
        sys.exit("No signing key for deploy. Set PRIVATE_KEY or --key-file.")
    deploy_contract(w3, acct, args.builder, args.validator, args.security)


def do_add_product(w3, c, args):
    name = args.name
    if not (0 < len(name) <= 16):
        sys.exit("name must be 1-16 chars.")
    git_ref = validate_git_ref(args.git_ref)
    if not prompt(args, f"add_product(name={name!r}, git_ref={git_ref})"):
        sys.exit("aborted")
    acct = get_signer(w3, args)
    send_tx(w3, acct, c.functions.add_product(name, git_ref))


def do_add_build(w3, c, args):
    git_ref = validate_git_ref(args.git_ref)
    kind = parse_kind(args.kind)
    ver = validate_verification(args.verification)
    if not prompt(args, f"add_product_build(ref={git_ref}, kind={kind}, ver={ver})"):
        sys.exit("aborted")
    acct = get_signer(w3, args)
    send_tx(w3, acct, c.functions.add_product_build(git_ref, kind, ver))


def do_approve(w3, c, args):
    ver = validate_verification(args.verification)
    if not prompt(args, f"approve_attestation({ver})"):
        sys.exit("aborted")
    acct = get_signer(w3, args)
    send_tx(w3, acct, c.functions.approve_attestation(ver))


def do_reject(w3, c, args):
    ver = validate_verification(args.verification)
    if not prompt(args, f"reject_attestation({ver})"):
        sys.exit("aborted")
    acct = get_signer(w3, args)
    send_tx(w3, acct, c.functions.reject_attestation(ver))


def do_set_critical(w3, c, args):
    flag = args.critical.lower() in ("1", "true", "yes", "on")
    if not prompt(args, f"set_critical(id={args.product_id}, critical={flag})"):
        sys.exit("aborted")
    acct = get_signer(w3, args)
    send_tx(w3, acct, c.functions.set_critical(args.product_id, flag))


# -- CLI parser ---------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        prog="distro_tool.py",
        description="openSUSE distro attestation contract CLI.",
    )
    p.add_argument("--network", default="sepolia")
    p.add_argument("--conf", default=CONF_PATH)
    p.add_argument("--provider")
    p.add_argument("--chain-id", type=int)
    p.add_argument("--contract")
    p.add_argument("--key-file", help="file with hex private key")
    p.add_argument("--gas", type=int)
    p.add_argument("-y", "--yes", action="store_true")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("deploy")
    s.add_argument("--builder", required=True)
    s.add_argument("--validator", required=True)
    s.add_argument("--security", required=True)
    s.set_defaults(func=do_deploy)

    s = sub.add_parser("add-product")
    s.add_argument("name")
    s.add_argument("git_ref")
    s.set_defaults(func=do_add_product)

    s = sub.add_parser("add-build")
    s.add_argument("git_ref")
    s.add_argument("kind", help="rpmmd|product|oci_container or 1|2|4")
    s.add_argument("verification")
    s.set_defaults(func=do_add_build)

    s = sub.add_parser("approve")
    s.add_argument("verification")
    s.set_defaults(func=do_approve)

    s = sub.add_parser("reject")
    s.add_argument("verification")
    s.set_defaults(func=do_reject)

    s = sub.add_parser("set-critical")
    s.add_argument("product_id", type=int)
    s.add_argument("critical", help="true/false/1/0")
    s.set_defaults(func=do_set_critical)

    s = sub.add_parser("roles")
    s.set_defaults(func=do_roles)

    s = sub.add_parser("counter")
    s.set_defaults(func=do_counter)

    s = sub.add_parser("show")
    s.add_argument("product_id", type=int)
    s.set_defaults(func=do_show)

    s = sub.add_parser("build")
    s.add_argument("verification")
    s.set_defaults(func=do_build)

    s = sub.add_parser("current")
    s.add_argument("name")
    s.add_argument("kind")
    s.set_defaults(func=do_current)
    return p


def main():
    args = build_parser().parse_args()
    check_artifacts_current()
    w3, tester = connect_web3(args)

    if args.command == "deploy":
        do_deploy(w3, None, args)
        return

    c = get_contract_addr(w3, args)
    args.func(w3, c, args)


if __name__ == "__main__":
    main()
