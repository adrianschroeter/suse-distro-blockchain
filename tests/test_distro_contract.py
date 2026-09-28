# SPDX-License-Identifier: GPL-3.0-or-later
"""End-to-end contract test, run directly with boa.

This is a standalone script, not a unittest, because it needs the boa
development chain. Run it with boa installed:

    python3 tests/test_distro_contract.py

The heavy imports stay inside ``main()`` so that unittest discovery can import
this module on systems without boa.
"""

import os
import re

CONTRACT_SOURCE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               os.pardir, "ape", "contracts", "distro.vy")


def main():
    import boa

    from eth_account import Account

    # static test data of a product build
    git_sha = "8a645f5782b507202c75ee7fbeaf7bb21d34dd5c2eda4118bb76a31a39226e30"
    primary_sha = ("562a8a6891053541a9cb4d6b252e0cdde4b9da98fc99e87aaeac3ecccb05b91755"
                   "a2ffcdfd3cdd3e3a55fc5deb96157be4565f4e1c4eb177f7b08075a15e2b70")
    product_name = "example-1"
    build_kind = 1
    # SecurityLevel flag values; vyper encodes a flag as a bit shift
    NOT_SET, LOW, MODERATE, IMPORTANT, CRITICAL = 1, 2, 4, 8, 16
    # interface level this tool was written for, see compatibility_level in the
    # contract and CONTRACT_COMPATIBILITY / COMPATIBILITY_LEVEL in the clients
    COMPATIBILITY_LEVEL = 1

    # our roles
    foundation_owner = Account.create('KEYSMASH FJAFJKLDSKF7JKFDJ 1530')
    validator = Account.create('KEYSMASH AJFFJKLDSKF7JKFDJ 1531')
    security_team = Account.create('KEYSMASH AAAFJKLDSKF7JKFDJ 1532')
    product_creator = Account.create('KEYSMASH BBBFJKLDSKF7JKFDJ 1533')
    random_guy = Account.create('KEYSMASH FFFFJKLDSKF7JKFDJ 1534')

    # deploy our contract
    boa.env.eoa = foundation_owner.address
    contract = boa.load(CONTRACT_SOURCE, product_creator.address, validator.address,
                        security_team.address)

    # the contract has to tell the tooling which interface it implements
    if contract.compatibility_level() != COMPATIBILITY_LEVEL:
        print("Unexpected compatibility level")
        raise SystemExit(1)
    print("Contract compatibility level is 1")

    #
    # Register a product build
    #
    boa.env.eoa = product_creator.address
    print("Setting balance...")
    boa.env.set_balance(boa.env.eoa, 1000 * 10**18)
    product_id = contract.add_product(product_name, git_sha)
    print(f"Created Product with ID {product_id}")
    contract.add_product_build(git_sha, build_kind, primary_sha)
    print("Created Product Build")

    #
    # The verification tool would do the following
    #
    boa.env.eoa = random_guy.address
    print("Setting balance...")
    product_build = contract.get_product_build(primary_sha)
    if product_build[0] != 1 or product_build[1] != 1:
        print("Product Build not found!")
        raise SystemExit(1)
    print("Found Product Build")
    product = contract.get_product(product_build[0])
    if product[0] != product_name or product[1] != git_sha:
        print("Product Build not found!")
        raise SystemExit(1)
    print("Found Product")
    verification = contract.current_product_build(product_name, build_kind)
    if verification != primary_sha:
        print("Is not current verification!")
        raise SystemExit(1)
    print("Product is verified to be current")

    # a new build starts without any reported security issue
    if contract.get_product_build(primary_sha)[3] != NOT_SET:
        print("A new build does not start at not_set")
        raise SystemExit(1)
    print("Security level of a new build is not_set")

    # a report is made for one build and covers every build of the product that
    # was registered before it, so the test needs a few builds to look at
    other_builds = ["b" * 128, "c" * 128, "d" * 128, "e" * 128]
    boa.env.eoa = product_creator.address
    for verification_of_build in other_builds:
        contract.add_product_build(git_sha, build_kind, verification_of_build)
    build_a, build_b, build_c, build_d, build_e = (
        [primary_sha] + other_builds)

    def levels(*expected):
        """The level in effect for each build, oldest first."""
        got = [contract.get_product_build(v)[3] for v in
               (build_a, build_b, build_c, build_d, build_e)]
        if got != list(expected):
            print(f"Levels are {got}, expected {list(expected)}")
            raise SystemExit(1)

    # a critical report on the second build also covers the first one
    boa.env.eoa = security_team.address
    contract.set_security_level(build_b, CRITICAL)
    levels(CRITICAL, CRITICAL, NOT_SET, NOT_SET, NOT_SET)
    print("A report covers the builds registered before it")

    # a later build can carry a lower level without touching the earlier ones
    contract.set_security_level(build_d, LOW)
    levels(CRITICAL, CRITICAL, LOW, LOW, NOT_SET)
    print("A later report starts a new range")

    # a report about an already reported build replaces it, also when it is
    # made out of order, i.e. after a report about a newer build
    contract.set_security_level(build_b, MODERATE)
    levels(MODERATE, MODERATE, LOW, LOW, NOT_SET)
    print("An out of order report updates its own build")

    # and not_set withdraws the report again
    contract.set_security_level(build_c, NOT_SET)
    levels(MODERATE, MODERATE, NOT_SET, LOW, NOT_SET)
    print("A report can be withdrawn")

    # every level the security team can report
    for level in (LOW, MODERATE, IMPORTANT, CRITICAL):
        contract.set_security_level(build_a, level)
        if contract.get_product_build(build_a)[3] != level:
            print(f"Security level of the oldest build is not {level}")
            raise SystemExit(1)
    contract.set_security_level(build_a, NOT_SET)
    print("Security level can be set to every level")

    # the reports are kept as a history, in the order they were made
    history = contract.product_security(product_id)
    if [m[0] for m in history] != [build_b, build_d, build_c, build_a]:
        print(f"Report history is {[m[0] for m in history]}")
        raise SystemExit(1)
    if [m[1] for m in history] != [MODERATE, LOW, NOT_SET, NOT_SET]:
        print(f"Report levels are {[m[1] for m in history]}")
        raise SystemExit(1)
    print("The report history is readable")

    # reports need a registered build
    try:
        contract.set_security_level("f" * 128, CRITICAL)
    except Exception:
        print("A report for an unknown build is refused")
    else:
        print("A report for an unknown build was accepted")
        raise SystemExit(1)

    # Validator approves
    boa.env.eoa = validator.address
    product_build = contract.get_product_build(primary_sha)
    if product_build[2] != 1:
        print("Attestation is not outstanding")
        raise SystemExit(1)
    contract.reject_attestation(primary_sha)
    product_build = contract.get_product_build(primary_sha)
    if product_build[2] != 4:
        print("Attestation is not rejected")
        raise SystemExit(1)
    contract.approve_attestation(primary_sha)
    product_build = contract.get_product_build(primary_sha)
    if product_build[2] != 2:
        print("Attestation is not approved")
        raise SystemExit(1)

    # test address changes, take away permissions for everyone
    boa.env.eoa = foundation_owner.address
    contract.set_product_creator(boa.env.eoa)
    contract.set_official_validator(boa.env.eoa)
    contract.set_security_team(boa.env.eoa)

    ### FIXME: add validations that functions are not working when not permitted

    check_report_limit(boa, product_creator, security_team)

    print("  SUCCESS :)  ")


def check_report_limit(boa, product_creator, security_team):
    """A product cannot be flagged on more builds than it keeps reports.

    The limit is a constant of the contract, so this deploys a copy of the very
    same source with a small one instead of registering 256 builds.
    """
    import tempfile

    with open(CONTRACT_SOURCE) as handle:
        source = handle.read()
    # the limit is a constant of the contract, so this deploys a copy of the
    # very same source with a small one instead of registering 256 builds
    declared = re.compile(r"MAX_SECURITY_MARKERS: constant\(uint256\) = \d+")
    if len(declared.findall(source)) != 1:
        raise SystemExit("MAX_SECURITY_MARKERS is not declared exactly once")
    handle = tempfile.NamedTemporaryFile("w", suffix=".vy", delete=False)
    with handle:
        handle.write(declared.sub("MAX_SECURITY_MARKERS: constant(uint256) = 2",
                                  source, count=1))
    if not re.search(r"MAX_SECURITY_MARKERS: constant\(uint256\) = 2\b", open(handle.name).read()):
        raise SystemExit("could not lower MAX_SECURITY_MARKERS for the limit test")
    try:
        boa.env.eoa = product_creator.address
        contract = boa.load(handle.name, product_creator.address,
                            product_creator.address, security_team.address)
        git_ref = "a" * 64
        contract.add_product("limit-test", git_ref)
        builds = [chr(ord("0") + i) * 128 for i in range(3)]
        for build in builds:
            contract.add_product_build(git_ref, 1, build)
        boa.env.eoa = security_team.address
        contract.set_security_level(builds[0], 16)
        contract.set_security_level(builds[1], 16)
        try:
            contract.set_security_level(builds[2], 16)
        except Exception:
            pass
        else:
            raise SystemExit("A report beyond the limit was accepted")
        # the state is unchanged, the build is not quietly reported as clean
        if len(contract.product_security(1)) != 2:
            raise SystemExit("The refused report changed the history")
        if contract.get_product_build(builds[2])[3] != 1:
            raise SystemExit("The refused report changed a level")
        # an already reported build can still be corrected at the limit
        contract.set_security_level(builds[1], 1)
        if contract.get_product_build(builds[1])[3] != 1:
            raise SystemExit("A report could not be corrected at the limit")
        print("The report limit is enforced and stays correct")
    finally:
        os.unlink(handle.name)


if __name__ == "__main__":
    main()
