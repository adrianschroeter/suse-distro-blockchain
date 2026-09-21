# SPDX-License-Identifier: GPL-3.0-or-later
"""End-to-end contract test, run directly with boa.

This is a standalone script, not a unittest, because it needs the boa
development chain. Run it with boa installed:

    python3 tests/test_distro_contract.py

The heavy imports stay inside ``main()`` so that unittest discovery can import
this module on systems without boa.
"""

import os

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

    # security team sets the warn flag
    boa.env.eoa = security_team.address
    contract.set_critical(product_build[0], True)

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

    print("  SUCCESS :)  ")


if __name__ == "__main__":
    main()
