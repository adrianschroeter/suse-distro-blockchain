# absolute minimal contract test case

import boa

from eth_account import Account
contract = boa.load('ape/contracts/distro.vy', boa.env.eoa, boa.env.eoa, boa.env.eoa)

git_sha="8a645f5782b507202c75ee7fbeaf7bb21d34dd5c2eda4118bb76a31a39226e30"
primary_sha="562a8a6891053541a9cb4d6b252e0cdde4b9da98fc99e87aaeac3ecccb05b91755a2ffcdfd3cdd3e3a55fc5deb96157be4565f4e1c4eb177f7b08075a15e2b70"
product_name="example-1"
build_kind=1

print("Setting balance...")
boa.env.set_balance(boa.env.eoa, 1000 * 10**18)
product_id = contract.add_product(product_name, git_sha)
print(f"Created Product with ID {product_id}")
contract.add_product_build(git_sha, build_kind, primary_sha)
print(f"Created Product Build")
product_build = contract.get_product_build(primary_sha)
if product_build[0] != 1 or product_build[1] != 1:
    print("Product Build not found!")
    exit(1)
print("Found Product Build")
product = contract.get_product(product_build[0])
if product[0] != product_name or product[1] != git_sha:
    print("Product Build not found!")
    exit(1)
print("Found Product")
verification = contract.current_product_build(product_name, build_kind)
if verification != primary_sha:
    print("Is not current verification!")
    exit(1)
print("Product is verified to be current")

print("  SUCCESS :)  ")
