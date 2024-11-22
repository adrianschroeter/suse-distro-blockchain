# absolute minimal contract test case

import boa

from eth_account import Account
contract = boa.load('ape/contracts/distro.vy', boa.env.eoa, boa.env.eoa, boa.env.eoa)
print(contract)
print("Setting balance...")
boa.env.set_balance(boa.env.eoa, 1000 * 10**18)
print("Add Product...")
product_id = contract.add_product("SLFO-16", "0x123")
print(f"Created Product with ID {product_id}")
contract.add_product_build("0x123", 1, "yxc")
print(f"Created Product Build")
product_build = contract.get_product_build("yxc")
if product_build[0] != 1 or product_build[1] != 1:
    print("Product Build not found!")
    exit(1)
print("Found Product Build")
verification = contract.current_product_build("SLFO-16", 1)
if verification != "yxc":
    print("Is not current verification!")
    exit(1)
print("Product is verified to be current")

print("  SUCCESS :)  ")
