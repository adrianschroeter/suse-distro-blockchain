# @version ^0.4.0

# The board of openSUSE community. Or the leadership team of SUSE.com.
foundation_owner: public(address)

# Empower an OBS admin to create products initially
product_creator: public(address)

# Empower an entity to become the official validator
official_validator: public(address)

# Allow to revoke a product build
security_team: public(address)

# count products to get an ID as identifier
next_product: public(uint256)

# A product entry, each iteration is a new product.
struct my_product :
    # short name including the branch
    # For example "SLFO-1.1" for the managed code stream
    name: String[16]
    # defines the used source hash.
    # no git url here, just the hash
    git_ref: String[64]
    # some marker to invalidate the build
    known_critical_issues: bool
    # reached_end_of_life: bool

products: public(HashMap[uint256, my_product])

# A product may be build in different forms. For example
# an rpm-md tree, an install iso, kvm image or container.
# Each of them need to become validated independend
struct my_product_build :
    # as given on product create
    product_id: uint256
    # 0=rpm-md | 1=install.iso | ....
    kind: int128
#    verification: String[64]
    verified: bool

product_builds: public(HashMap[String[64], my_product_build])

# Attestation for a product can be done by anyone
struct my_product_build_attestation :
    # as given on product create
    product_build_id: uint256
    verificator: address

attestations: public(HashMap[uint256, my_product_build_attestation])

@deploy
def __init__(_product_creator: address, _official_validator: address, _security_team: address):
    self.foundation_owner   = msg.sender
    self.product_creator    = _product_creator
    self.official_validator = _official_validator
    self.security_team      = _security_team
    self.next_product       = 0


@external
def add_product(name: String[16], git_ref: String[64]) -> uint256:
    # Only product creator is allowed to add a new product
    assert msg.sender == self.product_creator
    # we have not reached our limit yet
#    assert uint256(self.product_count + 1)
    # add the product
    current_product: uint256 = self.next_product
    self.products[current_product].name = name
    self.products[current_product].git_ref = git_ref
    self.products[current_product].known_critical_issues = False
    self.next_product += 1
    return current_product

@external
def add_product_build(git_ref: String[64], kind: int128, verification: String[64]):
    # Only product creator is allowed to add a new product
    assert msg.sender == self.product_creator
    # we have not reached our limit yet
#    assert uint256(self.product_count_build + 1)

    # find the product
    for id: uint256 in range(0, 9999):
       if self.products[id].git_ref == git_ref:
          self.product_builds[verification].product_id = id
          
    self.product_builds[verification].kind = kind
#    self.product_builds[verification].verification = verification
    self.product_builds[verification].verified = False

@external
def get_product(product_id: uint256) -> my_product:
    return self.products[product_id]

@external
def get_product_build(verification: String[64]) -> my_product_build:
    return self.product_builds[verification]

@external
def get_product_counter() -> uint256:
    return self.next_product

@external
def set_critical(product_id: uint256, critical: bool):
    assert msg.sender == self.security_team
    self.products[product_id].known_critical_issues = critical


@external
def add_attestation(verification: String[64]):
    # We have currently just a single official validator
    assert msg.sender == self.official_validator
    self.product_builds[verification].verified = True


