# @version ^0.4.0

# SHA-512 ready string for build verification
#type BuildVerificationType = Bytes[128]
# SHA-256 string for git refs
#type GitVerificationType = String[64]

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

products: HashMap[uint256, my_product]

# A product may be build in different forms. For example
# an rpm-md tree, an install iso, kvm image or container.
# Each of them need to become validated independend
flag BuildKinds:
    rpmmd
    product

struct my_product_build :
    # as given on product create
    product_id: uint256
    kind: uint8
    verified: bool

product_builds: HashMap[bytes32, my_product_build]

current_verification: HashMap[String[19], String[128]]

@deploy
def __init__(_product_creator: address, _official_validator: address, _security_team: address):
    self.foundation_owner   = msg.sender
    self.product_creator    = _product_creator
    self.official_validator = _official_validator
    self.security_team      = _security_team
    # zero product is currently used for not existing product
    self.next_product       = 1

@external
def add_product(name: String[16], git_ref: String[64]) -> uint256:
    # Only product creator is allowed to add a new product
    assert msg.sender == self.product_creator or msg.sender == self.foundation_owner
    # we have not reached our limit yet
    assert self.next_product < max_value(uint256)
    # add the product
    current_product: uint256 = self.next_product
    self.products[current_product].name = name
    self.products[current_product].git_ref = git_ref
    self.products[current_product].known_critical_issues = False
    self.next_product += 1
    return current_product

@external
def add_product_build(git_ref: String[64], kind: uint8, verification: String[128]):
    # Only product creator is allowed to add a new product
    assert msg.sender == self.product_creator or msg.sender == self.foundation_owner

    hash: bytes32 = keccak256(verification)

    # build is not yet registered
    assert self.product_builds[hash].product_id == 0

    # find the product
    for product_id: uint256 in range(max_value(uint256)):
       assert product_id < self.next_product

       if self.products[product_id].git_ref == git_ref:
          self.product_builds[hash].product_id = product_id
          cur_hash: String[19] = concat(self.products[product_id].name, uint2str(kind))
          # set current verification
          self.current_verification[cur_hash] = verification
          break

    # we found a product now          
    assert self.product_builds[hash].product_id != 0

    self.product_builds[hash].kind = kind
    self.product_builds[hash].verified = False


@view
@external
def get_product(product_id: uint256) -> my_product:
    return self.products[product_id]

@view
@external
def get_product_build(verification: String[128]) -> my_product_build:
    hash: bytes32 = keccak256(verification)
    return self.product_builds[hash]

@view
@external
def current_product_build(name: String[16], kind: uint8) -> String[128]:
    hash: String[19] = concat(name, uint2str(kind))
    return self.current_verification[hash]

@view
@external
def get_product_counter() -> uint256:
    return self.next_product - 1

@external
def set_critical(product_id: uint256, critical: bool):
    assert msg.sender == self.security_team
    self.products[product_id].known_critical_issues = critical


@external
def add_attestation(verification: String[128]):
    # We have currently just a single official validator
    assert msg.sender == self.official_validator
    hash: bytes32 = keccak256(verification)
    self.product_builds[hash].verified = True


