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

# index from git_ref to product for O(1) lookup in add_product_build
git_ref_index: HashMap[String[64], uint256]

# A product may be build in different forms. For example
# a rpm-md tree, an install iso, kvm image or container.
# Each of them need to become validated independend
flag BuildKinds:
    rpmmd
    product
    oci_container

flag Attestation:
    outstanding
    approved
    rejected

struct my_product_build :
    # as given on product create
    product_id: uint256
    kind: uint8
    attestation: Attestation

product_builds: HashMap[String[128], my_product_build]

current_verification: HashMap[String[25], String[128]]

#
# Events
#
# Everything below can already be read with the get_* views, so these exist for
# watchers rather than for the contract itself: without them a monitor has to
# poll every verification hash it knows about, because builds are not
# enumerable on chain and there is no other way to notice a change.
#
# verification is deliberately not indexed. Indexing a string puts only its
# keccak hash in the topic, and readers want the digest itself, which is the
# key the rest of the toolchain joins on.

event ProductAdded:
    product_id: indexed(uint256)
    name: String[16]
    git_ref: String[64]

event BuildRegistered:
    product_id: indexed(uint256)
    kind: indexed(uint8)
    verification: String[128]

event AttestationChanged:
    product_id: indexed(uint256)
    attestation: Attestation
    verification: String[128]

event CriticalFlagChanged:
    product_id: indexed(uint256)
    critical: bool

# build the current_verification key from a product name and a kind.
# The kind is encoded as exactly 3 digits, so different
# (name, kind) pairs can never collide in the concatenated key.
@view
def _build_key(_name: String[16], _kind: uint8) -> String[25]:
    h2: uint8 = _kind // 100
    h: uint8 = (_kind // 10) % 10
    d: uint8 = _kind % 10
    return concat(_name, concat(concat(uint2str(h2), uint2str(h)), uint2str(d)))

#
# Managing the contract and roles
#
@deploy
def __init__(_product_creator: address, _official_validator: address, _security_team: address):
    self.foundation_owner   = msg.sender
    self.product_creator    = _product_creator
    self.official_validator = _official_validator
    self.security_team      = _security_team
    # zero product is currently used for not existing product
    self.next_product       = 1

# NOTE: allowing the address changes to the foundation_owner could be seen as breakage of zero-trust
#       maybe this should require an approval from another party?
@external
def set_product_creator(_product_creator: address):
    # Only foundation owner is able to change roles
    assert msg.sender == self.foundation_owner
    self.product_creator = _product_creator

@external
def set_official_validator(_official_validator: address):
    # Only foundation owner is able to change roles
    assert msg.sender == self.foundation_owner
    self.official_validator = _official_validator

@external
def set_security_team(_security_team: address):
    # Only foundation owner is able to change roles
    assert msg.sender == self.foundation_owner
    self.security_team = _security_team

#
# Register new products and builds
#
@external
def add_product(name: String[16], git_ref: String[64]) -> uint256:
    # Only product creator is allowed to add a new product
    assert msg.sender == self.product_creator
    # we have not reached our limit yet
    assert self.next_product < max_value(uint256)
    # add the product
    current_product: uint256 = self.next_product
    self.products[current_product].name = name
    self.products[current_product].git_ref = git_ref
    self.products[current_product].known_critical_issues = False
    self.git_ref_index[git_ref] = current_product
    self.next_product += 1
    log ProductAdded(product_id=current_product, name=name, git_ref=git_ref)
    return current_product

@external
def add_product_build(git_ref: String[64], kind: uint8, verification: String[128]):
    # Only product creator is allowed to add a new product
    assert msg.sender == self.product_creator

    # build is not yet registered
    assert self.product_builds[verification].product_id == 0

    # find the product via the git_ref index
    product_id: uint256 = self.git_ref_index[git_ref]
    # we found a product now
    assert product_id != 0

    self.product_builds[verification].product_id = product_id
    # set current verification
    self.current_verification[self._build_key(self.products[product_id].name, kind)] = verification

    self.product_builds[verification].kind = kind
    self.product_builds[verification].attestation = Attestation.outstanding

    log BuildRegistered(product_id=product_id, kind=kind, verification=verification)

#
# Modify registered products
#
@external
def set_critical(product_id: uint256, critical: bool):
    # TEMPORARY superuser override: the foundation_owner may also flag products
    # in addition to the security_team. Remove this override once the role
    # separation between security_team and foundation_owner is proven in production.
    assert msg.sender == self.security_team or msg.sender == self.foundation_owner
    # only existing products can be flagged
    assert product_id > 0
    assert product_id < self.next_product
    self.products[product_id].known_critical_issues = critical
    log CriticalFlagChanged(product_id=product_id, critical=critical)


@external
def approve_attestation(verification: String[128]):
    # We have currently just a single official validator
    # TEMPORARY superuser override: the foundation_owner may also approve.
    # Remove this override once role separation is proven in production.
    assert msg.sender == self.official_validator or msg.sender == self.foundation_owner
    # only registered builds can be attested
    assert self.product_builds[verification].product_id != 0
    self.product_builds[verification].attestation = Attestation.approved
    log AttestationChanged(product_id=self.product_builds[verification].product_id,
                           attestation=Attestation.approved,
                           verification=verification)

@external
def reject_attestation(verification: String[128]):
    # We have currently just a single official validator
    # TEMPORARY superuser override: the foundation_owner may also reject.
    # Remove this override once the role separation is proven in production.
    assert msg.sender == self.official_validator or msg.sender == self.foundation_owner
    # only registered builds can be attested
    assert self.product_builds[verification].product_id != 0
    self.product_builds[verification].attestation = Attestation.rejected
    log AttestationChanged(product_id=self.product_builds[verification].product_id,
                           attestation=Attestation.rejected,
                           verification=verification)

#
# Read-Only operations for everybody
#
@view
@external
def get_product(product_id: uint256) -> my_product:
    return self.products[product_id]

@view
@external
def get_product_build(verification: String[128]) -> my_product_build:
    return self.product_builds[verification]

@view
@external
def current_product_build(name: String[16], kind: uint8) -> String[128]:
    return self.current_verification[self._build_key(name, kind)]

@view
@external
def get_product_counter() -> uint256:
    return self.next_product - 1

