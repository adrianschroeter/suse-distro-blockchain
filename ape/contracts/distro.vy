# @version ^0.4.3

# SHA-512 ready string for build verification
#type BuildVerificationType = Bytes[128]
# SHA-256 string for git refs
#type GitVerificationType = String[64]

# Interface level of this contract, readable with compatibility_level().
#
# It is bumped on every breaking change of the ABI or the storage layout, e.g.
# when the boolean known_critical_issues became the SecurityLevel flag. The
# tooling compares it with the level it was built for before it reads anything
# else, so a client never misinterprets the on-chain data of a contract it does
# not understand. Deployments without this constant predate the versioning and
# are therefore incompatible with every current tool.
compatibility_level: public(constant(uint256)) = 1

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

# count the registered builds, used to record the registration order of the
# builds of a product
next_build: public(uint256)

# Severity of the security issues known for a build, set by the security team
# for the build where an issue was found. not_set is the zero value, i.e. a
# build starts without any reported issue, and the levels grow with severity.
# The contract only stores and reports the level; which levels invalidate a
# build is decided by the verification policy (max_critical_issues in
# suse-distro-check.conf).
flag SecurityLevel:
    not_set
    low
    moderate
    important
    critical

# A product entry, each iteration is a new product.
struct my_product :
    # short name including the branch
    # For example "Leap-16.1" for the managed code stream
    name: String[16]
    # defines the used source hash.
    # no git url here, just the hash
    git_ref: String[64]
    # reached_end_of_life: bool

# A security report as set_security_level() recorded it: the level stated for
# this exact build, not the level effective for it. product_security() hands
# these out for the CLI to show the history.
struct SecurityMarker:
    verification: String[128]
    level: SecurityLevel

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
    # severity in effect for this build, computed on read from the security
    # reports of the product. Not stored: it is derived from the reports, so
    # that a later report can re-rate the builds registered before it.
    security_level: SecurityLevel

product_builds: HashMap[String[128], my_product_build]

# How many security reports one product keeps. Re-reporting a build that is
# already in the list updates it and costs nothing, so this is the number of
# builds a product can have ever been flagged on, not a cap on how many
# reports can be corrected.
MAX_SECURITY_MARKERS: constant(uint256) = 256

# Registration order of the builds of one product, 0 for "not registered".
# Every product starts counting at 1, so the numbers are only comparable within
# a single product, which is all _effective() needs.
build_sequence: HashMap[String[128], uint256]

# The security level reported for this exact build, the last write wins.
# 0 means "no report at all", which is different from a report of not_set: a
# build that was never flagged consumes no range.
build_level: HashMap[String[128], SecurityLevel]

# One entry per build that was ever reported, in the order the reports were
# made, which is not necessarily the order of the builds: a report about an
# older build can come late. MAX_SECURITY_MARKERS is the history depth per
# product, not a limit on the number of builds.
security_marker_builds: HashMap[uint256, DynArray[String[128], MAX_SECURITY_MARKERS]]

# The build_sequence of the newest report of a product. A build registered
# after it is answered without reading the array, and _effective() picks the
# report with the smallest sequence at or after the build it is asked for, so
# the array itself is never assumed to be sorted.
security_marker_newest_seq: HashMap[uint256, uint256]

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

event SecurityLevelChanged:
    product_id: indexed(uint256)
    level: SecurityLevel
    # the build the report is about, i.e. the end of the affected range
    verification: String[128]

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
    # the first build registered gets the sequence 2, 1 stays unused because 0
    # is the "not registered" marker of build_sequence
    self.next_build         = 1

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

    # remember when this build was registered, so a security report can be
    # resolved to the builds that existed at the time it was made
    self.next_build += 1
    self.build_sequence[verification] = self.next_build

    log BuildRegistered(product_id=product_id, kind=kind, verification=verification)

#
# Modify registered products
#
@external
def set_security_level(verification: String[128], level: SecurityLevel):
    # TEMPORARY superuser override: the foundation_owner may also flag products
    # in addition to the security_team. Remove this override once the role
    # separation between security_team and foundation_owner is proven in production.
    assert msg.sender == self.security_team or msg.sender == self.foundation_owner
    # only registered builds can be reported on
    product_id: uint256 = self.product_builds[verification].product_id
    assert product_id != 0, "unknown build"

    if convert(self.build_level[verification], uint256) == 0:
        # first report about this build: it becomes a range boundary. Appending
        # has to go through the storage path, an appended local copy is dropped.
        assert len(self.security_marker_builds[product_id]) < MAX_SECURITY_MARKERS, "security report limit reached for this product"
        self.security_marker_builds[product_id].append(verification)
    # a report for the newest build carries over to everything registered before
    # it, and re-reporting a build replaces what was reported for it, so that
    # set_security_level(verification, not_set) withdraws the report again
    self.build_level[verification] = level
    sequence: uint256 = self.build_sequence[verification]
    if sequence > self.security_marker_newest_seq[product_id]:
        self.security_marker_newest_seq[product_id] = sequence
    log SecurityLevelChanged(product_id=product_id, level=level, verification=verification)


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

# The security level in effect for a build, derived from the reports: it is the
# level reported for the first build that was registered at or after this one,
# and not_set when this build is newer than every report of its product.
@view
@internal
def _security_level(product_id: uint256, sequence: uint256) -> SecurityLevel:
    if sequence > self.security_marker_newest_seq[product_id]:
        return SecurityLevel.not_set
    marked: DynArray[String[128], MAX_SECURITY_MARKERS] = self.security_marker_builds[product_id]
    # reports can be made out of order, so the array is not sorted: the closest
    # one is the report with the smallest sequence that is not older than the
    # build in question
    found: uint256 = max_value(uint256)
    level: SecurityLevel = SecurityLevel.not_set
    for i: uint256 in range(len(marked), bound=MAX_SECURITY_MARKERS):
        reported: String[128] = marked[i]
        reported_sequence: uint256 = self.build_sequence[reported]
        if reported_sequence >= sequence and reported_sequence < found:
            found = reported_sequence
            level = self.build_level[reported]
    return level

@view
@external
def get_product_build(verification: String[128]) -> my_product_build:
    build: my_product_build = self.product_builds[verification]
    # an unregistered build has no product, so it has no reports either
    if build.product_id != 0:
        build.security_level = self._security_level(build.product_id, self.build_sequence[verification])
    return build

# The security reports of a product in the order they were made. The array in
# storage is not exposed directly because a public mapping of arrays can only
# be read one index at a time and does not report its length.
@view
@external
def product_security(product_id: uint256) -> DynArray[SecurityMarker, MAX_SECURITY_MARKERS]:
    history: DynArray[SecurityMarker, MAX_SECURITY_MARKERS] = []
    marked: DynArray[String[128], MAX_SECURITY_MARKERS] = self.security_marker_builds[product_id]
    for i: uint256 in range(len(marked), bound=MAX_SECURITY_MARKERS):
        history.append(SecurityMarker(verification=marked[i], level=self.build_level[marked[i]]))
    return history

@view
@external
def current_product_build(name: String[16], kind: uint8) -> String[128]:
    return self.current_verification[self._build_key(name, kind)]

@view
@external
def get_product_counter() -> uint256:
    return self.next_product - 1

