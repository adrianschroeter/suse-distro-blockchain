
TODO (before production)
========================

* Foundation owner has overwrite permissions atm. This should get removed
  before production.

* Adding examples and tooling to support container attestations.

* Currently each party (foundation, builder, validator) is a single signer.
  We need to cover groups here in a way that at least critical operations
  need multiple parties of the group.

  This could be achieved either by extending the distribution contract
  or via additional contracts one for each group.

* Support checking against via multiple RPC nodes.

* We do _not_ register git URL's, only hashes for products.
  This is on purpose so far, since a URL would point to a central service
  again.
   But we need a definition where to get it. Is it okay that it is
  only part of the sbom?

  
