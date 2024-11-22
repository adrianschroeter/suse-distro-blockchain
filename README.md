
Motivation
==========

The SUSE and openSUSE distribution creation and shipment relies on centralized
trust points today. A breach at these critical points inside of the production
process could lead to an unwanted shipment of harmful content. 

Furthermore we rely on external service providers for providing our products.
While these can not modify the products, they can still replace them with
different SUSE or openSUSE signed content.

The goal of this implementation is to achieve a real zero-trust implementation
for our distribution building and shipment.

Using this first demo implementation we can provide a way how any consumer
can check the state of the current provided products. 


High-Level product tracking of a SUSE/openSUSE distribution
===========================================================

0. Review of submissions and aggregation of a product

   This first itertion of the implementation is excluding the tracking
   of each individual review steps. However a lot could be done here
   in a later extension.

   Important right now is just that the product/code stream owner defines
   a fixed set of sources for his product which can be reviewed by any
   party.

   It is also critical to have a secure identifier of this state. This
   could be for example provided via a SHA-256 reflog entry of a project
   git.

1. The product build

   The OBS instance is building now the product, which means any binary
   artifact out of given source. The artifact provides also an identifier
   which can be used for tracking.

   The fact that products are signed by OBS with a key don't matter 
   in our concept, since we don't want to rely on a centralised 
   secret (the gpg private signing key). It could be mis-used by
   an attacker in the same way when the attacker is also able to
   provide binaries which don't rely on the given the source.

   Keep in mind that the attacker could be also one of the OBS 
   administrators.
   Or from the POV of the OBS administrator, I don't want to have the
   power here to do so. Never being in the situation that someone could
   claim that I did something like this.

   However, we again need a secure identifier, like a SHA-256 sum again.

2. The content providers

   Published products get distributed via various channels and mirrors.

   This involves also all possible inhouse mirrors and any network
   infrastructure entities which may spoof network access (Esp. when
   you consider SSL CA authorities as not secure enough).

   While content provides can not sign repositories with own content,
   it is possible for them to block security updates. Or even provide older
   versions with known attack vectors formerly signed by openSUSE or SUSE.

   This scenario becomes even worse when it is a targeted attack to or inside
   of a larger organisation.

The problems solved by a blockchain contract for product tracking
=================================================================

1) The responsibilities get defined and documented in the contract.

2) Validation of the current state, avoiding any blocked content.

3) Any role or entity validation can be distributed over multiple
   persons. For example we can require 3 votes out of the team of 9 security
   managers to mark a source state as unsecure.

   In short a zero-trust implementation for a single entity.

4) We avoid the need of a product modification by having a second channel
   (the blockchain).
   For example no need to modify a git commit or existing file by
   providing an additional signature in place.
   We just need a secure reference, for example a SHA-256 sum to be stored
   in the blockchain.

Roles in this example setup
===========================

1) The Organisation owner / The contract deployer

   This can be for example the openSUSE board. They would deploy a contract
   which defines the roles and responsibilities. 

   They have no further involvement in the production process afterwards.

2) The product creator

   This would be the OBS administrator in this example. He is responsible
   to take a defined source state and producing binary shipments.

   He has the duty to register new product builds in the chain.

3) The attestator

   She would rebuild the source and verifies that the same binary get created.

   She has the duty to acknowledge a registered product build as reproducable.

4) The security auditor

   He can register any product build as not-secure when grave issues appear.

   He has the duty to mark an existing product build as unsecure.

Involved software components
============================

1) The distribution contract can be found in ape/contracts/distro.vy

2) The tool to register a new product build for the OBS admin

3) The tool to modify a registered product build

4) The tool for the user to validate a product

