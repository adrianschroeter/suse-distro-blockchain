# USAGE - distro_tool operations

This documents the CLI operations of `distro_tool` (installed from this repo;
in the source tree `distro_tool` is an equivalent shim) against
the openSUSE distro attestation contract.

The tool is credential-free and safe for public git: the signing key is read at
run time from the `PRIVATE_KEY` environment variable or from a file passed via
`--key-file`. Network settings (RPC endpoints, chain id, contract address) come
from `suse-distro-check.conf`; a network section may list several endpoints,
which are then cross-checked by the verification tools (see
[Multiple RPC endpoints](#multiple-rpc-endpoints)).

## Prerequisites

```bash
# 1. environment (web3, eth-account; + eth-tester for --network tester)
pipx install web3 eth-account

# 2. generate the build artifact (needs vyper 0.4.3)
make contract-build

# 3. (defaults) network presets are read from suse-distro-check.conf:
#    hoodi, sepolia, mainnet, anvil
```

Each write operation prints the transaction hash, gas used and a
`status: OK` / `FAILED` line. All write commands ask for confirmation unless
`-y` is given.

## Common options

| option | meaning |
| --- | --- |
| `--network <name>` | preset from `suse-distro-check.conf`; default `sepolia`. Example conf networks: `hoodi`, `sepolia`, `mainnet`, `anvil` |
| `--provider <url>` | override the RPC provider (`distro_tool` uses the first configured endpoint) |
| `--chain-id <id>` | expect this chain id, abort otherwise |
| `--contract <addr>` | contract address override |
| `--key-file <path>` | read the hex key from a file |
| `-y` / `--yes` | skip confirmation prompts |

Globals go **before** the subcommand, e.g.
`distro_tool --network hoodi --key-file key.txt add-build ...`.

## 1. Deploy a contract instance

The deploying account becomes the `foundation_owner`. The other three roles are
passed at construction time. The `--builder` address becomes the on-chain
`product_creator` role.

```bash
distro_tool --network hoodi \
    deploy \
    --builder   0xADDRESS_PRODUCT_BUILDER \
    --validator 0xADDRESS_OFFICIAL_VALIDATOR \
    --security  0xADDRESS_SECURITY_TEAM
```

On success the contract address is printed (`deployed: 0x...`). Record it and
pin it for later runs, e.g. in `suse-distro-check.conf` under
`[hoodi] contract=0x...`.

Verify the deployed contract and default roles:

```bash
distro_tool --network hoodi --contract 0xADDRESS roles
```

Limitations: Everybody can deploy a contract, but the contract address is
unique for each deployment. Verification of a product will only happen via
an agreed conctract address.

One contract can support multiple products, but each product could also use
an own contract.

## 2. Register a new build

Limitations: This only works for the registered builder account in the contract.

Registering has two steps: create the product, then attach a build to it.

```bash
# 2a. create the product (product_creator role)
export PRIVATE_KEY=0x...
distro_tool --network hoodi --contract 0xADDRESS \
    add-product Leap-16.1 <git: 40-char sha1 or 64-char sha256>

# 2b. attach a build to the product (product_creator role)
distro_tool --network hoodi --contract 0xADDRESS \
    add-build <git_ref> <kind> <verification>
```

Arguments:

| argument | accepted values |
| --- | --- |
| `name` | 1-16 characters |
| `git_ref` | hex git commit, 40 (sha1) or 64 (sha256) chars, must match the contract's git_ref |
| `kind` | `rpmmd` (1), `product` (2) or `oci_container` (4) |
| `verification` | hex digest of the build artifacts, 1-128 chars. **SHA-512 is supported**: a sha512 digest is 128 hex chars (sha256 is 64). The same value references this build in every later attestation call. For `oci_container` this is the image manifest digest including the `sha256:` prefix (a bare 64-hex digest is auto-prefixed; see section 6) |

Example, registering a build identified by its SHA-512 checksum:

```bash
# full 128-hex-char sha512 digest of the build artifacts
SHA512=$(sha512sum Leap-16.1.iso | cut -d' ' -f1)   # -> 128 hex chars
distro_tool --network hoodi --contract 0xADDRESS \
    add-build <git_ref> rpmmd "$SHA512"
```

The `verification` string is stored verbatim in the contract as `String[128]`,
so a SHA-512 digest fits exactly. The product and build can be inspected
read-only:

```bash
distro_tool --network hoodi --contract 0xADDRESS showid 1
distro_tool --network hoodi --contract 0xADDRESS current Leap-16.1
distro_tool --network hoodi --contract 0xADDRESS current Leap-16.1 rpmmd
```

`current` shows the current (latest) build state for a product: source commit,
build kind, verification digest, security level and rebuild-validator
attestation. A `KIND` is optional — `rpmmd`, `product` or `oci_container` —
and filters to that build kind; without it, every registered build kind of
the product is shown.

### From an SPDX SBOM

`register` derives everything from an SPDX 2.x or 3.x JSON SBOM as emitted by
obs-build (`generate_sbom`), so no checksums have to be copied by hand:

```bash
# derive and print the values only
distro_tool --network hoodi --contract 0xADDRESS \
    register --dry-run Leap-16.1.spdx.json

# register the product and its rpmmd build
distro_tool --network hoodi --contract 0xADDRESS \
    register Leap-16.1.spdx.json
```

| SBOM field | becomes |
| --- | --- |
| `name` of the root package (`SPDXRef-DOCUMENT-ROOT`, or the target of the SPDX 3 `describes` relationship) | product `name`, arch and build suffix removed (`Leap-16.1-aarch64-ppc64le-s390x-x86_64-Build50.2` becomes `Leap-16.1`), max 16 chars |
| fragment of the root package's `vcs` reference, otherwise the md5 in its `obs-disturl` locator | `git_ref`, the product anchor: hex md5 (32), sha1 (40) or sha256 (64) |
| `rpm-md-primary-checksum` reference, otherwise the `versionInfo` of the first `repository` package with `primaryPackagePurpose: INSTALL`, otherwise the root package `versionInfo` | `rpmmd` build `verification`, stored as bare hex (max 128 chars, so sha512 fits) |

A product medium SBOM contains one `repository` package per `repomd.xml`; only
the first one is registered, the others are listed as skipped warnings. Since
the product is only added when no product is anchored at the same `git_ref`, and
the build only when its verification is not registered yet, re-running `register`
on the same SBOM is a no-op.

## 3. Approve or reject a product build attestation

Limitations: This only works for the registered validator account in the contract.

The `official_validator` audits the registered build for
**reproducibility**: the `verification` digest must be reproducible from the
published sources (git_ref). Then the attestation state is set:

```bash
# approve (state -> approved)   official_validator role
distro_tool --network hoodi --contract 0xADDRESS \
    approve <verification>

# reject (state -> rejected)    official_validator role
distro_tool --network hoodi --contract 0xADDRESS \
    reject <verification>
```

Attestation states: `none` (0), `outstanding` (1), `approved` (2),
`rejected` (4).

Check the attestation state of a build:

```bash
distro_tool --network hoodi --contract 0xADDRESS build <verification>
```

## 4. Set the security critical state

Limitations: This only works for the registered security account in the contract.

The `security_team` flags a product as having known critical issues. Set it
`true` to warn users via the verification UI, `false` to clear it:

```bash
distro_tool --network hoodi --contract 0xADDRESS \
    set-critical 1 true
distro_tool --network hoodi --contract 0xADDRESS \
    set-critical 1 false
```

`<product_id>` is the numeric product id returned by `add-product`.

Inspect the flag:

```bash
distro_tool --network hoodi --contract 0xADDRESS showid 1
# critical: True / False
```

## 5. Verify a repository (suse-distro-check + repoverification plugin)

Two front ends share the same checks and the same `/etc/suse-distro-check.conf`:

* the `suse-distro-check` command line tool reports the state of the already
  cached repositories below `/var/cache/zypp/raw`;
* the zypp **repoverification** plugin runs during a `zypper refresh`, right
  after `repodata/repomd.xml` is downloaded and before GPG checks and solv
  conversion. A failing check discards that one repository (exit non-zero).

Command line:

```bash
suse-distro-check                 # all rpm-md repos with cached metadata
suse-distro-check repo-oss repo-update
suse-distro-check -v              # also show the remaining successful checks
```

For each repository the primary metadata checksum (`repodata/<checksum>-primary.xml.*`)
is looked up on-chain via `get_product_build`, and the following is reported:

| check | meaning |
| --- | --- |
| `registration` | the digest is registered in the contract (config key `registered`) |
| `consensus` | all configured RPC endpoints returned the same data (config key `consensus`) |
| `rpc_error` | an RPC endpoint was unreachable (config key `rpc_error`) |
| `product` | product name / git_ref / build kind |
| `kind` | on-chain build kind is `rpmmd` |
| `critical_issues` | `known_critical_issues` flag set by the security team |
| `verification` | rebuild reproducibility: `outstanding` / `approved` / `rejected` (config key `min_attestation`) |
| `current_build` | this digest is the current build for the product |

The state of an accepted build (`product`, `critical_issues`, `verification`,
`current_build`) is **always** reported, by the command line tool as well as by
the zypp plugin, so every accepted repository states which product, security
level and attestation it belongs to. The remaining successful checks need `-v`.
Checks that passed without adding information, such as `registration` and
`kind`, are only shown with `-v` or when they fail.

### Multiple RPC endpoints

A network section can list several endpoints, separated by commas. The
verification tools (this CLI, the zypp plugin and the container checks) then
query **all** of them:

```ini
[hoodi]
chainid=560048
contract=0xADDRESS
http_provider=https://rpc.hoodi.ethpandaops.io,https://ethereum-hoodi-rpc.publicnode.com
```

* every endpoint is contacted **in parallel**; the wall clock cost is that of
  the slowest endpoint, not the sum of all of them;
* every endpoint must be reachable (`rpc_error`) and all answers must be
  identical (`consensus`) - one compromised, stale or lying RPC server can
  therefore no longer decide whether a repository is accepted;
* all reads are pinned to the **lowest block number** of the set, so endpoints
  with different sync progress are still compared at the same chain state;
* if an endpoint is on another chain, or cannot be reached, the check fails
  with the configured level (default `reject`, i.e. zypper discards that one
  repository). Use `rpc_error = warn` or fewer endpoints to tolerate a
  temporarily unavailable server;
* `distro_tool` sends transactions to the **first** endpoint of the list only
  and does not cross-check the ones it reads from.

### Per-repository policy

The plugin is called for every repository, so it only enforces aliases that
have a `[repo:<alias>]` section in `suse-distro-check.conf`. Everything else
follows `[defaults] unmanaged` (default `allow`, so unrelated repos are never
blocked):

```ini
[defaults]
unmanaged = allow
registered = reject
critical_issues = reject
rpc_error = reject
consensus = reject
current_build = warn
kind = warn
min_attestation = outstanding

[repo:repo-oss]
network = hoodi
current_build = reject
```

Each of `registered`, `critical_issues`, `rpc_error`, `consensus`,
`current_build`, `kind` and `signed` takes `reject` (discard the repository),
`warn` (keep it and print a warning) or `ignore` (skip the check). The GPG check
is `ignore` by default because the on-chain verification does not depend on the
package signature; set it to `warn` or `reject` to enforce signing as well.
`min_attestation` is `off`, `outstanding` or `approved`; a rejected attestation
fails unless the check is disabled with `off`, in which case it is reported as a
warning. `network` selects the section (endpoints, chain id, contract) for that
repository; without it the `[main] network` section is used.

## 6. Verify a container image (suse-distro-oci-check + spodman)

Container images are registered with `kind = oci_container` (4). The
`verification` value is the **manifest digest** of the image, i.e.
`sha256:<64 hex>` (71 chars, fits the contract's 128 char limit):

```bash
# resolve the digest and register the build (product_creator role)
DIGEST=$(skopeo inspect --raw docker://registry.example/opensuse/leap:16.1 \
         | sha256sum | cut -d' ' -f1)
distro_tool --network hoodi --contract 0xADDRESS \
    add-build <git_ref> oci_container "sha256:$DIGEST"
```

For a tag that points at a manifest list (multi-arch), the digest of the list
is used, so a product keeps a single, architecture independent "current" value.

### Command line

`suse-distro-oci-check` resolves a reference to its manifest digest (via
`skopeo inspect --raw`, so `skopeo` must be installed) and runs the same
on-chain checks as repository metadata:

```bash
suse-distro-oci-check registry.example/opensuse/leap:16.1
suse-distro-oci-check -v --conf /etc/suse-distro-check.conf <image>
suse-distro-oci-check --print-ref <image>   # print image@sha256:<digest>
```

A non-zero exit status means the image must not be used. The reported checks
are the same as for repositories (`registration`, `consensus`, `rpc_error`,
`product`, `kind`, `critical_issues`, `verification`, `current_build`); `kind`
expects `oci_container`, and the optional GPG check is not run for images. The
state of a registered build (`product`, `critical_issues`, `verification`,
`current_build`) is **always** reported, the remaining successful checks need
`-v`. Like the repository checks, the image is
only accepted if **all** RPC endpoints of the configured network are reachable
and return the same data (see [Multiple RPC endpoints](#multiple-rpc-endpoints)).

### Per-image policy

Images are matched by the prefix of their `registry/repository` scope. Sections
use the same policy values as repositories and are applied from the least to
the most specific prefix:

```ini
[defaults]
unmanaged = allow

[oci:registry.example]
network = hoodi

[oci:registry.example/opensuse]
current_build = reject
```

A scope with no matching `[oci:<scope>]` section follows `[defaults] unmanaged`
(default `allow`, so unrelated images are never blocked).

### spodman front end

Podman has no pull-time plugin hook (`containers-policy.json` only supports
signature based requirements), so enforcement uses a small front end installed
**in parallel** to podman. The rpm ships `plugin/podman` and a `spodman` symlink
in `/usr/bin`, so the real `podman` command is untouched. Call `spodman`
instead of `podman` when you want the checks:

```bash
spodman pull registry.example/opensuse/leap:16.1
spodman run -it --rm registry.example/opensuse/leap:16.1 sh
```

For `pull`, `run` and `create` it verifies the remote reference and then
delegates to the real podman (found via `PODMAN_REAL` or the remaining `PATH`)
with the reference rewritten to `image@sha256:<verified digest>`, so exactly
the verified bytes are used. Unmanaged scopes are passed through untouched.
`--pull=never` and local references (paths, image ids, `containers-storage:`)
are not verified. Other podman subcommands are forwarded unchanged.

Every accepted image reports the state of its registered build, so a pull
always says what was accepted:

```text
[OK] product: 'Leap-16.1' (git_ref 1a2b3c…, oci_container)
[OK] critical_issues: no known critical security issues
[OK] verification: reproducibility verification is approved
[OK] current_build: repository is the current build
```

These lines (and any warning) go to stderr; with `--print-ref` stdout carries
only the pinned reference. Checks that passed without adding information, such
as `registration` and `kind`, are only shown with `-v` or when they fail.

Environment switches:

| variable | meaning |
| --- | --- |
| `PODMAN_REAL` | path to the real podman binary |
| `SUSE_DISTRO_OCI_CHECK_SKIP=1` | bypass verification (also suppresses the lookup for unmanaged scopes) |

## Testing locally (no RPC, no funds)

```bash
distro_tool --network tester deploy \
    --builder   0xADDRESS_PRODUCT_BUILDER \
    --validator 0xADDRESS_OFFICIAL_VALIDATOR \
    --security  0xADDRESS_SECURITY_TEAM
```

Each `--network tester` invocation starts a fresh in-memory chain. Repeat the
commands above with `--network tester`; a signing key is created and funded
automatically.

## Role notes

- `foundation_owner` may replace the three empowered roles
  (`set_product_creator`, `set_official_validator`, `set_security_team`).
- Currently the contract also grants `foundation_owner` a **temporary
  superuser override** on `set_critical` / `approve_attestation` /
  `reject_attestation` (commit `6ead57b`, marked TEMP; to be removed once
  ownership is settled).
- Never store real `PRIVATE_KEY` values in this repository.
