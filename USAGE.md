# USAGE - distro_tool.py operations

This documents the CLI operations of `ape/distro_tool.py` against the openSUSE
distro attestation contract.

The tool is credential-free and safe for public git: the signing key is read at
run time from the `PRIVATE_KEY` environment variable or from a file passed via
`--key-file`. Network settings (RPC provider, chain id, contract address) come
from `suse-distro-check.conf`.

## Prerequisites

```bash
# 1. environment (web3, eth-account; + eth-tester for --network tester)
pipx install web3 eth-account

# 2. generate the build artifact ape/distro_contract.py (needs vyper 0.4.x)
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
| `--provider <url>` | override RPC provider |
| `--chain-id <id>` | expect this chain id, abort otherwise |
| `--contract <addr>` | contract address override |
| `--key-file <path>` | read the hex key from a file |
| `-y` / `--yes` | skip confirmation prompts |

Globals go **before** the subcommand, e.g.
`python3 ape/distro_tool.py --network hoodi --key-file key.txt add-build ...`.

## 1. Deploy a contract instance

The deploying account becomes the `foundation_owner`. The other three roles are
passed at construction time.

```bash
python3 ape/distro_tool.py --network hoodi \
    deploy \
    --creator  0xADDRESS_PRODUCT_CREATOR \
    --validator 0xADDRESS_OFFICIAL_VALIDATOR \
    --security  0xADDRESS_SECURITY_TEAM
```

On success the contract address is printed (`deployed: 0x...`). Record it and
pin it for later runs, e.g. in `suse-distro-check.conf` under
`[hoodi] contract=0x...`.

Verify the deployed contract and default roles:

```bash
python3 ape/distro_tool.py --network hoodi --contract 0xADDRESS roles
```

## 2. Register a new build

Registering has two steps: create the product, then attach a build to it.

```bash
# 2a. create the product (product_creator role)
export PRIVATE_KEY=0x...
python3 ape/distro_tool.py --network hoodi --contract 0xADDRESS \
    add-product SLFO-1.1 <git: 40-char sha1 or 64-char sha256>

# 2b. attach a build to the product (product_creator role)
python3 ape/distro_tool.py --network hoodi --contract 0xADDRESS \
    add-build <git_ref> <kind> <verification>
```

Arguments:

| argument | accepted values |
| --- | --- |
| `name` | 1-16 characters |
| `git_ref` | hex git commit, 40 (sha1) or 64 (sha256) chars, must match the contract's git_ref |
| `kind` | `rpmmd` (1), `product` (2) or `oci_container` (4) |
| `verification` | hex digest of the build artifacts, 1-128 chars. **SHA-512 is supported**: a sha512 digest is 128 hex chars (sha256 is 64). The same value references this build in every later attestation call |

Example, registering a build identified by its SHA-512 checksum:

```bash
# full 128-hex-char sha512 digest of the build artifacts
SHA512=$(sha512sum SLFO-1.1.iso | cut -d' ' -f1)   # -> 128 hex chars
python3 ape/distro_tool.py --network hoodi --contract 0xADDRESS \
    add-build <git_ref> rpmmd "$SHA512"
```

The `verification` string is stored verbatim in the contract as `String[128]`,
so a SHA-512 digest fits exactly. The product and build can be inspected
read-only:

```bash
python3 ape/distro_tool.py --network hoodi --contract 0xADDRESS show 1
python3 ape/distro_tool.py --network hoodi --contract 0xADDRESS current SLFO-1.1 rpmmd
```

## 3. Approve or reject a product build attestation

The `official_validator` (attestator) audits the registered build for
**reproducibility**: the `verification` digest must be reproducible from the
published sources (git_ref). Then the attestation state is set:

```bash
# approve (state -> approved)   official_validator role
python3 ape/distro_tool.py --network hoodi --contract 0xADDRESS \
    approve <verification>

# reject (state -> rejected)    official_validator role
python3 ape/distro_tool.py --network hoodi --contract 0xADDRESS \
    reject <verification>
```

Attestation states: `none` (0), `outstanding` (1), `approved` (2),
`rejected` (4).

Check the attestation state of a build:

```bash
python3 ape/distro_tool.py --network hoodi --contract 0xADDRESS build <verification>
```

## 4. Set the security critical state

The `security_team` flags a product as having known critical issues. Set it
`true` to warn users via the verification UI, `false` to clear it:

```bash
python3 ape/distro_tool.py --network hoodi --contract 0xADDRESS \
    set-critical 1 true
python3 ape/distro_tool.py --network hoodi --contract 0xADDRESS \
    set-critical 1 false
```

`<product_id>` is the numeric product id returned by `add-product`.

Inspect the flag:

```bash
python3 ape/distro_tool.py --network hoodi --contract 0xADDRESS show 1
# critical: True / False
```

## Testing locally (no RPC, no funds)

```bash
python3 ape/distro_tool.py --network tester deploy \
    --creator 0xADDRESS_PRODUCT_CREATOR \
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