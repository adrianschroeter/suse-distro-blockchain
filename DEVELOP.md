# pyremix

Create a virtual environment
I'm naming my virtual environment here `myv`.

PLEASE NOTE THAT THIS IS NOT PROTECTING YOUR SYSTEM.
DO THIS IN A RESERVED VM!

(todo: package the development env)

## distro_tool - public git safe CLI

`distro_tool` is the production CLI to register product releases and to
deploy the attestation contract. It contains no credentials and is safe to
commit to a public git repository.

The implementation lives in `src/suse_distro_blockchain/distro_tool.py` and is
installed as the `distro_tool` console script (see "RPM / wheel packaging"
below). In the source tree `ape/distro_tool.py` is a thin shim, so
`python3 ape/distro_tool.py ...` works exactly like the installed command.

Dependencies:
```bash
pipx install web3 eth-account      # for real networks
pipx install web3 eth-account eth-tester   # + --network tester for local runs
```

Signing key is read at run time from the `PRIVATE_KEY` environment variable or
from a file passed with `--key-file`. Network settings (RPC provider, chain id,
contract address) come from `suse-distro-check.conf` and can be overridden with
`--provider`, `--chain-id`, `--contract` or the `HTTP_PROVIDER_URL` / `CHAIN_ID`
/ `CONTRACT_ADDRESS` environment variables.

### Contract build artifact

`distro_tool` does not embed the ABI/bytecode. They are generated at build
time from `ape/contracts/distro.vy` into
`src/suse_distro_blockchain/distro_contract.py` (git-ignored), together with a
copy of the contract source as package data, by `ape/build_contract.py`:

```bash
make contract-build        # regenerate the artifact + source copy
make contract-check        # fail if the artifact is stale (for CI)
```

Requires vyper 0.4.x (as a python module or the `vyper` CLI). If the artifact is
missing, or the contract source changed since it was built, `distro_tool`
refuses to run and prints the rebuild command. `make contract-check` fails with
a non-zero exit code on a stale artifact, so you can gate CI on it. When the
tool is installed without the vyper source (e.g. from an rpm without the
packaged source copy), the compiled artifact is authoritative and the check is
skipped.

### RPM / wheel packaging

`pyproject.toml` uses setuptools with PEP 621 metadata and exposes two console
scripts, so a built wheel installs both executables:

* `suse-distro-check` (`src/suse_distro_blockchain/suse_distro_check.py`)
* `distro_tool` (`src/suse_distro_blockchain/distro_tool.py`)

Build order matters: run `make contract-build` **before** building the wheel so
`distro_contract.py` and the `contracts/distro.vy` copy are included. The
version lives in two places - keep them in sync: `pyproject.toml`
(`[project] version`) and `src/suse_distro_blockchain/__init__.py`
(`__version__`).

Examples:

```bash
# deploy a contract; the deployer becomes foundation_owner
distro_tool --network sepolia deploy \
    --builder 0xACCOUNT_PRODUCT_BUILDER \
    --validator 0xACCOUNT_OFFICIAL_VALIDATOR \
    --security 0xACCOUNT_SECURITY_TEAM

# register a product and its build (product_creator role)
export PRIVATE_KEY=0x...
distro_tool --network sepolia add-product SLFO-1.1 <git sha256>
distro_tool --network sepolia add-build <git sha256> rpmmd <sha512>

# validator / security roles
distro_tool approve <sha512>
distro_tool reject <sha512>
distro_tool set-critical 1 true

# read-only
distro_tool roles
distro_tool show 1
distro_tool current SLFO-1.1 rpmmd

# local test network (no RPC needed)
distro_tool --network tester deploy --builder ... --validator ... --security ...
```

## Ape based development

End-to-end tests of the contract live in `test_distro_contract.py` (boa based).

```bash
python3 -m venv ./myv
```
Make sure that if you name your virtual environment something else, you include it in the gitignore.

Install requirements:
```bash
pipx-3.12 install vyper eth-ape ape-vyper web3 streamlit python-dotenv
```
Make sure to have foundry installed.  
To work on these tooling you need to run an own local chain on
your workstation. For that run
```bash
anvil
```
And keep it running. It also creates multiple accounts with 
keypairs you need to use below.

First we need to create for each role an own account. So you need
to pick a matching public and private key pair from the output
of the anvil tool. And use it to create multiple accounts in the
anvil chain. 

```bash
ape accounts import foundation
ape accounts import product_creator
ape accounts import validator
ape accounts import security_team
```

To finally deploy the contract use
```bash
cd ape
ape run scripts/deploy_anvil.py --network http://localhost:8545 --balance 1
```

On modifications of the contract run:
```bash
# on abi changes:
vyper -f abi contracts/distro.vy  > .build/distro.json
python3 test_distro_contract.py
```
