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

`distro_tool` does not embed the ABI/bytecode. They are generated from
`ape/contracts/distro.vy` into `src/suse_distro_blockchain/distro_contract.py`,
together with a copy of the contract source as package data, by
`ape/build_contract.py`:

```bash
make contract-build        # regenerate the artifact + source copy
make contract-check        # fail if the artifact or source copy is stale (for CI)
```

Both generated files are committed so every wheel build ships them - the rpm
build does not need vyper. `make contract-build` is a no-op (exit 0, vyper is
never invoked) when the artifact is already current, so it is safe to run
unconditionally, including in the rpm `%build`. After any contract change, run
`make contract-build` and commit the regenerated files; CI must gate on
`make contract-check`, which verifies the artifact and the packaged source
copy against `ape/contracts/distro.vy`.

Requires vyper 0.4.x (as a python module or the `vyper` CLI) to regenerate. If
the artifact is missing, or the contract source changed since it was built,
`distro_tool` refuses to run and prints the rebuild command. When the tool is
installed without the vyper source, the compiled artifact is authoritative and
the check is skipped.

The build pins vyper **0.4.3** (`ape/ape-config.yaml`). Event logging uses
keyword arguments (`log SomeEvent(a=..., b=...)`), which is the required form
from vyper 0.4.1 onward. Keep the pin and the build environment at >= 0.4.1.

### RPM / wheel packaging

`pyproject.toml` uses setuptools with PEP 621 metadata and exposes three console
scripts, so a built wheel installs the repository tooling:

* `suse-distro-check` (`src/suse_distro_blockchain/suse_distro_check.py`)
* `suse-distro-oci-check` (`src/suse_distro_blockchain/oci_check.py`)
* `distro_tool` (`src/suse_distro_blockchain/distro_tool.py`)

`spodman` is **not** a console script; it is provided by the rpm as a symlink to
`plugin/podman` (see "spodman front end" below).

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
distro_tool --network sepolia add-product Leap-16.1 <git sha256>
distro_tool --network sepolia add-build <git sha256> rpmmd <sha512>

# validator / security roles
distro_tool approve <sha512>
distro_tool reject <sha512>
distro_tool set-critical 1 true

# read-only
distro_tool roles
distro_tool showid 1
distro_tool current Leap-16.1         # all build kinds
distro_tool current Leap-16.1 rpmmd   # single build kind

# local test network (no RPC needed)
distro_tool --network tester deploy --builder ... --validator ... --security ...
```

### zypp repoverification plugin

`plugin/suse-distro-check` is the zypp **repoverification** plugin. libzypp runs
every executable in `/usr/lib/zypp/plugins/repoverification` on each repository
metadata refresh, immediately after `repodata/repomd.xml` has been downloaded
and **before** GPG checks and solv conversion. A non-zero exit status makes
libzypp discard that single repository, so the raw metadata update is blocked.

The plugin is stateless and is called for *every* repository (it receives the
alias via `--ralias`), therefore it is opt-in by policy: only aliases that have
a `[repo:<alias>]` section in `/etc/suse-distro-check.conf` are enforced. All
other repositories follow the `unmanaged` setting (default: `allow`).

The protocol front end is `src/suse_distro_blockchain/repoverify.py`; the checks
are shared with the command line tool in
`src/suse_distro_blockchain/metadata.py`. The `suse-distro-check` console script
and the plugin therefore always agree.

The plugin is **not** part of the wheel (console scripts cannot target the zypp
plugin directory); the rpm spec must install it:

```spec
Requires: python3-web3
Requires: python3-iniparse
# no zypp-plugin-python needed for repoverification

%install
install -D -m 0755 plugin/suse-distro-check \
    %{buildroot}%{_prefix}/lib/zypp/plugins/repoverification/suse-distro-check
```

Make sure the rpm ships `/etc/suse-distro-check.conf` (the plugin reads the
`[defaults]` / `[repo:<alias>]` policy from there) and does **not** install an
older *sigcheck* plugin at `/usr/lib/zypp/plugins/sigcheck/suse-distro-check`;
that variant is unused now and would fail with a protocol error.

Test it directly, no zypper refresh required:

```bash
SUSE_DISTRO_CHECK_CONF=./suse-distro-check.conf \
  python3 plugin/suse-distro-check \
    --ralias repo-oss \
    --file /var/cache/zypp/raw/repo-oss/repodata/repomd.xml \
    --fsig /var/cache/zypp/raw/repo-oss/repodata/repomd.xml.asc
echo $?   # 0 = allow, 1 = discard the repository
```

### spodman front end

Podman has no pull-time plugin hook (`containers-policy.json` only supports
signature based requirements), so container verification uses a `spodman`
front end instead. The rpm installs `plugin/podman` and creates a `spodman`
symlink in `%{_bindir}`, so users call `spodman` instead of `podman` and the
real `podman` command stays untouched. It calls `suse-distro-oci-check` for
`pull`/`run`/`create` and delegates to the real podman (found via `PODMAN_REAL`
or the rest of `PATH`) with the reference rewritten to
`image@sha256:<verified digest>`.

The logic lives in `src/suse_distro_blockchain/spodman_shim.py` and is unit
tested in `tests/test_spodman_shim.py`. `suse-distro-oci-check` requires `skopeo`
(`Requires: skopeo`) to resolve a tag to its manifest digest. Images are
matched with `[oci:<registry/repo>]` sections; unmatched scopes follow
`unmanaged` (default `allow`).

```spec
Requires: skopeo

%install
install -D -m 0755 plugin/podman \
    %{buildroot}%{_prefix}/lib/suse-distro-blockchain/podman
ln -s %{_prefix}/lib/suse-distro-blockchain/podman \
    %{buildroot}%{_bindir}/spodman
```

## Ape based development

End-to-end tests of the contract live in `tests/test_distro_contract.py` (boa based).

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
python3 tests/test_distro_contract.py
```

## Running the unit tests

All unit tests live in `tests/` and import the package from `src/`:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -t .
```
