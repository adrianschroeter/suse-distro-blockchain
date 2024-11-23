# pyremix

Create a virtual environment
I'm naming my virtual environment here `myv`.

PLEASE NOTE THAT THIS IS NOT PROTECTING YOUR SYSTEM.
DO THIS IN A RESERVED VM!

(todo: package the development env)

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
ape accounts import attestator
ape accounts import security_team
```

To finally deploy the contract use
```bash
cd ape
ape run scripts/deploy_anvil.py --network http://localhost:8545
```

On modifications of the contract run:
```bash
# on abi changes:
vyper -f abi contracts/distro.vy  > .build/distro.json
python3 test_distro_contract.py
```
