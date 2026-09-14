# openSUSE distro attestation contract - build helpers.
#
# The contract artifact ape/distro_contract.py (CONTRACT_ABI / CONTRACT_BYTECODE)
# is generated from ape/contracts/distro.vy and is git-ignored. Rebuild it after
# every contract change; run contract-check in CI to catch stale artifacts.
#
# Requires vyper (0.4.x) either as a python module or as the `vyper` CLI.

PYTHON ?= python3

.PHONY: contract-build contract-check

contract-build:
	$(PYTHON) ape/build_contract.py

contract-check:
	$(PYTHON) ape/build_contract.py --check