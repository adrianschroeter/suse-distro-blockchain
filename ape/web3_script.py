from web3 import Web3, HTTPProvider
from dotenv import load_dotenv
import os

load_dotenv()

w3 = Web3(Web3.HTTPProvider('http://127.0.0.1:8545'))

assert w3.is_connected(), 'Failed to connect to the Ethereum client.'

contract_address = '0x0e075cB6f980203F8e930a0B527CDbE07F303eAD'
abi = [
    {
        "stateMutability": "nonpayable",
        "type": "function",
        "name": "add_product",
        "inputs": [
            {
                "name": "name",
                "type": "string"
            },
            {
                "name": "git_ref",
                "type": "string"
            }
        ],
        "outputs": [
            {
                "name": "",
                "type": "uint256"
            }
        ]
    },
    {
        "stateMutability": "nonpayable",
        "type": "function",
        "name": "add_product_build",
        "inputs": [
            {
                "name": "git_ref",
                "type": "string"
            },
            {
                "name": "kind",
                "type": "uint8"
            },
            {
                "name": "verification",
                "type": "string"
            }
        ],
        "outputs": []
    },
    {
        "stateMutability": "view",
        "type": "function",
        "name": "get_product",
        "inputs": [
            {
                "name": "product_id",
                "type": "uint256"
            }
        ],
        "outputs": [
            {
                "name": "",
                "type": "tuple",
                "components": [
                    {
                        "name": "name",
                        "type": "string"
                    },
                    {
                        "name": "git_ref",
                        "type": "string"
                    },
                    {
                        "name": "known_critical_issues",
                        "type": "bool"
                    }
                ]
            }
        ]
    },
    {
        "stateMutability": "view",
        "type": "function",
        "name": "get_product_build",
        "inputs": [
            {
                "name": "verification",
                "type": "string"
            }
        ],
        "outputs": [
            {
                "name": "",
                "type": "tuple",
                "components": [
                    {
                        "name": "product_id",
                        "type": "uint256"
                    },
                    {
                        "name": "kind",
                        "type": "uint8"
                    },
                    {
                        "name": "verified",
                        "type": "bool"
                    }
                ]
            }
        ]
    },
    {
        "stateMutability": "view",
        "type": "function",
        "name": "current_product_build",
        "inputs": [
            {
                "name": "name",
                "type": "string"
            },
            {
                "name": "kind",
                "type": "uint8"
            }
        ],
        "outputs": [
            {
                "name": "",
                "type": "string"
            }
        ]
    },
    {
        "stateMutability": "view",
        "type": "function",
        "name": "get_product_counter",
        "inputs": [],
        "outputs": [
            {
                "name": "",
                "type": "uint256"
            }
        ]
    },
    {
        "stateMutability": "nonpayable",
        "type": "function",
        "name": "set_critical",
        "inputs": [
            {
                "name": "product_id",
                "type": "uint256"
            },
            {
                "name": "critical",
                "type": "bool"
            }
        ],
        "outputs": []
    },
    {
        "stateMutability": "nonpayable",
        "type": "function",
        "name": "add_attestation",
        "inputs": [
            {
                "name": "verification",
                "type": "string"
            }
        ],
        "outputs": []
    },
    {
        "stateMutability": "view",
        "type": "function",
        "name": "foundation_owner",
        "inputs": [],
        "outputs": [
            {
                "name": "",
                "type": "address"
            }
        ]
    },
    {
        "stateMutability": "view",
        "type": "function",
        "name": "product_creator",
        "inputs": [],
        "outputs": [
            {
                "name": "",
                "type": "address"
            }
        ]
    },
    {
        "stateMutability": "view",
        "type": "function",
        "name": "official_validator",
        "inputs": [],
        "outputs": [
            {
                "name": "",
                "type": "address"
            }
        ]
    },
    {
        "stateMutability": "view",
        "type": "function",
        "name": "security_team",
        "inputs": [],
        "outputs": [
            {
                "name": "",
                "type": "address"
            }
        ]
    },
    {
        "stateMutability": "view",
        "type": "function",
        "name": "next_product",
        "inputs": [],
        "outputs": [
            {
                "name": "",
                "type": "uint256"
            }
        ]
    },
    {
        "stateMutability": "nonpayable",
        "type": "constructor",
        "inputs": [
            {
                "name": "_product_creator",
                "type": "address"
            },
            {
                "name": "_official_validator",
                "type": "address"
            },
            {
                "name": "_security_team",
                "type": "address"
            }
        ],
        "outputs": []
    }
]

contract = w3.eth.contract(address=contract_address, abi=abi)

account_address = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8'
private_key = os.getenv('PRIVATE_KEY')
assert private_key, 'Private key not found in .env file'

def add_product(name, git_ref):
    # Update nonce before building transaction
    updated_nonce = w3.eth.get_transaction_count(account_address)

    # Build transaction with updated nonce
    txn = contract.functions.add_product(name, git_ref).build_transaction({
        'chainId': 31337,
        'gas': 2000000,
        'nonce': updated_nonce,
    })

    # Sign transaction
    signed_txn = w3.eth.account.sign_transaction(txn, private_key=private_key)
    # Send transaction
    tx_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
    # Wait for transaction to be mined
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    return tx_receipt

def add_product_build(git_ref, kind, verification):
    # Update nonce before building transaction
    updated_nonce = w3.eth.get_transaction_count(account_address)

    # Build transaction with updated nonce
    txn = contract.functions.add_product_build(git_ref, kind, verification).build_transaction({
        'chainId': 31337,
        'gas': 2000000,
        'nonce': updated_nonce,
    })

    # Sign transaction
    signed_txn = w3.eth.account.sign_transaction(txn, private_key=private_key)
    # Send transaction
    tx_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
    # Wait for transaction to be mined
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    return tx_receipt

def get_product(product_id):
    return contract.functions.get_product(product_id).call()

def get_product_build(verification):
    return contract.functions.get_product_build(verification).call()

def current_product_build(name, kind):
    return contract.functions.current_product_build(name, kind).call()

def get_product_counter():
    return contract.functions.get_product_counter().call()

def set_critical(product_id, critical):
    # Update nonce before building transaction
    updated_nonce = w3.eth.get_transaction_count(account_address)

    # Build transaction with updated nonce
    txn = contract.functions.set_critical(product_id, critical).build_transaction({
        'chainId': 31337,
        'gas': 2000000,
        'nonce': updated_nonce,
    })

    # Sign transaction
    signed_txn = w3.eth.account.sign_transaction(txn, private_key=private_key)
    # Send transaction
    tx_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
    # Wait for transaction to be mined
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    return tx_receipt

def add_attestation(verification):
    # Update nonce before building transaction
    updated_nonce = w3.eth.get_transaction_count(account_address)

    # Build transaction with updated nonce
    txn = contract.functions.add_attestation(verification).build_transaction({
        'chainId': 31337,
        'gas': 2000000,
        'nonce': updated_nonce,
    })

    # Sign transaction
    signed_txn = w3.eth.account.sign_transaction(txn, private_key=private_key)
    # Send transaction
    tx_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
    # Wait for transaction to be mined
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    return tx_receipt

def foundation_owner():
    return contract.functions.foundation_owner().call()

def product_creator():
    return contract.functions.product_creator().call()

def official_validator():
    return contract.functions.official_validator().call()

def security_team():
    return contract.functions.security_team().call()

def next_product():
    return contract.functions.next_product().call()

