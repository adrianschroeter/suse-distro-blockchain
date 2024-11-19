import json
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

def create_web3_script(output_file):
    chain_id = os.getenv('CHAIN_ID', '31337')  # Default to 31337 if not found
    contract_address = os.getenv('CONTRACT_ADDRESS')
    account_address = os.getenv('ACCOUNT_ADDRESS')
    http_provider_url = os.getenv('HTTP_PROVIDER_URL')
    abi = json.loads(os.getenv('ABI', '[]'))  # Default to empty list if not found

    with open(output_file, 'w') as f:
        f.write("from web3 import Web3, HTTPProvider\n")
        f.write("from dotenv import load_dotenv\n")
        f.write("import os\n\n")
        f.write("load_dotenv()\n\n")
        f.write(f"w3 = Web3(Web3.HTTPProvider('{http_provider_url}'))\n\n")
        f.write("assert w3.is_connected(), 'Failed to connect to the Ethereum client.'\n\n")
        f.write(f"contract_address = '{contract_address}'\n")
        f.write("abi = " + json.dumps(abi, indent=4) + "\n\n")
        f.write("contract = w3.eth.contract(address=contract_address, abi=abi)\n\n")
        f.write(f"account_address = '{account_address}'\n")
        f.write("private_key = os.getenv('PRIVATE_KEY')\n")
        f.write("assert private_key, 'Private key not found in .env file'\n\n")

        for item in abi:
            if item['type'] == 'function':
                function_name = item['name']
                params = [input['name'] for input in item['inputs']]
                params_str = ", ".join(params)
                f.write(f"def {function_name}({params_str}):\n")
                if item['stateMutability'] in ['view', 'pure']:
                    f.write(f"    return contract.functions.{function_name}({params_str}).call()\n\n")
                else:
                    f.write("    # Update nonce before building transaction\n")
                    f.write("    updated_nonce = w3.eth.get_transaction_count(account_address)\n\n")
                    f.write(f"    # Build transaction with updated nonce\n")
                    f.write(f"    txn = contract.functions.{function_name}({params_str}).build_transaction({{\n")
                    f.write("        'chainId': " + chain_id + ",\n")
                    f.write("        'gas': 2000000,\n")
                    f.write("        'nonce': updated_nonce,\n")
                    f.write("    })\n\n")
                    f.write("    # Sign transaction\n")
                    f.write("    signed_txn = w3.eth.account.sign_transaction(txn, private_key=private_key)\n")
                    f.write("    # Send transaction\n")
                    f.write("    tx_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)\n")
                    f.write("    # Wait for transaction to be mined\n")
                    f.write("    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)\n")
                    f.write("    return tx_receipt\n\n")

# Example usage
output_script_path = 'web3_script.py'
create_web3_script(output_script_path)
