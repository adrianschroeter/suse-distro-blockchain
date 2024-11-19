from ape import accounts, project
import os
import subprocess

def pyremix(contract):
    contract_name = contract
    subprocess.run(["python", "../pyremix/create_abi.py", contract_name])
    subprocess.run(["python", "../pyremix/createweb3.py"])
    subprocess.run(["python", "../pyremix/create_streamlit_abi.py", contract_name])


    # Run Streamlit app
    subprocess.run(["streamlit", "run", "streamlit_app.py"])


def main(): 
    contract_name = input("Enter contract name: ")

    # Initialize deployer account and print balance 
    dev_account = accounts.load("scrollsep") 
    print(f'The account balance is: {dev_account.balance / 1e18} ETH')  

    #####CHOOSE NETWORK FOR LOCAL UI###
    chain_id = "534351"
    ###################################

    # Deploy the smart contract and print a message 
    contract_class = getattr(project, contract_name)
    kw = {
        'type':0
    }
    deployed_contract = dev_account.deploy(contract_class, **kw)
    print("Contract deployed!")

    contract_address = deployed_contract.address
    ###################################
    
    # Write CONTRACT_ADDRESS + CHAINID to .env file
    env_file_path = "../.env"
    new_lines = []
    contract_address_line = f"CONTRACT_ADDRESS={contract_address}\n"
    chain_id_line = f"CHAIN_ID={chain_id}\n"
    if os.path.exists(env_file_path):
        with open(env_file_path, "r") as file:
            lines = file.readlines()
            for line in lines:
                if not line.startswith("CONTRACT_ADDRESS") and not line.startswith("CHAIN_ID"):
                    new_lines.append(line)
    new_lines.append(contract_address_line)
    new_lines.append(chain_id_line)
    with open(env_file_path, "w") as file:
        file.writelines(new_lines)
    ###################################   
    
    # Run scripts for local UI in 'pyremix' folder
    pyremix(contract=contract_name)
    