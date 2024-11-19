from ape import accounts, project
from datetime import datetime
import os
import subprocess

def pyremix(contract):
    contract_name = contract
    subprocess.run(["python", "../pyremix/create_abi.py", contract_name])
    subprocess.run(["python", "../pyremix/createweb3.py"])
    subprocess.run(["python", "../pyremix/create_streamlit_abi.py", contract_name])

    #subprocess.run(["python", "../pyremix/run_setup.py"])

    # Run Streamlit app
    subprocess.run(["streamlit", "run", "streamlit_app.py"])


def main(): 
    #contract_name = input("Enter contract name: ")
    contracts_dir = os.path.join("./", "contracts")
    contract_files = [f for f in os.listdir(contracts_dir) if os.path.isfile(os.path.join(contracts_dir, f)) and f.endswith('.vy')]
    contract_names = [os.path.splitext(f)[0] for f in contract_files]

    # Present contract names to the user
    print("Available contracts:")
    for i, name in enumerate(contract_names, start=1):
        print(f"{i}: {name}")

    # Get user choice
    contract_choice = None
    while contract_choice not in range(1, len(contract_names) + 1):
        try:
            contract_choice = int(input("Enter the number of the contract you want to deploy: "))
        except ValueError:
            pass  # Invalid input, prompt again

    contract_name = contract_names[contract_choice - 1]

    # Initialize deployer account and print balance 
    dev_account = accounts.load("anvil0") 
    print(f'The account balance is: {dev_account.balance / 1e18} ETH')

    #####CHOOSE NETWORK FOR LOCAL UI###
    # Present network choices and get user input
    networks = {'1': 'anvil', '2': 'scroll-test-net'}
    print("Choose the network:")
    for key, value in networks.items():
        print(f"{key}: {value}")

    choice = None
    while choice not in networks:
        choice = input("Enter your choice (1 or 2): ")

    chosen_network = networks[choice]
    chain_id = "31337" if chosen_network == "anvil" else "534351"
    #######


    # Deploy the smart contract and print a message 
    contract_class = getattr(project, contract_name)
    deployed_contract = dev_account.deploy(contract_class)
    print("Contract deployed!") 
    contract_address = deployed_contract.address

    # Get the current timestamp
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Write the contract name, address, and timestamp to a file
    with open("deployed_contracts.txt", "a") as file:
        file.write(f"{current_time}: {contract_name} - Address: {contract_address}\n")
    print(f"{contract_name} address {contract_address} recorded with timestamp.")

    # Write CONTRACT_ADDRESS to .env file
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

    # Run 'run_setup.py' in 'pyremix' folder
    pyremix(contract=contract_name)
    




# from ape import accounts, project

# def main(): 
#       # Initialize deployer account and print balance 
#     dev_account = accounts.load("scrollsep") 
#     print(f'The account balance is: {dev_account.balance / 1e18} ETH')  
#      # Deploy the smart contract and print a message 
#     kw = {
#         'type': 0
#     }
#     dev_account.deploy(project.hello, **kw) 
#     print("Contract deployed!") 