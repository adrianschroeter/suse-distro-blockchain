import json
import os
import sys

def write_abi_to_env(contract_name):
    # Adjust file path to point to the correct location
    print("getting abi for " + contract_name)
    file_path = os.path.join("..", "ape", ".build", f"{contract_name}.json")
    print("this is filepath"+file_path)
    # Read ABI from the JSON file
    try:
        with open(file_path, 'r') as file:
            contract_data = json.load(file)
            abi = contract_data['abi']
    except FileNotFoundError:
        print(f"File {file_path} not found.")
        return
    except KeyError:
        print(f"ABI not found in {file_path}.")
        return

    # Adjust .env file path to be at the same level as pyremix folder
    env_file_path = os.path.join("..", ".env")
    abi_str = json.dumps(abi)
    
    # Read the existing .env file and replace or append ABI
    new_lines = []
    abi_line = f"ABI={abi_str}\n"
    if os.path.exists(env_file_path):
        with open(env_file_path, "r") as file:
            lines = file.readlines()
            for line in lines:
                if not line.startswith("ABI"):
                    new_lines.append(line)
    new_lines.append(abi_line)
    
    with open(env_file_path, "w") as file:
        file.writelines(new_lines)

    print("ABI written to .env file.")

# Example usage
if len(sys.argv) > 1:
    contract_name = sys.argv[1]
else:
    print("No contract name provided.")
    sys.exit(1)

write_abi_to_env(contract_name)
