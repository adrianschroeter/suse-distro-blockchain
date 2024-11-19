import json
from dotenv import load_dotenv
import os

load_dotenv(dotenv_path='../.env')

def create_streamlit_app_from_abi(abi, streamlit_app_file):
    with open(streamlit_app_file, 'w') as app_file:
        # Write the imports and basic setup for Streamlit app
        app_file.write("import streamlit as st\n")
        app_file.write("from web3_script import *\n\n")  # Adjust this import according to your web3 script
        app_file.write("st.title('Web3 Contract Interaction')\n\n")

        # Generate Streamlit widgets for each function in the ABI
        for item in abi:
            if item['type'] == 'function':
                function_name = item['name']
                params = item['inputs']

                app_file.write(f"st.header('Function: {function_name}')\n")
                param_values = []
                for param in params:
                    param_name = param['name']
                    param_type = param['type']
                    key = f"{function_name}_{param_name}"
                    if param_type == 'bytes':
                        app_file.write(f"{param_name} = st.text_input('Enter {param_name}', key='{key}').encode()\n")
                    elif 'uint' in param_type or 'int' in param_type:
                        app_file.write(f"{param_name} = st.number_input('Enter {param_name}', step=1, key='{key}')\n")
                    else:
                        app_file.write(f"{param_name} = st.text_input('Enter {param_name}', key='{key}')\n")
                    param_values.append(param_name)

                # Create a button for the function
                app_file.write(f"if st.button('Execute {function_name}', key='{function_name}_button'):\n")
                app_file.write(f"    result = {function_name}(" + ', '.join(param_values) + ")\n")
                app_file.write("    st.write(f'Result: {result}')\n\n")

# Example usage
contract_abi = json.loads(os.getenv('ABI', '[]'))
streamlit_app_path = 'streamlit_app.py'  # Path for the new Streamlit app

create_streamlit_app_from_abi(contract_abi, streamlit_app_path)
