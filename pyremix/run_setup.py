import subprocess

def run_scripts_in_order():
    scripts = [("create_abi.py", "argument_for_abi"), "createweb3.py", "create_streamlit_abi.py"]

    for script in scripts:
        if isinstance(script, tuple):
            script_name, arg = script
            command = ["python", script_name, arg]
        else:
            command = ["python", script]

        try:
            subprocess.run(command, check=True)
            print(f"Successfully ran {script}")
        except subprocess.CalledProcessError as e:
            print(f"An error occurred while running {script}: {e}")
            break

if __name__ == "__main__":
    run_scripts_in_order()
