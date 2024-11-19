# pyremix

Create a virtual environment
I'm naming my virtual environment here `myv`.
```bash
python3 -m venv ./myv
```
Make sure that if you name your virtual environment something else, you include it in the gitignore.

Install requirements:
```bash
pip install -r requirements.txt
```
Make sure to have foundry installed.  
You need anvil running in a seperate terminal for this.  
Run in a seperate terminal:
```bash
anvil
```

Inside the `ape` folder there is a sample ape project.  
Go to the folder and run `ape compile` to compile the contract and then run the deploy script.  
You can also run the deploy script directly and ape will compile your project, if you haven't done so.

Make sure to check the deploy script and replace the account with your account name.  
When running the command you need to enter the name of the contract. Make sure it's the same as the name you've given the `.vy` file name.  
```bash
ape run scripts/deploy.py --network http://localhost:8545
```
