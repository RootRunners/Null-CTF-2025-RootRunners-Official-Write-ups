from web3 import Web3

RPC_URL = "http://public.ctf.r0devnull.team:3001/6f5b4875-c6a9-48c8-8152-ea20494e8e18"
SETUP_CONTRACT_ADDR = "0x9b198D366513F2814779223057021f57A034D7FC"

w3 = Web3(Web3.HTTPProvider(RPC_URL))
coin_slot = w3.eth.get_storage_at(SETUP_CONTRACT_ADDR, 0)
coin_address = w3.to_checksum_address(coin_slot[-20:])
print(f"Coin address: {coin_address}")

coin_balance = w3.eth.get_balance(coin_address)
print(f"Coin contract balance: {w3.from_wei(coin_balance, 'ether')} ETH")

is_solved_abi = [{"inputs":[],"name":"isSolved","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"}]
setup_contract = w3.eth.contract(address=SETUP_CONTRACT_ADDR, abi=is_solved_abi)
is_solved = setup_contract.functions.isSolved().call()
print(f"Solved: {is_solved}")
