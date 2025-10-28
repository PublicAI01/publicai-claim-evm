# PublicAI Claim EVM Contract

An upgradeable reward claiming system for Ethereum Virtual Machine (EVM) compatible blockchains.

## Overview

This is a reward claiming system that allows users to claim USDT and PUBLIC token rewards through signature verification. The contract uses the UUPS (Universal Upgradeable Proxy Standard) proxy pattern for upgradeability.

## Features

- ✅ **Signature-based Claiming**: Ed25519 signature verification for secure reward claims
- ✅ **Dual Token Support**: Support for both USDT and PUBLIC token rewards
- ✅ **Replay Attack Prevention**: Nonce mechanism to prevent duplicate claims
- ✅ **Task Pool Management**: Create and manage multiple reward pools
- ✅ **Access Control**: Owner-based permission management using OpenZeppelin's Ownable
- ✅ **Reentrancy Protection**: ReentrancyGuard to prevent reentrancy attacks
- ✅ **Upgradeability**: UUPS proxy pattern for contract upgrades

## Architecture

### Data Structures

```solidity
// Reward types
enum RewardType {
    USDT,    // 0: USDT token
    PUBLIC   // 1: PUBLIC token
}

// User reward record
struct RewardItem {
    address user;      // User address
    uint16 task;       // Task ID
    uint128 reward;    // Accumulated reward amount
    uint16 times;      // Claim count (nonce)
}

// Pool information
struct PoolInfo {
    uint128 total;     // Total reward allocation
    uint128 claimed;   // Amount already claimed
}
```

## Installation

```bash
# Install dependencies
npm install

# Compile contracts
npx hardhat compile

# Run tests
npx hardhat test
```

## Deployment

### Deploy Upgradeable Contract

```bash
# Deploy to local network
npx hardhat run ignition/modules/deploy.ts --network hardhat

# Deploy to testnet/mainnet
npx hardhat run ignition/modules/deploy.ts --network <network-name>
```

### Deployment Script Usage

```typescript
import { ethers, upgrades } from "hardhat";

const PublicAIClaimUpgradeable = await ethers.getContractFactory("PublicAIClaimUpgradeable");
const claim = await upgrades.deployProxy(
    PublicAIClaimUpgradeable,
    [signerPublicKeyHash, usdtTokenAddress, publicTokenAddress],
    { kind: "uups" }
);
```

## Contract Functions

### Owner Functions

#### Set Signer
```solidity
function setSigner(bytes32 newSigner) external onlyOwner
```
Update the Ed25519 public key hash used for signature verification.

#### Set Token Addresses
```solidity
function setUsdtToken(address newToken) external onlyOwner
function setPublicToken(address newToken) external onlyOwner
```
Update the USDT or PUBLIC token contract addresses.

#### Register Reward Pool
```solidity
function registerPool(uint16 task, uint128 reward) external onlyOwner
```
Register a new reward pool for a specific task.

#### Withdraw Tokens
```solidity
function withdraw(uint128 amount, RewardType tokenType) external onlyOwner
```
Withdraw tokens from the contract.

### User Functions

#### Claim USDT Rewards
```solidity
function claim(
    uint16 task,              // Task ID
    uint16 nonce,             // Current nonce (replay prevention)
    uint128 reward,           // Reward amount
    address receiver,         // Receiver address
    bytes memory signature    // Ed25519 signature (64 bytes)
) external nonReentrant
```

#### Claim PUBLIC Rewards
```solidity
function claimPublic(
    uint16 task,
    uint16 nonce,
    uint128 reward,
    address receiver,
    bytes memory signature
) external nonReentrant
```

### View Functions

#### Get Pool Information
```solidity
function getPool(uint16 task) external view returns (PoolInfo memory)
```

#### Get User Rewards
```solidity
function getReward(uint16 task, address user) external view returns (RewardItem memory)
```

#### Get User Nonce
```solidity
function getClaimNonce(uint16 task, address user) external view returns (uint16)
```

#### Get Statistics
```solidity
function getTotalClaimed() external view returns (uint128)
function getTotalClaimedPublic() external view returns (uint128)
function getStateVersion() external view returns (uint32)
function version() external pure returns (string memory)
```

## Signature Generation

The contract uses Ed25519 signature verification. Message format:

### USDT Claim Signature
```solidity
bytes32 messageHash = keccak256(
    abi.encodePacked(task, nonce, reward, receiver)
);
```

### PUBLIC Claim Signature
```solidity
bytes32 messageHash = keccak256(
    abi.encodePacked(task, nonce, reward, receiver, uint8(RewardType.PUBLIC))
);
```

**Note**: The current implementation uses a simplified signature verification for demonstration purposes. For production use, implement full Ed25519 signature verification using a proper library.

## Testing

The project includes a comprehensive test suite:

```bash
# Run all tests
npx hardhat test

# Run with gas reporting
REPORT_GAS=true npx hardhat test

# Run specific test file
npx hardhat test test/PublicAIClaimUpgradeable.test.ts
```

### Test Coverage

- ✅ Contract deployment and initialization
- ✅ Access control (owner operations)
- ✅ Pool management (create, query)
- ✅ USDT and PUBLIC token claiming
- ✅ Nonce verification and replay attack prevention
- ✅ Multi-user and multi-task scenarios
- ✅ Reentrancy attack protection
- ✅ Contract upgrades (upgradeability)
- ✅ State preservation (after upgrade)

### Test Results

```
43 passing (2s)
```

All test cases pass successfully!

## Gas Consumption

| Operation | Average Gas | Min Gas | Max Gas |
|-----------|------------|---------|---------|
| Deploy Upgradeable Contract | 2,149,250 | - | - |
| First Claim | 184,431 | 76,361 | 184,431 |
| Subsequent Claims | 154,705 | 76,361 | 184,431 |
| Register Pool | 74,986 | - | 74,986 |
| Withdraw Tokens | 66,257 | 66,222 | 66,292 |
| Upgrade Contract | 32,486 | - | 32,486 |

## Security Considerations

1. **Signature Verification**: Current implementation uses simplified signature verification. Production deployments must use full Ed25519 verification library.
2. **Private Key Management**: The signing private key must be securely stored. Compromise will allow arbitrary claims.
3. **Token Authorization**: Sufficient tokens must be transferred to the contract address after deployment.
4. **Upgrade Permissions**: Only the contract owner can upgrade. Secure the owner private key properly.
5. **Auditing**: Professional security audits are recommended before production deployment.

## Upgrading the Contract

### Upgrade Script Usage

```bash
PROXY_ADDRESS=0x... npx hardhat run ignition/modules/upgrade.ts --network <network-name>
```

The UUPS proxy pattern ensures:
- State is preserved after upgrades
- Only owner can authorize upgrades
- Upgrade history is tracked on-chain

## Project Structure

```
.
├── contracts/
│   ├── PublicAIClaimUpgradeable.sol   # Upgradeable claim contract
│   └── MockERC20.sol                  # Test ERC20 token
├── test/
│   └── PublicAIClaimUpgradeable.test.ts # Comprehensive test suite
├── ignition/
│   └── modules/
│       └── deploy.ts                  # Deployment script
├── hardhat.config.ts                  # Hardhat configuration
└── README.md                          # This file
```

## Development Environment

- Solidity: ^0.8.28
- Hardhat: ^2.26.3
- OpenZeppelin Contracts: ^5.4.0
- OpenZeppelin Contracts Upgradeable: ^5.4.0
- OpenZeppelin Hardhat Upgrades: ^3.9.1

## Environment Variables

Create a `.env` file for deployment:

```bash
# Network RPC URLs
MAINNET_RPC_URL=https://...
TESTNET_RPC_URL=https://...

# Private keys (never commit!)
PRIVATE_KEY=your_private_key_here

# Contract parameters
SIGNER_PUBLIC_KEY=0x...
USDT_TOKEN=0x...
PUBLIC_TOKEN=0x...

# Etherscan API key (for verification)
ETHERSCAN_API_KEY=your_api_key_here
```

## License

MIT License

## Contributing

Contributions are welcome! Please submit issues and pull requests on GitHub.

## Support

For questions or issues, please open a GitHub issue.
