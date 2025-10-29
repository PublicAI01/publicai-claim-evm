// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/**
 * @title PublicAIClaimUpgradeable
 * @dev An upgradeable contract for claiming rewards with Ed25519 signature verification
 * Ported from NEAR contract functionality to EVM with UUPS proxy pattern
 */
contract PublicAIClaimUpgradeable is
    Initializable,
    OwnableUpgradeable,
    ReentrancyGuardUpgradeable,
    UUPSUpgradeable
{
    // Reward types enum
    enum RewardType {
        USDT,
        PUBLIC
    }

    // Reward item structure for tracking user rewards
    struct RewardItem {
        address user;
        uint16 task;
        uint128 reward;
        uint16 times; // nonce counter
    }

    // Pool information structure
    struct PoolInfo {
        uint128 total;
        uint128 claimed;
    }

    // Voter reward item structure for tracking user rewards
    struct VoterRewardItem {
        address user;
        uint128 reward;
        uint32 timestamp;
        uint16 times; // nonce counter
    }

    // Pool structure with reward mapping
    struct Pool {
        uint128 total;
        uint128 claimed;
        mapping(address => RewardItem) rewards;
    }

    // Pool structure with voter reward mapping
    struct VoterPool {
        uint128 total;
        uint128 claimed;
        mapping(address => VoterRewardItem) rewards;
    }

    // State variables
    address public signer; // Signer address for ECDSA verification
    uint128 public totalClaimed;
    uint128 public totalClaimedPublic;
    IERC20 public usdtToken;
    IERC20 public publicToken;

    // Mapping from task ID to Pool
    mapping(uint16 => Pool) public pools;
    mapping(uint16 => bool) public poolExists;
    VoterPool public voterPool;

    // Events
    event PoolRegistered(uint16 indexed task, uint128 reward);
    event RewardClaimed(
        address indexed user,
        uint16 indexed task,
        uint128 reward,
        uint16 nonce,
        RewardType rewardType
    );
    event SignerUpdated(address newSigner);
    event TokenUpdated(address token, RewardType tokenType);
    event Withdrawn(address indexed receiver, uint128 amount, RewardType tokenType);
    event VoterRewardClaimed(
        address indexed user,
        uint128 reward,
        uint32 timestamp,
        uint16 nonce,
        RewardType rewardType
    );

    // Custom errors
    error InvalidSignerLength();
    error OnlyOwnerMethod();
    error InvalidSignature();
    error ClaimInfoError();
    error UnauthorizedAccount();
    error InvalidNonce();
    error PoolNotExist();
    error ClaimTypeError();
    error OverflowError();
    error TimestampError();
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @dev Initialize the contract (replaces constructor for upgradeable contracts)
     * @param _signer Signer address for ECDSA verification
     * @param _usdtToken USDT token contract address
     * @param _publicToken PUBLIC token contract address
     */
    function initialize(
        address _signer,
        address _usdtToken,
        address _publicToken
    ) public initializer {
        require(_signer != address(0), "Invalid signer");
        require(_usdtToken != address(0), "Invalid USDT token");
        require(_publicToken != address(0), "Invalid PUBLIC token");

        __Ownable_init(msg.sender);
        __ReentrancyGuard_init();
        __UUPSUpgradeable_init();

        signer = _signer;
        usdtToken = IERC20(_usdtToken);
        publicToken = IERC20(_publicToken);
        totalClaimed = 0;
        totalClaimedPublic = 0;
    }

    /**
     * @dev Authorize upgrade (required by UUPSUpgradeable)
     */
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    /**
     * @dev Update the signer address
     * @param newSigner New signer address for ECDSA verification
     */
    function setSigner(address newSigner) external onlyOwner {
        require(newSigner != address(0), "Invalid signer");
        signer = newSigner;
        emit SignerUpdated(newSigner);
    }

    /**
     * @dev Update the USDT token address
     * @param newToken New USDT token address
     */
    function setUsdtToken(address newToken) external onlyOwner {
        require(newToken != address(0), "Invalid token");
        usdtToken = IERC20(newToken);
        emit TokenUpdated(newToken, RewardType.USDT);
    }

    /**
     * @dev Update the PUBLIC token address
     * @param newToken New PUBLIC token address
     */
    function setPublicToken(address newToken) external onlyOwner {
        require(newToken != address(0), "Invalid token");
        publicToken = IERC20(newToken);
        emit TokenUpdated(newToken, RewardType.PUBLIC);
    }

    /**
     * @dev Register a new reward pool for a task
     * @param task Task ID
     * @param reward Total reward amount for the pool
     */
    function registerPool(uint16 task, uint128 reward) external onlyOwner {
        if (!poolExists[task]) {
            Pool storage pool = pools[task];
            pool.total = reward;
            pool.claimed = 0;
            poolExists[task] = true;
            emit PoolRegistered(task, reward);
        }
    }

    /**
     * @dev Get pool information
     * @param task Task ID
     * @return PoolInfo structure with total and claimed amounts
     */
    function getPool(uint16 task) external view returns (PoolInfo memory) {
//        require(poolExists[task], "Pool does not exist");
        Pool storage pool = pools[task];
        return PoolInfo({total: pool.total, claimed: pool.claimed});
    }

    /**
     * @dev Get reward information for a user in a specific task
     * @param task Task ID
     * @param user User address
     * @return RewardItem structure
     */
    function getReward(uint16 task, address user) external view returns (RewardItem memory) {
//        require(poolExists[task], "Pool does not exist");
        return pools[task].rewards[user];
    }

    /**
     * @dev Get voter reward information for a user
     * @param user User address
     * @return RewardItem structure
     */
    function getVoterReward(address user) external view returns (VoterRewardItem memory) {
        return voterPool.rewards[user];
    }

    /**
     * @dev Get the current nonce for a user in a specific task
     * @param task Task ID
     * @param user User address
     * @return Current nonce value
     */
    function getClaimNonce(uint16 task, address user) external view returns (uint16) {
        if (!poolExists[task]) {
            return 0;
        }
        RewardItem storage rewardItem = pools[task].rewards[user];
        return rewardItem.times;
    }

    /**
     * @dev Verify ECDSA (secp256k1) signature
     * @param messageHash The message hash that was signed
     * @param signature The signature bytes (65 bytes: r, s, v)
     * @param signerAddress The expected signer address
     * @return bool True if signature is valid
     */
    function verifySignature(
        bytes32 messageHash,
        bytes memory signature,
        address signerAddress
    ) internal pure returns (bool) {
        require(signature.length == 65, "Invalid signature length");

        bytes32 r;
        bytes32 s;
        uint8 v;

        // Extract r, s, v from signature
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }

        // Ethereum signatures use v = 27 or 28
        if (v < 27) {
            v += 27;
        }

        require(v == 27 || v == 28, "Invalid signature v value");

        // Create Ethereum Signed Message hash
        // This is what eth_sign and personal_sign produce
        bytes32 ethSignedMessageHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash)
        );

        // Recover the signer address from the signature
        address recoveredSigner = ecrecover(ethSignedMessageHash, v, r, s);

        // Check if recovered address matches expected signer
        return (recoveredSigner != address(0) && recoveredSigner == signerAddress);
    }

    /**
     * @dev Claim USDT rewards with signature verification
     * @param task Task ID
     * @param nonce Nonce for replay protection
     * @param reward Reward amount
     * @param receiver Receiver address
     * @param signature Ed25519 signature
     */
    function claim(
        uint16 task,
        uint16 nonce,
        uint128 reward,
        address receiver,
        bytes memory signature
    ) external nonReentrant {
        require(msg.sender == receiver, "Unauthorized account");

        // Create message hash
        bytes32 messageHash = keccak256(
            abi.encodePacked(task, nonce, reward, receiver)
        );

        // Verify signature
        require(
            verifySignature(messageHash, signature, signer),
            "Invalid signature"
        );

        // Initialize pool if it doesn't exist
        if (!poolExists[task]) {
            Pool storage newPool = pools[task];
            newPool.total = 1000000000; // Meaningless default value
            newPool.claimed = 0;
            poolExists[task] = true;
        }

        Pool storage pool = pools[task];
        RewardItem storage rewardItem = pool.rewards[receiver];

        // Check nonce for replay protection
        if (rewardItem.user != address(0)) {
            require(rewardItem.times == nonce, "Invalid nonce");

            // Update existing reward
            uint128 newReward = rewardItem.reward + reward;
            require(newReward >= rewardItem.reward, "Overflow in reward");
            rewardItem.reward = newReward;
            rewardItem.times += 1;
        } else {
            // Create new reward item
            require(nonce == 0, "Invalid nonce for new user");
            rewardItem.user = receiver;
            rewardItem.task = task;
            rewardItem.reward = reward;
            rewardItem.times = 1;
        }

        // Update pool and total claimed
        uint128 newClaimed = pool.claimed + reward;
        require(newClaimed >= pool.claimed, "Overflow in pool claimed");
        pool.claimed = newClaimed;

        uint128 newTotalClaimed = totalClaimed + reward;
        require(newTotalClaimed >= totalClaimed, "Overflow in total claimed");
        totalClaimed = newTotalClaimed;

        // Transfer tokens
        require(
            usdtToken.transfer(receiver, uint256(reward)),
            "Token transfer failed"
        );

        emit RewardClaimed(receiver, task, reward, nonce, RewardType.USDT);
    }

    /**
     * @dev Claim PUBLIC token rewards with signature verification
     * @param task Task ID
     * @param nonce Nonce for replay protection
     * @param reward Reward amount
     * @param receiver Receiver address
     * @param signature Ed25519 signature
     */
    function claimPublic(
        uint16 task,
        uint16 nonce,
        uint128 reward,
        address receiver,
        bytes memory signature
    ) external nonReentrant {
        require(msg.sender == receiver, "Unauthorized account");

        // Create message hash with reward type
        bytes32 messageHash = keccak256(
            abi.encodePacked(task, nonce, reward, receiver, uint8(RewardType.PUBLIC))
        );

        // Verify signature
        require(
            verifySignature(messageHash, signature, signer),
            "Invalid signature"
        );

        // Initialize pool if it doesn't exist
        if (!poolExists[task]) {
            Pool storage newPool = pools[task];
            newPool.total = 1000000000; // Meaningless default value
            newPool.claimed = 0;
            poolExists[task] = true;
        }

        Pool storage pool = pools[task];
        RewardItem storage rewardItem = pool.rewards[receiver];

        // Check nonce for replay protection
        if (rewardItem.user != address(0)) {
            require(rewardItem.times == nonce, "Invalid nonce");

            // Update existing reward
            uint128 newReward = rewardItem.reward + reward;
            require(newReward >= rewardItem.reward, "Overflow in reward");
            rewardItem.reward = newReward;
            rewardItem.times += 1;
        } else {
            // Create new reward item
            require(nonce == 0, "Invalid nonce for new user");
            rewardItem.user = receiver;
            rewardItem.task = task;
            rewardItem.reward = reward;
            rewardItem.times = 1;
        }

        // Update pool and total claimed
        uint128 newClaimed = pool.claimed + reward;
        require(newClaimed >= pool.claimed, "Overflow in pool claimed");
        pool.claimed = newClaimed;

        uint128 newTotalClaimedPublic = totalClaimedPublic + reward;
        require(newTotalClaimedPublic >= totalClaimedPublic, "Overflow in total claimed");
        totalClaimedPublic = newTotalClaimedPublic;

        // Transfer tokens
        require(
            publicToken.transfer(receiver, uint256(reward)),
            "Token transfer failed"
        );

        emit RewardClaimed(receiver, task, reward, nonce, RewardType.PUBLIC);
    }

    /**
     * @dev Withdraw tokens from the contract (owner only)
     * @param amount Amount to withdraw
     * @param tokenType Type of token to withdraw (USDT or PUBLIC)
     */
    function withdraw(uint128 amount, RewardType tokenType) external onlyOwner {
        IERC20 token = tokenType == RewardType.USDT ? usdtToken : publicToken;

        require(
            token.transfer(owner(), uint256(amount)),
            "Token transfer failed"
        );

        emit Withdrawn(owner(), amount, tokenType);
    }

    /**
     * @dev Claim USDT rewards for voter with signature verification
     * @param nonce Nonce for replay protection
     * @param timestamp Timestamp when the claim was created
     * @param reward Reward amount
     * @param receiver Receiver address
     * @param signature Ed25519 signature
     */
    function voter_claim(
        uint16 nonce,
        uint32 timestamp,
        uint128 reward,
        address receiver,
        bytes memory signature
    ) external nonReentrant {
        if (msg.sender != receiver) revert UnauthorizedAccount();

        // Create message hash
        bytes32 messageHash = keccak256(
            abi.encodePacked(nonce, timestamp, reward, receiver)
        );

        // Verify signature
        if (!verifySignature(messageHash, signature, signer)) revert InvalidSignature();

        // Initialize the reward item if it doesn't already exist
        VoterRewardItem storage rewardItem = voterPool.rewards[receiver];
        if (rewardItem.user != address(0)) {
            // Check nonce for replay protection
            if (rewardItem.times != nonce) revert InvalidNonce();

            // Update existing reward
            uint128 newReward = rewardItem.reward + reward;
            if (newReward < rewardItem.reward) revert OverflowError();

            rewardItem.reward = newReward;
            rewardItem.times += 1;
            if(rewardItem.timestamp > timestamp) revert TimestampError();
            rewardItem.timestamp = timestamp;
        } else {
            // Create new reward item
            if (nonce != 0) revert InvalidNonce();

            rewardItem.user = receiver;
            rewardItem.reward = reward;
            rewardItem.times = 1;
            rewardItem.timestamp = timestamp;
        }

        // Update total claimed
        uint128 newTotalClaimed = voterPool.claimed + reward;
        if (newTotalClaimed < voterPool.claimed) revert OverflowError();

        voterPool.claimed = newTotalClaimed;

        // Transfer tokens
        bool success = usdtToken.transfer(receiver, uint256(reward));
        if (!success) revert ClaimInfoError();

        emit VoterRewardClaimed(
            receiver,
            reward,
            timestamp,
            nonce,
            RewardType.USDT
        );
    }


    /**
     * @dev Claim PUBLIC token rewards for voter with signature verification
     * @param nonce Nonce for replay protection
     * @param timestamp Timestamp when the claim was created
     * @param reward Reward amount
     * @param receiver Receiver address
     * @param signature Ed25519 signature
     */
    function voter_claim_public(
        uint16 nonce,
        uint32 timestamp,
        uint128 reward,
        address receiver,
        bytes memory signature
    ) external nonReentrant {
        if (msg.sender != receiver) revert UnauthorizedAccount();

        // Create message hash
        bytes32 messageHash = keccak256(
            abi.encodePacked(nonce, timestamp, reward, receiver)
        );

        // Verify signature
        if (!verifySignature(messageHash, signature, signer)) revert InvalidSignature();


        // Initialize the reward item if it doesn't already exist
        VoterRewardItem storage rewardItem = voterPool.rewards[receiver];
        if (rewardItem.user != address(0)) {
            // Check nonce for replay protection
            if (rewardItem.times != nonce) revert InvalidNonce();

            // Update existing reward
            uint128 newReward = rewardItem.reward + reward;
            if (newReward < rewardItem.reward) revert OverflowError();

            rewardItem.reward = newReward;
            rewardItem.times += 1;
            if(rewardItem.timestamp > timestamp) revert TimestampError();
            rewardItem.timestamp = timestamp;
        } else {
            // Create new reward item
            if (nonce != 0) revert InvalidNonce();

            rewardItem.user = receiver;
            rewardItem.reward = reward;
            rewardItem.times = 1;
            rewardItem.timestamp = timestamp;
        }

        // Update total claimed
        uint128 newTotalClaimedPublic = totalClaimedPublic + reward;
        if (newTotalClaimedPublic < totalClaimedPublic) revert OverflowError();

        totalClaimedPublic = newTotalClaimedPublic;

        // Transfer tokens
        bool success = publicToken.transfer(receiver, uint256(reward));
        if (!success) revert ClaimInfoError();

        emit VoterRewardClaimed(
            receiver,
            reward,
            timestamp,
            nonce,
            RewardType.PUBLIC
        );
    }

}
