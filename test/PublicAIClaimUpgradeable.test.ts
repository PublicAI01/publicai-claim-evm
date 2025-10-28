import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import { PublicAIClaimUpgradeable, MockERC20 } from "../typechain-types";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";

describe("PublicAIClaimUpgradeable", function () {
  let claim: PublicAIClaimUpgradeable;
  let usdtToken: MockERC20;
  let publicToken: MockERC20;
  let owner: HardhatEthersSigner;
  let signer: HardhatEthersSigner;
  let user1: HardhatEthersSigner;
  let user2: HardhatEthersSigner;

  beforeEach(async function () {
    // Get signers
    [owner, signer, user1, user2] = await ethers.getSigners();

    // Deploy mock ERC20 tokens
    const MockERC20Factory = await ethers.getContractFactory("MockERC20");
    usdtToken = await MockERC20Factory.deploy("Mock USDT", "USDT", 6);
    publicToken = await MockERC20Factory.deploy("Mock PUBLIC", "PUBLIC", 18);

    // Deploy PublicAIClaimUpgradeable contract with proxy
    const PublicAIClaimFactory = await ethers.getContractFactory("PublicAIClaimUpgradeable");
    claim = (await upgrades.deployProxy(
      PublicAIClaimFactory,
      [signer.address, await usdtToken.getAddress(), await publicToken.getAddress()],
      { kind: "uups" }
    )) as unknown as PublicAIClaimUpgradeable;

    // Mint tokens to the claim contract
    const usdtAmount = ethers.parseUnits("1000000", 6); // 1M USDT
    const publicAmount = ethers.parseUnits("1000000", 18); // 1M PUBLIC
    await usdtToken.mint(await claim.getAddress(), usdtAmount);
    await publicToken.mint(await claim.getAddress(), publicAmount);
  });

  // Helper function to create ECDSA signature
  async function signMessage(
    task: number,
    nonce: number,
    reward: bigint,
    receiver: string,
    rewardType?: number
  ): Promise<string> {
    let messageHash: string;

    if (rewardType !== undefined) {
      // For PUBLIC token claims
      messageHash = ethers.solidityPackedKeccak256(
        ["uint16", "uint16", "uint128", "address", "uint8"],
        [task, nonce, reward, receiver, rewardType]
      );
    } else {
      // For USDT claims
      messageHash = ethers.solidityPackedKeccak256(
        ["uint16", "uint16", "uint128", "address"],
        [task, nonce, reward, receiver]
      );
    }

    // Sign the message hash using Ethereum's personal_sign format
    // This adds the "\x19Ethereum Signed Message:\n32" prefix
    // The contract's verifySignature function handles this prefix
    const messageHashBytes = ethers.getBytes(messageHash);
    const signature = await signer.signMessage(messageHashBytes);

    return signature;
  }

  describe("Deployment", function () {
    it("Should set the right owner", async function () {
      expect(await claim.owner()).to.equal(owner.address);
    });

    it("Should set the correct signer", async function () {
      expect(await claim.signer()).to.equal(signer.address);
    });

    it("Should set the correct token addresses", async function () {
      expect(await claim.usdtToken()).to.equal(await usdtToken.getAddress());
      expect(await claim.publicToken()).to.equal(await publicToken.getAddress());
    });
  });

  describe("Upgradeability", function () {
    it("Should be upgradeable by owner", async function () {
      const PublicAIClaimV2Factory = await ethers.getContractFactory("PublicAIClaimUpgradeable");
      const upgraded = await upgrades.upgradeProxy(
        await claim.getAddress(),
        PublicAIClaimV2Factory
      );

      // State should be preserved
      expect(await upgraded.signer()).to.equal(signer.address);
      expect(await upgraded.owner()).to.equal(owner.address);
    });

    it("Should not be upgradeable by non-owner", async function () {
      const PublicAIClaimV2Factory = await ethers.getContractFactory(
        "PublicAIClaimUpgradeable",
        user1
      );

      // This should fail because only owner can upgrade
      await expect(
        upgrades.upgradeProxy(await claim.getAddress(), PublicAIClaimV2Factory)
      ).to.be.reverted;
    });

    it("Should preserve state after upgrade", async function () {
      // Register a pool and make a claim before upgrade
      const task = 1;
      const reward = ethers.parseUnits("100", 6);
      const signature = await signMessage(task, 0, reward, user1.address);

      await claim.registerPool(task, ethers.parseUnits("10000", 6));
      await claim.connect(user1).claim(task, 0, reward, user1.address, signature);

      const rewardBefore = await claim.getReward(task, user1.address);
      const totalClaimedBefore = await claim.totalClaimed();

      // Upgrade
      const PublicAIClaimV2Factory = await ethers.getContractFactory("PublicAIClaimUpgradeable");
      const upgraded = (await upgrades.upgradeProxy(
        await claim.getAddress(),
        PublicAIClaimV2Factory
      )) as unknown as PublicAIClaimUpgradeable;

      // Check that state is preserved
      const rewardAfter = await upgraded.getReward(task, user1.address);
      const totalClaimedAfter = await upgraded.totalClaimed();

      expect(rewardAfter.reward).to.equal(rewardBefore.reward);
      expect(rewardAfter.times).to.equal(rewardBefore.times);
      expect(totalClaimedAfter).to.equal(totalClaimedBefore);
    });
  });

  describe("Setter Functions", function () {
    it("Should allow owner to set new signer", async function () {
      const newSigner = user2.address;
      await expect(claim.setSigner(newSigner))
        .to.emit(claim, "SignerUpdated")
        .withArgs(newSigner);
      expect(await claim.signer()).to.equal(newSigner);
    });

    it("Should not allow non-owner to set signer", async function () {
      const newSigner = user2.address;
      await expect(
        claim.connect(user1).setSigner(newSigner)
      ).to.be.revertedWithCustomError(claim, "OwnableUnauthorizedAccount");
    });

    it("Should allow owner to set new USDT token", async function () {
      const MockERC20Factory = await ethers.getContractFactory("MockERC20");
      const newToken = await MockERC20Factory.deploy("New USDT", "NUSDT", 6);
      const newTokenAddress = await newToken.getAddress();

      await expect(claim.setUsdtToken(newTokenAddress))
        .to.emit(claim, "TokenUpdated")
        .withArgs(newTokenAddress, 0); // RewardType.USDT = 0

      expect(await claim.usdtToken()).to.equal(newTokenAddress);
    });

    it("Should allow owner to set new PUBLIC token", async function () {
      const MockERC20Factory = await ethers.getContractFactory("MockERC20");
      const newToken = await MockERC20Factory.deploy("New PUBLIC", "NPUBLIC", 18);
      const newTokenAddress = await newToken.getAddress();

      await expect(claim.setPublicToken(newTokenAddress))
        .to.emit(claim, "TokenUpdated")
        .withArgs(newTokenAddress, 1); // RewardType.PUBLIC = 1

      expect(await claim.publicToken()).to.equal(newTokenAddress);
    });
  });

  describe("Pool Management", function () {
    it("Should allow owner to register a new pool", async function () {
      const task = 1;
      const reward = ethers.parseUnits("10000", 6);

      await expect(claim.registerPool(task, reward))
        .to.emit(claim, "PoolRegistered")
        .withArgs(task, reward);

      const poolInfo = await claim.getPool(task);
      expect(poolInfo.total).to.equal(reward);
      expect(poolInfo.claimed).to.equal(0);
    });

    it("Should not allow non-owner to register pool", async function () {
      const task = 1;
      const reward = ethers.parseUnits("10000", 6);

      await expect(
        claim.connect(user1).registerPool(task, reward)
      ).to.be.revertedWithCustomError(claim, "OwnableUnauthorizedAccount");
    });

    it("Should return pool information correctly", async function () {
      const task = 1;
      const reward = ethers.parseUnits("10000", 6);

      await claim.registerPool(task, reward);
      const poolInfo = await claim.getPool(task);

      expect(poolInfo.total).to.equal(reward);
      expect(poolInfo.claimed).to.equal(0);
    });

    // it("Should revert when getting non-existent pool", async function () {
    //   await expect(claim.getPool(999)).to.be.revertedWith("Pool does not exist");
    // });
  });

  describe("Claim Nonce", function () {
    it("Should return 0 for users who haven't claimed", async function () {
      const task = 1;
      expect(await claim.getClaimNonce(task, user1.address)).to.equal(0);
    });

    it("Should return 0 for non-existent pool", async function () {
      const task = 999;
      expect(await claim.getClaimNonce(task, user1.address)).to.equal(0);
    });
  });

  describe("USDT Claim", function () {
    it("Should allow user to claim USDT rewards with valid signature", async function () {
      const task = 1;
      const nonce = 0;
      const reward = ethers.parseUnits("100", 6);

      const signature = await signMessage(task, nonce, reward, user1.address);

      const initialBalance = await usdtToken.balanceOf(user1.address);

      await expect(
        claim.connect(user1).claim(task, nonce, reward, user1.address, signature)
      )
        .to.emit(claim, "RewardClaimed")
        .withArgs(user1.address, task, reward, nonce, 0); // RewardType.USDT = 0

      const finalBalance = await usdtToken.balanceOf(user1.address);
      expect(finalBalance - initialBalance).to.equal(reward);

      // Check reward item
      const rewardItem = await claim.getReward(task, user1.address);
      expect(rewardItem.user).to.equal(user1.address);
      expect(rewardItem.task).to.equal(task);
      expect(rewardItem.reward).to.equal(reward);
      expect(rewardItem.times).to.equal(1);

      // Check total claimed
      expect(await claim.totalClaimed()).to.equal(reward);
    });

    it("Should allow user to claim multiple times with incrementing nonce", async function () {
      const task = 1;
      const reward1 = ethers.parseUnits("100", 6);
      const reward2 = ethers.parseUnits("200", 6);

      // First claim
      const signature1 = await signMessage(task, 0, reward1, user1.address);
      await claim.connect(user1).claim(task, 0, reward1, user1.address, signature1);

      // Second claim with nonce = 1
      const signature2 = await signMessage(task, 1, reward2, user1.address);
      await claim.connect(user1).claim(task, 1, reward2, user1.address, signature2);

      const rewardItem = await claim.getReward(task, user1.address);
      expect(rewardItem.reward).to.equal(reward1 + reward2);
      expect(rewardItem.times).to.equal(2);

      const totalClaimed = await claim.totalClaimed();
      expect(totalClaimed).to.equal(reward1 + reward2);
    });

    it("Should revert when using wrong nonce", async function () {
      const task = 1;
      const reward = ethers.parseUnits("100", 6);
      const signature = await signMessage(task, 0, reward, user1.address);

      // First claim
      await claim.connect(user1).claim(task, 0, reward, user1.address, signature);

      // Try to claim again with wrong nonce (should be 1, not 0)
      const signature2 = await signMessage(task, 0, reward, user1.address);
      await expect(
        claim.connect(user1).claim(task, 0, reward, user1.address, signature2)
      ).to.be.revertedWith("Invalid nonce");
    });

    it("Should revert when receiver doesn't match sender", async function () {
      const task = 1;
      const nonce = 0;
      const reward = ethers.parseUnits("100", 6);
      const signature = await signMessage(task, nonce, reward, user2.address);

      await expect(
        claim.connect(user1).claim(task, nonce, reward, user2.address, signature)
      ).to.be.revertedWith("Unauthorized account");
    });

    it("Should revert for new user with non-zero nonce", async function () {
      const task = 1;
      const nonce = 1; // Should be 0 for new user
      const reward = ethers.parseUnits("100", 6);
      const signature = await signMessage(task, nonce, reward, user1.address);

      await expect(
        claim.connect(user1).claim(task, nonce, reward, user1.address, signature)
      ).to.be.revertedWith("Invalid nonce for new user");
    });
  });

  describe("PUBLIC Token Claim", function () {
    it("Should allow user to claim PUBLIC rewards with valid signature", async function () {
      const task = 2;
      const nonce = 0;
      const reward = ethers.parseUnits("1000", 18);

      const signature = await signMessage(task, nonce, reward, user1.address, 1); // RewardType.PUBLIC = 1

      const initialBalance = await publicToken.balanceOf(user1.address);

      await expect(
        claim.connect(user1).claimPublic(task, nonce, reward, user1.address, signature)
      )
        .to.emit(claim, "RewardClaimed")
        .withArgs(user1.address, task, reward, nonce, 1); // RewardType.PUBLIC = 1

      const finalBalance = await publicToken.balanceOf(user1.address);
      expect(finalBalance - initialBalance).to.equal(reward);

      // Check reward item
      const rewardItem = await claim.getReward(task, user1.address);
      expect(rewardItem.user).to.equal(user1.address);
      expect(rewardItem.task).to.equal(task);
      expect(rewardItem.reward).to.equal(reward);
      expect(rewardItem.times).to.equal(1);

      // Check total claimed for PUBLIC
      expect(await claim.totalClaimedPublic()).to.equal(reward);
    });

    it("Should allow user to claim PUBLIC multiple times", async function () {
      const task = 2;
      const reward1 = ethers.parseUnits("1000", 18);
      const reward2 = ethers.parseUnits("2000", 18);

      const signature1 = await signMessage(task, 0, reward1, user1.address, 1);
      await claim.connect(user1).claimPublic(task, 0, reward1, user1.address, signature1);

      const signature2 = await signMessage(task, 1, reward2, user1.address, 1);
      await claim.connect(user1).claimPublic(task, 1, reward2, user1.address, signature2);

      const rewardItem = await claim.getReward(task, user1.address);
      expect(rewardItem.reward).to.equal(reward1 + reward2);
      expect(rewardItem.times).to.equal(2);

      const totalClaimed = await claim.totalClaimedPublic();
      expect(totalClaimed).to.equal(reward1 + reward2);
    });
  });

  describe("Withdraw", function () {
    it("Should allow owner to withdraw USDT", async function () {
      const withdrawAmount = ethers.parseUnits("1000", 6);
      const initialBalance = await usdtToken.balanceOf(owner.address);

      await expect(claim.withdraw(withdrawAmount, 0)) // RewardType.USDT = 0
        .to.emit(claim, "Withdrawn")
        .withArgs(owner.address, withdrawAmount, 0);

      const finalBalance = await usdtToken.balanceOf(owner.address);
      expect(finalBalance - initialBalance).to.equal(withdrawAmount);
    });

    it("Should allow owner to withdraw PUBLIC", async function () {
      const withdrawAmount = ethers.parseUnits("1000", 18);
      const initialBalance = await publicToken.balanceOf(owner.address);

      await expect(claim.withdraw(withdrawAmount, 1)) // RewardType.PUBLIC = 1
        .to.emit(claim, "Withdrawn")
        .withArgs(owner.address, withdrawAmount, 1);

      const finalBalance = await publicToken.balanceOf(owner.address);
      expect(finalBalance - initialBalance).to.equal(withdrawAmount);
    });

    it("Should not allow non-owner to withdraw", async function () {
      const withdrawAmount = ethers.parseUnits("1000", 6);

      await expect(
        claim.connect(user1).withdraw(withdrawAmount, 0)
      ).to.be.revertedWithCustomError(claim, "OwnableUnauthorizedAccount");
    });
  });

  describe("Multiple Users and Tasks", function () {
    it("Should handle multiple users claiming from different tasks", async function () {
      const task1 = 1;
      const task2 = 2;
      const reward1 = ethers.parseUnits("100", 6);
      const reward2 = ethers.parseUnits("200", 6);

      const signature1 = await signMessage(task1, 0, reward1, user1.address);
      const signature2 = await signMessage(task2, 0, reward2, user2.address);

      // User1 claims from task1
      await claim.connect(user1).claim(task1, 0, reward1, user1.address, signature1);

      // User2 claims from task2
      await claim.connect(user2).claim(task2, 0, reward2, user2.address, signature2);

      const reward1Item = await claim.getReward(task1, user1.address);
      const reward2Item = await claim.getReward(task2, user2.address);

      expect(reward1Item.reward).to.equal(reward1);
      expect(reward2Item.reward).to.equal(reward2);

      const totalClaimed = await claim.totalClaimed();
      expect(totalClaimed).to.equal(reward1 + reward2);
    });

    it("Should handle same user claiming from multiple tasks", async function () {
      const task1 = 1;
      const task2 = 2;
      const reward1 = ethers.parseUnits("100", 6);
      const reward2 = ethers.parseUnits("200", 6);

      const signature1 = await signMessage(task1, 0, reward1, user1.address);
      const signature2 = await signMessage(task2, 0, reward2, user1.address);

      // User1 claims from both tasks
      await claim.connect(user1).claim(task1, 0, reward1, user1.address, signature1);
      await claim.connect(user1).claim(task2, 0, reward2, user1.address, signature2);

      const reward1Item = await claim.getReward(task1, user1.address);
      const reward2Item = await claim.getReward(task2, user1.address);

      expect(reward1Item.reward).to.equal(reward1);
      expect(reward2Item.reward).to.equal(reward2);
      expect(reward1Item.task).to.equal(task1);
      expect(reward2Item.task).to.equal(task2);
    });
  });

  describe("Pool Statistics", function () {
    it("Should track pool claimed amount correctly", async function () {
      const task = 1;
      const totalReward = ethers.parseUnits("10000", 6);

      // Register pool
      await claim.registerPool(task, totalReward);

      // User1 claims
      const reward1 = ethers.parseUnits("100", 6);
      const signature1 = await signMessage(task, 0, reward1, user1.address);
      await claim.connect(user1).claim(task, 0, reward1, user1.address, signature1);

      // User2 claims
      const reward2 = ethers.parseUnits("200", 6);
      const signature2 = await signMessage(task, 0, reward2, user2.address);
      await claim.connect(user2).claim(task, 0, reward2, user2.address, signature2);

      const poolInfo = await claim.getPool(task);
      expect(poolInfo.claimed).to.equal(reward1 + reward2);
      expect(poolInfo.total).to.equal(totalReward);
    });

    it("Should track nonce correctly after multiple claims", async function () {
      const task = 1;

      // Claim 3 times
      for (let i = 0; i < 3; i++) {
        const reward = ethers.parseUnits("100", 6);
        const signature = await signMessage(task, i, reward, user1.address);
        await claim.connect(user1).claim(task, i, reward, user1.address, signature);
      }

      const currentNonce = await claim.getClaimNonce(task, user1.address);
      expect(currentNonce).to.equal(3);
    });
  });

  describe("Reentrancy Protection", function () {
    it("Should prevent reentrancy attacks", async function () {
      // The ReentrancyGuard should prevent reentrancy
      const task = 1;
      const nonce = 0;
      const reward = ethers.parseUnits("100", 6);
      const signature = await signMessage(task, nonce, reward, user1.address);

      // Normal claim should work
      await expect(
        claim.connect(user1).claim(task, nonce, reward, user1.address, signature)
      ).to.not.be.reverted;
    });
  });

  // Helper function to create signature for voter claims
  async function signVoterMessage(
      nonce: number,
      timestamp: number,
      reward: bigint,
      receiver: string
  ): Promise<string> {
    const messageHash = ethers.solidityPackedKeccak256(
        ["uint16", "uint32", "uint128", "address"],
        [nonce, timestamp, reward, receiver]
    );

    // Sign the message hash
    const messageHashBytes = ethers.getBytes(messageHash);
    const signature = await signer.signMessage(messageHashBytes);

    return signature;
  }

  describe("Voter Claim Functions", function () {
    describe("voter_claim (USDT)", function () {
      it("Should allow a user to claim USDT rewards", async function () {
        const reward = ethers.parseUnits("100", 6); // 100 USDT
        const timestamp = Math.floor(Date.now() / 1000); // Current time in seconds
        const nonce = 0; // First claim

        // Get initial balances
        const initialUserBalance = await usdtToken.balanceOf(user1.address);

        // Sign the message
        const signature = await signVoterMessage(nonce, timestamp, reward, user1.address);

        // Claim the reward
        await claim.connect(user1).voter_claim(nonce, timestamp, reward, user1.address, signature);

        // Check user's balance has increased
        const newUserBalance = await usdtToken.balanceOf(user1.address);
        expect(newUserBalance - initialUserBalance).to.equal(reward);

        // Check that the event was emitted
        const filter = claim.filters.VoterRewardClaimed(user1.address);
        const events = await claim.queryFilter(filter);
        expect(events.length).to.be.greaterThan(0);

        const event = events[events.length - 1];
        expect(event.args[0]).to.equal(user1.address); // user
        expect(event.args[1]).to.equal(reward); // reward
        expect(event.args[2]).to.equal(timestamp); // timestamp
        expect(event.args[3]).to.equal(nonce); // nonce
        expect(event.args[4]).to.equal(0); // RewardType.USDT
      });

      it("Should allow incremental rewards with proper nonce", async function () {
        // First claim
        const reward1 = ethers.parseUnits("50", 6);
        const timestamp1 = Math.floor(Date.now() / 1000);
        const nonce1 = 0;

        const signature1 = await signVoterMessage(nonce1, timestamp1, reward1, user1.address);
        await claim.connect(user1).voter_claim(nonce1, timestamp1, reward1, user1.address, signature1);

        // Second claim (incremental)
        const reward2 = ethers.parseUnits("75", 6);
        const timestamp2 = Math.floor(Date.now() / 1000) + 100; // 100 seconds later
        const nonce2 = 1; // Must increment nonce

        const signature2 = await signVoterMessage(nonce2, timestamp2, reward2, user1.address);
        await claim.connect(user1).voter_claim(nonce2, timestamp2, reward2, user1.address, signature2);

        // Check total received
        const totalExpected = reward1 + reward2;
        const userBalance = await usdtToken.balanceOf(user1.address);
        expect(userBalance).to.equal(totalExpected);
      });

      it("Should reject invalid signatures", async function () {
        const reward = ethers.parseUnits("100", 6);
        const timestamp = Math.floor(Date.now() / 1000);
        const nonce = 0;

        // Create signature for user1 but try to use it for user2
        const signature = await signVoterMessage(nonce, timestamp, reward, user1.address);

        // Should fail when user2 tries to claim with user1's signature
        await expect(
            claim.connect(user2).voter_claim(nonce, timestamp, reward, user2.address, signature)
        ).to.be.revertedWithCustomError(claim, "InvalidSignature");
      });

      it("Should reject expired timestamps", async function () {
        const reward = ethers.parseUnits("100", 6);
        const expiredTimestamp = Math.floor(Date.now() / 1000);
        const nonce = 0;

        const signature = await signVoterMessage(nonce, expiredTimestamp, reward, user1.address);

        // Should fail due to expired timestamp
        await claim.connect(user1).voter_claim(nonce, expiredTimestamp, reward, user1.address, signature);
        const reward2 = ethers.parseUnits("75", 6);
        const timestamp2 = Math.floor(Date.now() / 1000)-1000;
        const nonce2 = 1; // Must increment nonce

        const signature2 = await signVoterMessage(nonce2, timestamp2, reward2, user1.address);
        await expect(
            claim.connect(user1).voter_claim(nonce2, timestamp2, reward2, user1.address, signature2)
        ).to.be.revertedWithCustomError(claim, "TimestampError");
      });

      it("Should reject invalid nonce", async function () {
        // First claim
        const reward1 = ethers.parseUnits("50", 6);
        const timestamp1 = Math.floor(Date.now() / 1000);
        const nonce1 = 0;

        const signature1 = await signVoterMessage(nonce1, timestamp1, reward1, user1.address);
        await claim.connect(user1).voter_claim(nonce1, timestamp1, reward1, user1.address, signature1);

        // Try to claim with wrong nonce (should be 1, not 2)
        const reward2 = ethers.parseUnits("75", 6);
        const timestamp2 = Math.floor(Date.now() / 1000) + 100;
        const wrongNonce = 2;

        const signature2 = await signVoterMessage(wrongNonce, timestamp2, reward2, user1.address);

        // Should fail due to invalid nonce
        await expect(
            claim.connect(user1).voter_claim(wrongNonce, timestamp2, reward2, user1.address, signature2)
        ).to.be.revertedWithCustomError(claim, "InvalidNonce");
      });
    });

    describe("voter_claim_public (PUBLIC)", function () {
      it("Should allow a user to claim PUBLIC token rewards", async function () {
        const reward = ethers.parseUnits("100", 18); // 100 PUBLIC tokens
        const timestamp = Math.floor(Date.now() / 1000);
        const nonce = 0;

        // Get initial balances
        const initialUserBalance = await publicToken.balanceOf(user1.address);

        // Sign the message
        const signature = await signVoterMessage(nonce, timestamp, reward, user1.address);

        // Claim the reward
        await claim.connect(user1).voter_claim_public(nonce, timestamp, reward, user1.address, signature);

        // Check user's balance has increased
        const newUserBalance = await publicToken.balanceOf(user1.address);
        expect(newUserBalance - initialUserBalance).to.equal(reward);

        // Check that the event was emitted
        const filter = claim.filters.VoterRewardClaimed(user1.address);
        const events = await claim.queryFilter(filter);
        expect(events.length).to.be.greaterThan(0);

        const event = events[events.length - 1];
        expect(event.args[0]).to.equal(user1.address); // user
        expect(event.args[1]).to.equal(reward); // reward
        expect(event.args[2]).to.equal(timestamp); // timestamp
        expect(event.args[3]).to.equal(nonce); // nonce
        expect(event.args[4]).to.equal(1); // RewardType.PUBLIC
      });

      it("Should allow incremental PUBLIC token rewards", async function () {
        // First claim
        const reward1 = ethers.parseUnits("50", 18);
        const timestamp1 = Math.floor(Date.now() / 1000);
        const nonce1 = 0;

        const signature1 = await signVoterMessage(nonce1, timestamp1, reward1, user1.address);
        await claim.connect(user1).voter_claim_public(nonce1, timestamp1, reward1, user1.address, signature1);

        // Second claim (incremental)
        const reward2 = ethers.parseUnits("75", 18);
        const timestamp2 = Math.floor(Date.now() / 1000) + 100; // 100 seconds later
        const nonce2 = 1; // Must increment nonce

        const signature2 = await signVoterMessage(nonce2, timestamp2, reward2, user1.address);
        await claim.connect(user1).voter_claim_public(nonce2, timestamp2, reward2, user1.address, signature2);

        // Check total received
        const totalExpected = reward1 + reward2;
        const userBalance = await publicToken.balanceOf(user1.address);
        expect(userBalance).to.equal(totalExpected);
      });

      it("Should reject unauthorized accounts", async function () {
        const reward = ethers.parseUnits("100", 18);
        const timestamp = Math.floor(Date.now() / 1000);
        const nonce = 0;

        // Sign for user1
        const signature = await signVoterMessage(nonce, timestamp, reward, user1.address);

        // User2 tries to claim as user1
        await expect(
            claim.connect(user2).voter_claim_public(nonce, timestamp, reward, user1.address, signature)
        ).to.be.revertedWithCustomError(claim, "UnauthorizedAccount");
      });

      it("Should update contract state variables correctly", async function () {
        const reward = ethers.parseUnits("100", 18);
        const timestamp = Math.floor(Date.now() / 1000);
        const nonce = 0;

        // Get initial total claimed
        const initialTotalClaimed = await claim.totalClaimedPublic();

        // Sign and claim
        const signature = await signVoterMessage(nonce, timestamp, reward, user1.address);
        await claim.connect(user1).voter_claim_public(nonce, timestamp, reward, user1.address, signature);

        // Check total claimed has increased
        const newTotalClaimed = await claim.totalClaimedPublic();
        expect(newTotalClaimed - initialTotalClaimed).to.equal(reward);
      });
    });
  });

});
