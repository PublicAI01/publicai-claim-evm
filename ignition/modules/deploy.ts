import { ethers, upgrades } from "hardhat";

/**
 * Deploy Upgradeable PublicAIClaim Contract
 *
 * Usage:
 * 1. Configure environment variables: SIGNER_PUBLIC_KEY, USDT_TOKEN, PUBLIC_TOKEN
 * 2. Run: npx hardhat run ignition/modules/deploy.ts --network <network-name>
 */
async function main() {
  console.log("Deploying PublicAIClaimUpgradeable contract...\n");

  // Get deployer account
  const [deployer] = await ethers.getSigners();
  console.log("Deployer:", deployer.address);
  console.log("Balance:", ethers.formatEther(await ethers.provider.getBalance(deployer.address)), "ETH\n");

  // Configuration parameters
  const SIGNER_PUBLIC_KEY = process.env.SIGNER_PUBLIC_KEY || ethers.hexlify(ethers.randomBytes(32));
  const USDT_TOKEN = process.env.USDT_TOKEN || "0x0000000000000000000000000000000000000000";
  const PUBLIC_TOKEN = process.env.PUBLIC_TOKEN || "0x0000000000000000000000000000000000000000";

  console.log("Configuration:");
  console.log("- Signer Public Key:", SIGNER_PUBLIC_KEY);
  console.log("- USDT Token:", USDT_TOKEN);
  console.log("- PUBLIC Token:", PUBLIC_TOKEN);
  console.log();

  // Deploy Mock ERC20 tokens if needed (for testnet only)
  let usdtAddress = USDT_TOKEN;
  let publicAddress = PUBLIC_TOKEN;

  if (USDT_TOKEN === "0x0000000000000000000000000000000000000000") {
    console.log("Deploying test ERC20 tokens...");
    const MockERC20 = await ethers.getContractFactory("MockERC20");

    const usdtToken = await MockERC20.deploy("Mock USDT", "USDT", 6);
    await usdtToken.waitForDeployment();
    usdtAddress = await usdtToken.getAddress();
    console.log("✅ USDT Token:", usdtAddress);

    const publicToken = await MockERC20.deploy("Mock PUBLIC", "PUBLIC", 18);
    await publicToken.waitForDeployment();
    publicAddress = await publicToken.getAddress();
    console.log("✅ PUBLIC Token:", publicAddress);
    console.log();
  }

  // Deploy upgradeable contract
  console.log("Deploying PublicAIClaimUpgradeable...");
  const PublicAIClaimUpgradeable = await ethers.getContractFactory("PublicAIClaimUpgradeable");

  const claim = await upgrades.deployProxy(
    PublicAIClaimUpgradeable,
    [SIGNER_PUBLIC_KEY, usdtAddress, publicAddress],
    { kind: "uups", initializer: "initialize" }
  );

  await claim.waitForDeployment();
  const proxyAddress = await claim.getAddress();
  const implAddress = await upgrades.erc1967.getImplementationAddress(proxyAddress);

  console.log("✅ Proxy Address:", proxyAddress);
  console.log("✅ Implementation Address:", implAddress);
  console.log();

  // Verify deployment
  console.log("Deployment Info:");
  console.log("- Owner:", await claim.owner());
  console.log("- Signer:", await claim.signer());
  console.log("- USDT Token:", await claim.usdtToken());
  console.log("- PUBLIC Token:", await claim.publicToken());
  console.log();

  console.log("=".repeat(60));
  console.log("✅ Deployment Complete!");
  console.log("=".repeat(60));
  console.log("\nNext Steps:");
  console.log("1. Transfer reward tokens to contract:", proxyAddress);
  console.log("2. Register pools: registerPool(taskId, totalReward)");
  console.log("3. Users can claim rewards via claim() or claimPublic()");
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("Deployment failed:", error);
    process.exit(1);
  });
