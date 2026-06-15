import { ethers, upgrades } from "hardhat";

async function main() {
    console.log("Deploying StakingVault contract...\n");
    const [deployer] = await ethers.getSigners();

    console.log("Deploying contracts with the account:", deployer.address);
    console.log("Account balance:", (await ethers.provider.getBalance(deployer.address)).toString());

    console.log("\nUpgrading StakingVault...");
    const StakingVault = await ethers.getContractFactory("PublicAIClaimUpgradeable");
    const stakingVault = await upgrades.upgradeProxy(
        '0x0e9CA28534ADBa8A89E6386CB4e23693Fb226adB',
        StakingVault,
    );
    console.log("Box upgraded");
}

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error(error);
        process.exit(1);
    });