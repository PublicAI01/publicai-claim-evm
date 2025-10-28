import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import "@openzeppelin/hardhat-upgrades";
import dotenv from 'dotenv'
dotenv.config()

const config: HardhatUserConfig = {
  defaultNetwork: "hardhat",
  solidity: {
    compilers: [
      {
        version: '0.8.28',
        settings: {
          optimizer: {
            enabled: true,
            runs: 200,
          },
        },
      },
    ],
  },
  sourcify: {
    enabled: true
  },
  networks: {
    hardhat: {
      allowUnlimitedContractSize: false,
      chainId: 1,
    },
    bscTestnet: {
      url: process.env.EVM_RPC!,
      chainId: 97,
      accounts: [
        process.env.PRIVATE!,
      ]
    },
    bsc: {
      url: process.env.EVM_RPC!,
      chainId: 56,
      accounts: [
        process.env.PRIVATE!,
      ]
    },
  },
  etherscan: {
    apiKey: process.env.API_KEY!,
  }
};
export default config;
