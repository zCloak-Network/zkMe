// import "@nomicfoundation/hardhat-toolbox";
import "@nomicfoundation/hardhat-chai-matchers";
import { HardhatUserConfig } from "hardhat/config";

const config: HardhatUserConfig = {
  solidity: "0.8.17",
  networks:{
    localhost: {
      url: "http://127.0.0.1:8545"
    },
    hardhat: {
      accounts: {mnemonic: "health correct setup usage father decorate curious copper sorry recycle skin equal"}
    },
  }
};

export default config;
