import { ethers } from "hardhat";

async function main() {
  const CredDigestVerify = await ethers.getContractFactory("CredDigestVerify");
  const credigestverify = await CredDigestVerify.deploy();
}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
