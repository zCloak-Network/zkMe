import { expect } from "chai";
import { ethers } from "hardhat";

describe("CredDigestVerify", function () {
  describe("Use EIP 191 for signature", function () {
    describe("Verify VC, with version 0", function () {
      it("Valid VC should pass the verification and be registered onchain", async function () {
        const MyContract = await ethers.getContractFactory("CredDigestVerify");
        const myContract = await MyContract.deploy();
        await myContract.deployed();

        expect(
          await myContract.verifyVC(
            "0xc08734bbd035fe0880ba6e469e40b160601a2389d0284f6255a5f0b395d2336c",
            "0x0186815ed1ea",
            "0x00",
            "0xb159990a86e5a2b97d9a0f6b1f95b2678b8ae396f2ec73ae3f6d22d8dd1e1668",
            "0x0000",
            true,
            "0xd052bfd09dfe286ab5d2994b033b10aaa261bdd74b77bfd87577dac7f4c9d0886912c6123104e6fd41af4627f468525e0faf2fa1910493c663da45920c970e5401",
            "0x361F1dd3db9037d2aC39f84007DC65dfA8BD248E"
          )
        ).emit(myContract, "vcVerifySuccess");
        expect(
          await myContract.VCAttester(
            "0x2bae994bbc2efa62f11362eba81a9e8d8ad8f016c86f32c04be6c96b1f4932db"
          )
        ).to.equal("0x361F1dd3db9037d2aC39f84007DC65dfA8BD248E");
        expect(
          await myContract.VCHolder(
            "0x2bae994bbc2efa62f11362eba81a9e8d8ad8f016c86f32c04be6c96b1f4932db"
          )
        ).to.equal("0x11f8b77F34FCF14B7095BF5228Ac0606324E82D1");
      });
      it("Invalid VC should lead to Fail Event", async function () {
        const MyContract = await ethers.getContractFactory("CredDigestVerify");
        const myContract = await MyContract.deploy();
        await myContract.deployed();

        expect(
          await myContract.verifyVC(
            "0xc08734bbd035fe0880ba6e469e40b160601a2389d0284f6255a5f0b395d2336c",
            "0x0186815ed1ea",
            "0x01",
            "0xb159990a86e5a2b97d9a0f6b1f95b2678b8ae396f2ec73ae3f6d22d8dd1e1668",
            "0x0000",
            true,
            "0xd052bfd09dfe286ab5d2994b033b10aaa261bdd74b77bfd87577dac7f4c9d0886912c6123104e6fd41af4627f468525e0faf2fa1910493c663da45920c970e5401",
            "0x361F1dd3db9037d2aC39f84007DC65dfA8BD248E"
          )
        ).emit(myContract, "vcVerifyFail");
        expect(
          await myContract.VCAttester(
            "0x2bae994bbc2efa62f11362eba81a9e8d8ad8f016c86f32c04be6c96b1f4932db"
          )
        ).to.equal("0x0000000000000000000000000000000000000000");
        expect(
          await myContract.VCHolder(
            "0x2bae994bbc2efa62f11362eba81a9e8d8ad8f016c86f32c04be6c96b1f4932db"
          )
        ).to.equal("0x0000000000000000000000000000000000000000");
      });
      it("The same VC cannot be uploaded twice", async function () {
        const MyContract = await ethers.getContractFactory("CredDigestVerify");
        const myContract = await MyContract.deploy();
        await myContract.deployed();
        await myContract.verifyVC(
          "0xc08734bbd035fe0880ba6e469e40b160601a2389d0284f6255a5f0b395d2336c",
          "0x0186815ed1ea",
          "0x01",
          "0xb159990a86e5a2b97d9a0f6b1f95b2678b8ae396f2ec73ae3f6d22d8dd1e1668",
          "0x0000",
          true,
          "0xd052bfd09dfe286ab5d2994b033b10aaa261bdd74b77bfd87577dac7f4c9d0886912c6123104e6fd41af4627f468525e0faf2fa1910493c663da45920c970e5401",
          "0x361F1dd3db9037d2aC39f84007DC65dfA8BD248E"
        );

        expect(
          await myContract.VCAttester(
            "0x2bae994bbc2efa62f11362eba81a9e8d8ad8f016c86f32c04be6c96b1f4932db"
          )
        ).to.equal("0x0000000000000000000000000000000000000000");
        expect(
          await myContract.VCHolder(
            "0x2bae994bbc2efa62f11362eba81a9e8d8ad8f016c86f32c04be6c96b1f4932db"
          )
        ).to.equal("0x0000000000000000000000000000000000000000");

        expect(
          await myContract.verifyVC(
            "0xc08734bbd035fe0880ba6e469e40b160601a2389d0284f6255a5f0b395d2336c",
            "0x0186815ed1ea",
            "0x01",
            "0xb159990a86e5a2b97d9a0f6b1f95b2678b8ae396f2ec73ae3f6d22d8dd1e1668",
            "0x0000",
            true,
            "0xd052bfd09dfe286ab5d2994b033b10aaa261bdd74b77bfd87577dac7f4c9d0886912c6123104e6fd41af4627f468525e0faf2fa1910493c663da45920c970e5401",
            "0x361F1dd3db9037d2aC39f84007DC65dfA8BD248E"
          )
        ).to.be.revertedWith("This VC has been upload before");
      });
    });

    describe("Verify VC, with version 1", function () {
      it("Valid VC should pass the verification and be registered onchain", async function () {
        const MyContract = await ethers.getContractFactory("CredDigestVerify");
        const myContract = await MyContract.deploy();
        await myContract.deployed();

        expect(
          await myContract.verifyVC(
            "0xc08734bbd035fe0880ba6e469e40b160601a2389d0284f6255a5f0b395d2336c",
            "0x01867dd7f36e",
            "0x00",
            "0xe006fd6502041b27a7e841d4d3a86141a702d295080686e330dc01ef50a99d70",
            "0x0001",
            true,
            "0x88c0a261f8745eff16f9d4a347f57525f274c8399444226f363c7d48781207f1114af652940925475443d15a38f522b7c2f23ebd711fe459875c2f709cf2235700",
            "0x361F1dd3db9037d2aC39f84007DC65dfA8BD248E"
          )
        ).emit(myContract, "vcVerifySuccess");

        expect(
          await myContract.VCHolder(
            "0xe0389db77876bb3e84e9f237415de5ef5658356450c69f652d62009115c0a8df"
          )
        ).to.equal("0x11f8b77F34FCF14B7095BF5228Ac0606324E82D1");
        expect(
          await myContract.VCAttester(
            "0xe0389db77876bb3e84e9f237415de5ef5658356450c69f652d62009115c0a8df"
          )
        ).to.equal("0x361F1dd3db9037d2aC39f84007DC65dfA8BD248E");
      });

      it("InValid VC should lead to Fail event", async function () {
        const MyContract = await ethers.getContractFactory("CredDigestVerify");
        const myContract = await MyContract.deploy();
        await myContract.deployed();

        expect(
          await myContract.verifyVC(
            "0xc08734bbd035fe0880ba6e469e40b160601a2389d0284f6255a5f0b395d2336c",
            "0x01867dd7f36e",
            "0x01",
            "0xe006fd6502041b27a7e841d4d3a86141a702d295080686e330dc01ef50a99d70",
            "0x0001",
            true,
            "0x88c0a261f8745eff16f9d4a347f57525f274c8399444226f363c7d48781207f1114af652940925475443d15a38f522b7c2f23ebd711fe459875c2f709cf2235700",
            "0x361F1dd3db9037d2aC39f84007DC65dfA8BD248E"
          )
        ).emit(myContract, "vcVerifyFail");
      });

      it("VC Version should be 0x0000 or 0x0001", async function () {
        const MyContract = await ethers.getContractFactory("CredDigestVerify");
        const myContract = await MyContract.deploy();
        await myContract.deployed();

        await expect(
          myContract.verifyVC(
            "0xc08734bbd035fe0880ba6e469e40b160601a2389d0284f6255a5f0b395d2336c",
            "0x01867dd7f36e",
            "0x00",
            "0xe006fd6502041b27a7e841d4d3a86141a702d295080686e330dc01ef50a99d70",
            "0x0002",
            true,
            "0x88c0a261f8745eff16f9d4a347f57525f274c8399444226f363c7d48781207f1114af652940925475443d15a38f522b7c2f23ebd711fe459875c2f709cf2235700",
            "0x361F1dd3db9037d2aC39f84007DC65dfA8BD248E"
          )
        ).to.be.revertedWith("The vcVersion is invalid");
      });

      it("The same VC cannot be uploaded twice", async function () {
        const MyContract = await ethers.getContractFactory("CredDigestVerify");
        const myContract = await MyContract.deploy();
        await myContract.deployed();

        await myContract.verifyVC(
          "0xc08734bbd035fe0880ba6e469e40b160601a2389d0284f6255a5f0b395d2336c",
          "0x01867dd7f36e",
          "0x00",
          "0xe006fd6502041b27a7e841d4d3a86141a702d295080686e330dc01ef50a99d70",
          "0x0001",
          true,
          "0x88c0a261f8745eff16f9d4a347f57525f274c8399444226f363c7d48781207f1114af652940925475443d15a38f522b7c2f23ebd711fe459875c2f709cf2235700",
          "0x361F1dd3db9037d2aC39f84007DC65dfA8BD248E"
        );

        await expect(
          myContract.verifyVC(
            "0xc08734bbd035fe0880ba6e469e40b160601a2389d0284f6255a5f0b395d2336c",
            "0x01867dd7f36e",
            "0x00",
            "0xe006fd6502041b27a7e841d4d3a86141a702d295080686e330dc01ef50a99d70",
            "0x0001",
            true,
            "0x88c0a261f8745eff16f9d4a347f57525f274c8399444226f363c7d48781207f1114af652940925475443d15a38f522b7c2f23ebd711fe459875c2f709cf2235700",
            "0x361F1dd3db9037d2aC39f84007DC65dfA8BD248E"
          )
        ).to.be.revertedWith("This VC has been upload before");
      });
    });
  });

  describe("Not Use EIP 191 for signature", function () {
    describe("Verify VC, with version 0", function () {
      it("Valid VC should pass the verification and be registered onchain", async function () {
        const MyContract = await ethers.getContractFactory("CredDigestVerify");
        const myContract = await MyContract.deploy();
        await myContract.deployed();

        expect(
          await myContract.verifyVC(
            "0xc08734bbd035fe0880ba6e469e40b160601a2389d0284f6255a5f0b395d2336c",
            "0x0186821e3ffb",
            "0x00",
            "0xb206a46582390775a34f484ae0f084901427e54d0f8fe29852085bf8f6d4ed81",
            "0x0000",
            false,
            "0xec4d6316984219a46e9cb3b9175434d1c44c07a50c4e72d8e8d10e0743aae0cc5fc78dca32545fe5401ae5ef37a2736494a31f85961b2943bb1016d136bc6a7c01",
            "0x361F1dd3db9037d2aC39f84007DC65dfA8BD248E"
          )
        ).emit(myContract, "vcVerifySuccess");
        expect(
          await myContract.VCAttester(
            "0xc56e9075e83bc19ce32e1fb3742453df23882db93375de9a33410c9a5b139179"
          )
        ).to.equal("0x361F1dd3db9037d2aC39f84007DC65dfA8BD248E");
        expect(
          await myContract.VCHolder(
            "0xc56e9075e83bc19ce32e1fb3742453df23882db93375de9a33410c9a5b139179"
          )
        ).to.equal("0x11f8b77F34FCF14B7095BF5228Ac0606324E82D1");
      });

      it("Invalid VC should lead to Fail Event", async function () {
        const MyContract = await ethers.getContractFactory("CredDigestVerify");
        const myContract = await MyContract.deploy();
        await myContract.deployed();

        expect(
          await myContract.verifyVC(
            "0xc08734bbd035fe0880ba6e469e40b160601a2389d0284f6255a5f0b395d2336c",
            "0x0186821e3ffb",
            "0x01",
            "0xb206a46582390775a34f484ae0f084901427e54d0f8fe29852085bf8f6d4ed81",
            "0x0000",
            false,
            "0xec4d6316984219a46e9cb3b9175434d1c44c07a50c4e72d8e8d10e0743aae0cc5fc78dca32545fe5401ae5ef37a2736494a31f85961b2943bb1016d136bc6a7c01",
            "0x361F1dd3db9037d2aC39f84007DC65dfA8BD248E"
          )
        ).emit(myContract, "vcVerifyFail");
        expect(
          await myContract.VCAttester(
            "0xc56e9075e83bc19ce32e1fb3742453df23882db93375de9a33410c9a5b139179"
          )
        ).to.equal("0x0000000000000000000000000000000000000000");
        expect(
          await myContract.VCHolder(
            "0xc56e9075e83bc19ce32e1fb3742453df23882db93375de9a33410c9a5b139179"
          )
        ).to.equal("0x0000000000000000000000000000000000000000");
      });
      it("The same VC cannot be uploaded twice", async function () {
        const MyContract = await ethers.getContractFactory("CredDigestVerify");
        const myContract = await MyContract.deploy();
        await myContract.deployed();
        await myContract.verifyVC(
          "0xc08734bbd035fe0880ba6e469e40b160601a2389d0284f6255a5f0b395d2336c",
          "0x0186821e3ffb",
          "0x00",
          "0xb206a46582390775a34f484ae0f084901427e54d0f8fe29852085bf8f6d4ed81",
          "0x0000",
          false,
          "0xec4d6316984219a46e9cb3b9175434d1c44c07a50c4e72d8e8d10e0743aae0cc5fc78dca32545fe5401ae5ef37a2736494a31f85961b2943bb1016d136bc6a7c01",
          "0x361F1dd3db9037d2aC39f84007DC65dfA8BD248E"
        );

        expect(
          await myContract.VCAttester(
            "0xc56e9075e83bc19ce32e1fb3742453df23882db93375de9a33410c9a5b139179"
          )
        ).to.equal("0x361F1dd3db9037d2aC39f84007DC65dfA8BD248E");
        expect(
          await myContract.VCHolder(
            "0xc56e9075e83bc19ce32e1fb3742453df23882db93375de9a33410c9a5b139179"
          )
        ).to.equal("0x11f8b77F34FCF14B7095BF5228Ac0606324E82D1");

        await expect(
          myContract.verifyVC(
            "0xc08734bbd035fe0880ba6e469e40b160601a2389d0284f6255a5f0b395d2336c",
            "0x0186821e3ffb",
            "0x00",
            "0xb206a46582390775a34f484ae0f084901427e54d0f8fe29852085bf8f6d4ed81",
            "0x0000",
            false,
            "0xec4d6316984219a46e9cb3b9175434d1c44c07a50c4e72d8e8d10e0743aae0cc5fc78dca32545fe5401ae5ef37a2736494a31f85961b2943bb1016d136bc6a7c01",
            "0x361F1dd3db9037d2aC39f84007DC65dfA8BD248E"
          )
        ).to.be.revertedWith("This VC has been upload before");
      });
    });
  });
});
