// SPDX-License-Identifier: GPL-3.0

pragma solidity ^0.8.9;

// This contract is meant to verify VC, it will recombine the key elements to restore digest, and check whether the VC has been attested.

/**
 * @title CredDigestVerify
 * @dev used to verify VC. The VC's key components needs to be passed in, the contract will do the verification job.
 */
contract CredDigestVerify {
    // the version header of the eip191
    bytes25 constant EIP191_VERSION_E_HEADER = "Ethereum Signed Message:\n";

    // the prefix of did, which is 'did::zk'
    bytes7 constant DID_ZK_PREFIX = bytes7("did:zk:");

    // the prefix of the attestation message, which is CredentialVersionedDigest
    bytes25 constant EIP191_CRE_VERSION_DIGEST_PREFIX = bytes25("CredentialVersionedDigest");

    // the length of Digest, which likes 0xb32b6e54e4420cfaf2feecdc0a15dc3fc0a7681687123a0f8cb348b451c2989
    bytes2 constant EIP191_CRE_DIGEST_LEN_V0 = 0x3332;

    // the length of the CredentialVersionedDigest, which likes CredentialVersionedDigest0x00011b32b6e54e4420cfaf2feecdc0a15dc3fc0a7681687123a0f8cb348b451c2989
    bytes2 constant EIP191_CRE_VERSION_DIGEST_LEN_V1 = 0x3539;

    // represent the user's ethereum address who owns the VC (VC digesthash => ethereumAddress)
    mapping(bytes32 => address) public VCHolder;

    // represent the user's ethereum address who attests the VC (VC digesthash => ethereumAddress)
    mapping(bytes32 => address) public VCAttester;

    // emit a vcVerifyFail event
    event vcVerifyFail(
        address indexed sender,
        bytes32 indexed digest,
        bytes2 vcVersion
    );

    // emit a vcVerifySuccess event
    event vcVerifySuccess(
        address indexed sender,
        bytes32 indexed digest,
        bytes2 vcVersion
    );

    /**
     * @dev calculate the digestHash
     * @param userAddress, the user address
     * @param ctype, the ctype of the VC
     * @param issuanceDate, the timestamp of the issuanceDate
     * @param expirationDate, the timestamp of the expirationDate.
     * @param roothash, the roothash of the VC
     */
    function _calcDigest(
        bytes32 roothash,
        address userAddress,
        bytes memory issuanceDate,
        bytes memory expirationDate,
        bytes32 ctype,
        bytes2 vcVersion
    ) internal pure returns (bytes32 digest) {
        // if the vcVersion is not valid, revert
        require(
            vcVersion == 0x0001 || vcVersion == 0x0000,
            "The vcVersion is invalid"
        );

        // convert sender address to bytes
        bytes memory userDidAsBytes;

        // concat and compute digest according to the vcVersion(different concat rule)
        bytes memory concatResult;

        if (vcVersion == 0x0001) {
            userDidAsBytes = abi.encodePacked(userAddress);
            concatResult = abi.encodePacked(
                roothash,
                DID_ZK_PREFIX,
                userDidAsBytes,
                issuanceDate,
                expirationDate,
                ctype
            );
        } else if (vcVersion == 0x0000) {
            userDidAsBytes = abi.encodePacked("0x", _getChecksum(userAddress));
            concatResult = abi.encodePacked(
                roothash,
                DID_ZK_PREFIX,
                userDidAsBytes,
                expirationDate,
                ctype
            );
        }
        digest = keccak256(concatResult);
    }

    /**
     * @dev calculate the digestHash, and verify the attestation signature. If the verification phase is passed, the verification result can be checked via the 'VCHolder' interface.
     * @param roothash, the roothash of the VC
     * @param issuanceDate, the timestamp of the issuanceDate
     * @param expirationDate, the timestamp of the expirationDate
     * @param ctype, the ctype of the VC
     * @param vcVersion, the version of the VC
     * @param isEip191, whether the signature used eip191 proposal
     * @param signature, the attestation signature of the VC, which is in the format of 'base58'
     * @param attester, the attester of the VC
     */
    function verifyVC(
        bytes32 ctype,
        bytes memory issuanceDate,
        bytes memory expirationDate,
        bytes32 roothash,
        bytes2 vcVersion,
        bool isEip191,
        bytes memory signature,
        address attester
    ) public {
        bytes32 digest = _calcDigest(
            roothash,
            msg.sender,
            issuanceDate,
            expirationDate,
            ctype,
            vcVersion
        );

        bool verificationResult = _verifyDigestSignature(
            digest,
            vcVersion,
            isEip191,
            signature,
            attester
        );

        if (verificationResult == true) {
            require(
                VCHolder[digest] == address(0) && VCAttester[digest] == address(0),
                "This VC has been upload before"
            );
            VCAttester[digest] = attester;
            VCHolder[digest] = msg.sender;
            emit vcVerifySuccess(msg.sender, digest, vcVersion);
        } else {
            emit vcVerifyFail(msg.sender, digest, vcVersion);
        }
    }

    /**
     * @dev verify the signature, check if it is a valid proof of the digest, check whether the attester signed this digest
     * @param digest, the digestHash of the VC
     * @param vcVersion, the version of the VC
     * @param isEip191, whether the signature used eip191 proposal
     * @param signature, the attestation signature of the VC
     * @param attester, the attester of the VC
     */
    function _verifyDigestSignature(
        bytes32 digest,
        bytes2 vcVersion,
        bool isEip191,
        bytes memory signature,
        address attester
    ) internal pure returns (bool) {
        bytes32 ethSignedMessageHash;
        if (isEip191 == false) {
            ethSignedMessageHash = digest;
        } else {
            if (vcVersion == 0x0001) {
                bytes memory versionedDigest = abi.encodePacked(
                    vcVersion,
                    digest
                );
                ethSignedMessageHash = keccak256(
                    abi.encodePacked(
                        bytes1(0x19),
                        EIP191_VERSION_E_HEADER,
                        EIP191_CRE_VERSION_DIGEST_LEN_V1,
                        EIP191_CRE_VERSION_DIGEST_PREFIX,
                        versionedDigest
                    )
                );
            } else {
                ethSignedMessageHash = keccak256(
                    abi.encodePacked(
                        bytes1(0x19),
                        EIP191_VERSION_E_HEADER,
                        EIP191_CRE_DIGEST_LEN_V0,
                        digest
                    )
                );
            }
        }
        return recover(ethSignedMessageHash, signature) == attester;
    }

    /**
     * @dev parse the signature, and recover the signer address
     * @param hash, the messageHash which the signer signed
     * @param sig, the signature
     */
    function recover(
        bytes32 hash,
        bytes memory sig
    ) internal pure returns (address) {
        bytes32 r;
        bytes32 s;
        uint8 v;

        // Check the signature length
        if (sig.length != 65) {
            return (address(0));
        }

        // Divide the signature in r, s and v variables
        // ecrecover takes the signature parameters, and the only way to get them
        // currently is to use assembly.
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }

        // Version of signature should be 27 or 28, but 0 and 1 are also possible versions
        if (v < 27) {
            v += 27;
        }

        // If the version is correct return the signer address
        if (v != 27 && v != 28) {
            return (address(0));
        } else {
            // solium-disable-next-line arg-overflow
            return ecrecover(hash, v, r, s);
        }
    }

    /**
     * @dev Get a checksummed string hex representation of an account address.
     * @param account address The account to get the checksum for.
     */
    function _getChecksum(
        address account
    ) internal pure returns (string memory accountChecksum) {
        // call internal function for converting an account to a checksummed string.
        return _toChecksumString(account);
    }

    function _toChecksumString(
        address account
    ) internal pure returns (string memory asciiString) {
        // convert the account argument from address to bytes.
        bytes20 data = bytes20(account);

        // create an in-memory fixed-size bytes array.
        bytes memory asciiBytes = new bytes(40);

        // declare variable types.
        uint8 b;
        uint8 leftNibble;
        uint8 rightNibble;
        bool leftCaps;
        bool rightCaps;
        uint8 asciiOffset;

        // get the capitalized characters in the actual checksum.
        bool[40] memory caps = _toChecksumCapsFlags(account);

        // iterate over bytes, processing left and right nibble in each iteration.
        for (uint256 i = 0; i < data.length; i++) {
            // locate the byte and extract each nibble.
            b = uint8(uint160(data) / (2 ** (8 * (19 - i))));
            leftNibble = b / 16;
            rightNibble = b - 16 * leftNibble;

            // locate and extract each capitalization status.
            leftCaps = caps[2 * i];
            rightCaps = caps[2 * i + 1];

            // get the offset from nibble value to ascii character for left nibble.
            asciiOffset = _getAsciiOffset(leftNibble, leftCaps);

            // add the converted character to the byte array.
            asciiBytes[2 * i] = bytes1(leftNibble + asciiOffset);

            // get the offset from nibble value to ascii character for right nibble.
            asciiOffset = _getAsciiOffset(rightNibble, rightCaps);

            // add the converted character to the byte array.
            asciiBytes[2 * i + 1] = bytes1(rightNibble + asciiOffset);
        }

        return string(asciiBytes);
    }

    function _toChecksumCapsFlags(
        address account
    ) internal pure returns (bool[40] memory characterCapitalized) {
        // convert the address to bytes.
        bytes20 a = bytes20(account);

        // hash the address (used to calculate checksum).
        bytes32 b = keccak256(abi.encodePacked(_toAsciiString(a)));

        // declare variable types.
        uint8 leftNibbleAddress;
        uint8 rightNibbleAddress;
        uint8 leftNibbleHash;
        uint8 rightNibbleHash;

        // iterate over bytes, processing left and right nibble in each iteration.
        for (uint256 i; i < a.length; i++) {
            // locate the byte and extract each nibble for the address and the hash.
            rightNibbleAddress = uint8(a[i]) % 16;
            leftNibbleAddress = (uint8(a[i]) - rightNibbleAddress) / 16;
            rightNibbleHash = uint8(b[i]) % 16;
            leftNibbleHash = (uint8(b[i]) - rightNibbleHash) / 16;

            characterCapitalized[2 * i] = (leftNibbleAddress > 9 &&
                leftNibbleHash > 7);
            characterCapitalized[2 * i + 1] = (rightNibbleAddress > 9 &&
                rightNibbleHash > 7);
        }
    }

    function _getAsciiOffset(
        uint8 nibble,
        bool caps
    ) internal pure returns (uint8 offset) {
        // to convert to ascii characters, add 48 to 0-9, 55 to A-F, & 87 to a-f.
        if (nibble < 10) {
            offset = 48;
        } else if (caps) {
            offset = 55;
        } else {
            offset = 87;
        }
    }

    // based on https://ethereum.stackexchange.com/a/56499/48410
    function _toAsciiString(
        bytes20 data
    ) internal pure returns (string memory asciiString) {
        // create an in-memory fixed-size bytes array.
        bytes memory asciiBytes = new bytes(40);

        // declare variable types.
        uint8 b;
        uint8 leftNibble;
        uint8 rightNibble;

        // iterate over bytes, processing left and right nibble in each iteration.
        for (uint256 i = 0; i < data.length; i++) {
            // locate the byte and extract each nibble.
            b = uint8(uint160(data) / (2 ** (8 * (19 - i))));
            leftNibble = b / 16;
            rightNibble = b - 16 * leftNibble;

            // to convert to ascii characters, add 48 to 0-9 and 87 to a-f.
            asciiBytes[2 * i] = bytes1(
                leftNibble + (leftNibble < 10 ? 48 : 87)
            );
            asciiBytes[2 * i + 1] = bytes1(
                rightNibble + (rightNibble < 10 ? 48 : 87)
            );
        }

        return string(asciiBytes);
    }
}
