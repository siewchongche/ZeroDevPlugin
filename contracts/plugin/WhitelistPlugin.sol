//SPDX-License-Identifier: GPL
pragma solidity ^0.8.7;

import "./ZeroDevBasePlugin.sol";
using ECDSA for bytes32;

contract WhitelistPlugin is ZeroDevBasePlugin {
    // return value in case of signature failure, with no time-range.
    // equivalent to packSigTimeRange(true,0,0);
    uint256 internal constant SIG_VALIDATION_FAILED = 1;

    constructor() EIP712("WhitelistPlugin", "0.0.1") {}

    function _validatePluginData(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        bytes calldata data,
        bytes calldata signature
    ) internal view override returns (bool) {
        address whitelisted = address(bytes20(data[0:20]));
        bytes32 digest = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    keccak256("Session(bytes32 userOpHash,uint256 nonce)"), // we are going to trust plugin for verification
                    userOpHash,
                    userOp.nonce
                )
            )
        );
        address recovered = digest.recover(signature);
        require(recovered == whitelisted, "account: invalid signature");
        return true;
    }
}
