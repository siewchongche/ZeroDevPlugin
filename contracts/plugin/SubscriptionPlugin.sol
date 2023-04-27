//SPDX-License-Identifier: GPL
pragma solidity ^0.8.7;

import "./ZeroDevBasePlugin.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
using ECDSA for bytes32;

struct SubscriptionStorageStruct {
    mapping(address => uint) nextPaymentTime;
    mapping(address => bool) isBlocked;
}

contract SubscriptionPlugin is ZeroDevBasePlugin, Ownable {
    // return value in case of signature failure, with no time-range.
    // equivalent to packSigTimeRange(true,0,0);
    uint256 internal constant SIG_VALIDATION_FAILED = 1;

    event SubscriptionBlocked(address subscriptionProvider);
    event SubscriptionUnblocked(address subscriptionProvider);

    constructor() EIP712("SubscriptionPlugin", "0.0.1") {}

    function getPolicyStorage() internal pure returns (SubscriptionStorageStruct storage s) {
        bytes32 position = bytes32(uint256(keccak256("account.eip4337.subscription")) - 1);
        assembly {
            s.slot := position
        }
    }

    function blockSubscription(address subscriptionProvider) external onlyOwner {
        getPolicyStorage().isBlocked[subscriptionProvider] = true;
        emit SubscriptionBlocked(subscriptionProvider);
    }

    function unblockSubscription(address subscriptionProvider) external onlyOwner {
        getPolicyStorage().isBlocked[subscriptionProvider] = false;
        emit SubscriptionUnblocked(subscriptionProvider);
    }

    function _validatePluginData(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        bytes calldata data,
        bytes calldata signature
    ) internal override returns (bool) {
        address subscriptionProvider = address(bytes20(data[0:20]));
        require(getPolicyStorage().nextPaymentTime[subscriptionProvider] < block.timestamp, "Plugin: Not yet next payment");
        bytes32 merkleRoot = bytes32(data[20:52]);

        uint payment = uint(bytes32(signature[0:32]));
        require(payment == uint(bytes32(userOp.callData[36:68])), "Plugin: Invalid payment");
        // recommend to use ERC20 instead of ETH because payment + gas used by this userOp might exceed balance in sender 
        require(address(userOp.sender).balance > payment, "Plugin: Account not enough pay subscription");
        uint subscriptionPeriod = uint(bytes32(signature[32:64]));
        uint nextPaymentTime = getPolicyStorage().nextPaymentTime[subscriptionProvider];

        // general bundler with geth tracecall check might block userOp that use block.timestamp
        if (nextPaymentTime == 0) {
            // first subscription
            getPolicyStorage().nextPaymentTime[subscriptionProvider] = block.timestamp + subscriptionPeriod;
        } else {
            getPolicyStorage().nextPaymentTime[subscriptionProvider] = nextPaymentTime + subscriptionPeriod;
        }

        {
            bytes32 leaf1 = keccak256(signature[0:32]);
            bytes32 leaf2 = keccak256(signature[32:64]);
            (bytes32[] memory proof1, bytes32[] memory proof2) = abi.decode(signature[129:], (bytes32[], bytes32[]));
            require(MerkleProof.verify(proof1, merkleRoot, leaf1), "Plugin: Invalid merkle root for payment");
            require(MerkleProof.verify(proof2, merkleRoot, leaf2), "Plugin: Invalid merkle root for period");
        }

        signature = signature[64:129];
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
        require(recovered == subscriptionProvider, "Plugin: Invalid signature for subscription provider");
        return true;
    }
}
