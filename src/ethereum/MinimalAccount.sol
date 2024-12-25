// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IAccount} from "account-abstraction/interfaces/IAccount.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS} from "account-abstraction/core/Helpers.sol";
import {IEntryPoint} from "account-abstraction/core/EntryPoint.sol";

contract MinimalAccount is IAccount, Ownable {
    error MinimalAccount_NotFromEntryPoint();
    error MinimalAccount_NotFromEntryPointOrOwner();
    error MinimalAccount_CallFailed(bytes);

    IEntryPoint private immutable i_entryPoint;

    modifier requireFromEntryPoint() {
        if (msg.sender != address(i_entryPoint)) {
            revert MinimalAccount_NotFromEntryPoint();
        }
        _;
    }

    modifier requireFromEntryPointOrOwner() {
        if (msg.sender != address(i_entryPoint) && msg.sender != owner()) {
            revert MinimalAccount_NotFromEntryPointOrOwner();
        }
        _;
    }

    constructor(address entryPoint) Ownable(msg.sender) {
        i_entryPoint = IEntryPoint(entryPoint);
    }

    receive() external payable {}

    /*///////////////////////////////////////////////////////////////////////
     *                          EXTERNAL FUNCTIONS
     */ /////////////////////////////////////////////////////////////////////
    function execute(
        address dest,
        uint256 value,
        bytes calldata functionData
    ) external requireFromEntryPointOrOwner {
        (bool success, bytes memory result) = dest.call{value: value}(
            functionData
        );

        if (!success) {
            revert MinimalAccount_CallFailed(result);
        }
    }

    // A signature is valid if it's the MinimalAccount owner
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external returns (uint256 validationData) {
        validationData = _validateSignature(userOp, userOpHash);
        // _validateNonce
        _payPreFund(missingAccountFunds);
    }

    /*///////////////////////////////////////////////////////////////////////
     *                          INTERNAL FUNCTIONS
     */ /////////////////////////////////////////////////////////////////////

    // EIP-191 version of the signed hash
    function _validateSignature(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal view returns (uint256 validationData) {
        bytes32 ethSignedMessageHash = MessageHashUtils.toEthSignedMessageHash(
            userOpHash
        );
        address signer = ECDSA.recover(ethSignedMessageHash, userOp.signature);

        if (signer != owner()) {
            return SIG_VALIDATION_FAILED;
        }

        return SIG_VALIDATION_SUCCESS;
    }

    function _payPreFund(uint256 missingAccountFunds) internal {
        if (missingAccountFunds != 0) {
            (bool success, ) = payable(msg.sender).call{
                value: missingAccountFunds,
                gas: type(uint256).max
            }("");
            (success);
        }
    }

    /*///////////////////////////////////////////////////////////////////////
     *                              GETTERS
     */ /////////////////////////////////////////////////////////////////////
    function getEntryPoint() external view returns (address) {
        return address(i_entryPoint);
    }
}
