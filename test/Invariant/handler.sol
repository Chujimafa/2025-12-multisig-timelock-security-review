// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
import {Test, console2} from "forge-std/Test.sol";
import {MultiSigTimelock} from "../../src/MultiSigTimelock.sol";

contract Handler is Test {
    MultiSigTimelock multiSigTimelock;
    address[] public activeSigners;
    mapping(uint256 transactionId => mapping(address user => bool userHasSignedCorrectly)) public s_signatures;
    uint256 public ghost_lastTrxId;
    mapping(uint256 => uint256) public ghost_executeTimestamp;
    uint256[] public ghost_executedTxIds;

    constructor(MultiSigTimelock _multiSigTimelock) {
        multiSigTimelock = _multiSigTimelock;
        activeSigners.push(multiSigTimelock.owner());
        vm.deal(address(multiSigTimelock), 1000 ether);
    }

    function grantSigningRole(address signer) public {
        // Constrain to valid signast
        vm.assume(signer != address(0));

        if (multiSigTimelock.getSignerCount() >= 5) {
            return;
        }
        for (uint256 i = 0; i < activeSigners.length; i++) {
            if (activeSigners[i] == signer) {
                return;
            }
        }
        vm.prank(multiSigTimelock.owner());
        multiSigTimelock.grantSigningRole(signer);
        activeSigners.push(signer);
    }

    function revokeSigningRole(uint256 signerIndex) public {
        if (activeSigners.length <= 1) return;
        uint256 index = signerIndex % activeSigners.length;
        address toRemove = activeSigners[index];

        vm.prank(multiSigTimelock.owner());
        multiSigTimelock.revokeSigningRole(toRemove);

        activeSigners[index] = activeSigners[activeSigners.length - 1];
        activeSigners.pop();
    }

    function transferOwnership(address newOwner) public {
        vm.assume(newOwner != address(0));
        vm.prank(multiSigTimelock.owner());
        multiSigTimelock.transferOwnership(newOwner);
    }

    // function renounceRole(uint256 callerIndex) public {
    //     uint256 index = callerIndex % activeSigners.length;
    //     address caller = activeSigners[index];

    //     vm.prank(caller);
    //     multiSigTimelock.renounceRole(multiSigTimelock.getSigningRole(), caller);

    //     activeSigners[index] = activeSigners[activeSigners.length - 1];
    //     activeSigners.pop();
    // }

    function proposeTransaction(address to, uint256 value, bytes calldata data) public {
        vm.assume(to != address(0));
        vm.assume(to > address(0x1000));
        value = bound(value, 0, address(multiSigTimelock).balance);
        vm.prank(multiSigTimelock.owner());
        uint256 trxId = multiSigTimelock.proposeTransaction(to, value, data);
        ghost_lastTrxId = trxId;
    }

    function confirmTransaction(uint256 trxIdSeed, uint256 signerIndexSeed) public {
        (uint256 trxId, address selectedSigner) = _getValidActiveTrxIdAndSigner(trxIdSeed, signerIndexSeed);

        if (s_signatures[trxId][selectedSigner]) return;
        vm.prank(selectedSigner);
        multiSigTimelock.confirmTransaction(trxId);

        s_signatures[trxId][selectedSigner] = true;
    }

    function revokeConfirmation(uint256 trxIdSeed, uint256 signerIndexSeed) public {
        (uint256 trxId, address selectedSigner) = _getValidActiveTrxIdAndSigner(trxIdSeed, signerIndexSeed);

        if (!s_signatures[trxId][selectedSigner]) {
            return;
        }

        vm.prank(selectedSigner);
        multiSigTimelock.revokeConfirmation(trxId);
        s_signatures[trxId][selectedSigner] = false;
    }

    function executeTransaction(uint256 trxIdSeed, uint256 signerIndexSeed) public {
        (uint256 trxId, address selectedSigner) = _getValidActiveTrxIdAndSigner(trxIdSeed, signerIndexSeed);

        MultiSigTimelock.Transaction memory trx = multiSigTimelock.getTransaction(trxId);
        if (address(multiSigTimelock).balance < trx.value) return;
        if (trx.confirmations < 3) {
            return;
        }

        uint256 delay = multiSigTimelock._getTimelockDelay(trx.value);
        uint256 minExecutionTime = trx.proposedAt + delay;

        vm.prank(selectedSigner);
        (bool success,) =
            address(multiSigTimelock).call(abi.encodeWithSelector(multiSigTimelock.executeTransaction.selector, trxId));

        if (success) {
            ghost_executeTimestamp[trxId] = block.timestamp;
            ghost_executedTxIds.push(trxId);
        }
    }

    function _getValidActiveTrxId(uint256 trxIdSeed) internal returns (uint256, bool) {
        uint256 count = multiSigTimelock.getTransactionCount();
        if (count == 0) return (0, false);
        uint256 validId = bound(trxIdSeed, 0, count - 1);

        MultiSigTimelock.Transaction memory trx = multiSigTimelock.getTransaction(validId);
        if (trx.executed) return (0, false);

        return (validId, true);
    }

    function _getValidActiveTrxIdAndSigner(uint256 trxIdSeed, uint256 signerIndexSeed)
        internal
        returns (uint256, address)
    {
        vm.assume(activeSigners.length > 0);
        (uint256 trxId, bool success) = _getValidActiveTrxId(trxIdSeed);
        vm.assume(success);

        uint256 signerIndex = bound(signerIndexSeed, 0, activeSigners.length - 1);
        address selectedSigner = activeSigners[signerIndex];

        return (trxId, selectedSigner);
    }

    function getExecutedTxCount() public view returns (uint256) {
        return ghost_executedTxIds.length;
    }

    function getActiveSignersCount() public view returns (uint256) {
        return activeSigners.length;
    }
}
