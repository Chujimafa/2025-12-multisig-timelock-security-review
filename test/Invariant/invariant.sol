// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Handler} from "test/Invariant/handler.sol";
import {Test, console2} from "forge-std/Test.sol";
import {MultiSigTimelock} from "../../src/MultiSigTimelock.sol";
import {StdInvariant} from "forge-std/StdInvariant.sol";

contract Invariant is StdInvariant, Test {
    MultiSigTimelock multiSigTimelock;
    Handler handler;

    function setUp() public {
        multiSigTimelock = new MultiSigTimelock();
        handler = new Handler(multiSigTimelock);

        bytes4[] memory selectors = new bytes4[](7);
        selectors[0] = handler.grantSigningRole.selector;
        selectors[1] = handler.revokeSigningRole.selector;
        selectors[2] = handler.transferOwnership.selector;
        selectors[3] = handler.proposeTransaction.selector;
        selectors[4] = handler.confirmTransaction.selector;
        selectors[5] = handler.revokeConfirmation.selector;
        selectors[6] = handler.executeTransaction.selector;

        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));

        targetContract(address(handler));
    }

    function statefulFuzz_invariant_signerCount() public view {
        uint256 signerCount = multiSigTimelock.getSignerCount();
        address[5] memory signers = multiSigTimelock.getSigners();

        assert(signerCount >= 1 && signerCount <= 5);
        for (uint256 i = 0; i < signerCount; i++) {
            assert(multiSigTimelock.hasRole(multiSigTimelock.getSigningRole(), signers[i]));
        }
        for (uint256 i = 0; i < signerCount; i++) {
            assert(signers[i] != address(0));
        }
        for (uint256 i = signerCount; i < 5; i++) {
            assert(signers[i] == address(0));
        }
    }

    function statefulFuzz_invariant_transactionCountAlignment() public view {
        uint256 currentCount = multiSigTimelock.getTransactionCount();
        if (currentCount > 0) {
            if (handler.ghost_lastTrxId() != currentCount - 1) {
                console2.log("Ghost ID:", handler.ghost_lastTrxId());
                console2.log("Contract Count:", currentCount);
            }
            assertEq(handler.ghost_lastTrxId(), currentCount - 1);
        }
    }

    function statefulFuzz_invariant_contractBalance() public view {
        assertGe(address(multiSigTimelock).balance, 0);
    }

    function statefulFuzz_invariant_TimelockMustBeRespected() public view {
        uint256 executedCount = handler.getExecutedTxCount();

        for (uint256 i = 0; i < executedCount; i++) {
            uint256 txId = handler.ghost_executedTxIds(i);
            uint256 actualExecTime = handler.ghost_executeTimestamp(txId);

            MultiSigTimelock.Transaction memory trx = multiSigTimelock.getTransaction(txId);
            uint256 delay = multiSigTimelock._getTimelockDelay(trx.value);

            assertGe(actualExecTime, trx.proposedAt + delay);
        }
    }

    function statefulFuzz_invariant_ConfirmationsNumberShouldMatch() public view {
        uint256 currentCount = multiSigTimelock.getTransactionCount();
        for (uint256 i = 0; i < currentCount; i++) {
            MultiSigTimelock.Transaction memory trx = multiSigTimelock.getTransaction(i);
            uint256 trxConfirmation = trx.confirmations;

            uint256 singerconfirmationsCount;
            uint256 count = handler.getActiveSignersCount();
            for (uint256 j = 0; j < count; j++) {
                address signer = handler.activeSigners(j);
                if (handler.s_signatures(i, signer)) {
                    singerconfirmationsCount++;
                }
            }
            assertEq(trxConfirmation, singerconfirmationsCount);
        }
    }
}
