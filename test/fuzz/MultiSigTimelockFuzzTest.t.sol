// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Test, console2} from "forge-std/Test.sol";
import {MultiSigTimelock} from "src/MultiSigTimelock.sol";
import {EthRejector} from "test/utils/EthRejector.sol";
import {TestTimelockDelay} from "test/utils/TestTimelockDelay.sol";

/**
 * @title
 * @author
 * @dev Stateless Fuzzing
 */
contract MultiSigTimeLockFuzzTest is Test {
    MultiSigTimelock multiSigTimelock;
    EthRejector ethRejector;
    TestTimelockDelay testTimelockDelay;

    address public OWNER = address(this);
    address public SIGNER_TWO = makeAddr("signer_two");
    address public SIGNER_THREE = makeAddr("signer_three");
    address public SIGNER_FOUR = makeAddr("signer_four");
    address public SIGNER_FIVE = makeAddr("signer_five");

    function setUp() public {
        multiSigTimelock = new MultiSigTimelock();
    }

    modifier grantSigningRoles() {
        multiSigTimelock.grantSigningRole(SIGNER_TWO);
        multiSigTimelock.grantSigningRole(SIGNER_THREE);
        multiSigTimelock.grantSigningRole(SIGNER_FOUR);
        multiSigTimelock.grantSigningRole(SIGNER_FIVE);
        _;
    }

    function testFuzz_GetTimelockDelay(uint256 value) public {
        testTimelockDelay = new TestTimelockDelay();
        uint256 delay = testTimelockDelay.getTimelockDelay(value);

        if (value < 1 ether) {
            assertEq(delay, 0);
        } else if (value < 10 ether) {
            assertEq(delay, 1 days);
        } else if (value < 100 ether) {
            assertEq(delay, 2 days);
        } else {
            assertEq(delay, 7 days);
        }

        // Invariant: Delay is always one of the defined constants
        assertTrue(delay == 0 || delay == 1 days || delay == 2 days || delay == 7 days);
    }

    function testFuzz_GrantSigningRole(address[] calldata randomAddresses) public grantSigningRoles {
        // Constrain to realistic inputs: up to 5 addresses, but since we start with some signers, limit fuzz
        vm.assume(randomAddresses.length <= 5 - multiSigTimelock.getSignerCount()); // Avoid exceeding max signers

        for (uint256 i = 0; i < randomAddresses.length; i++) {
            address newSigner = randomAddresses[i];
            // Assume valid non-zero, non-existing signer
            vm.assume(
                newSigner != address(0) && !multiSigTimelock.hasRole(multiSigTimelock.getSigningRole(), newSigner)
            );

            multiSigTimelock.grantSigningRole(newSigner);
            assertTrue(multiSigTimelock.hasRole(multiSigTimelock.getSigningRole(), newSigner));
            assertEq(multiSigTimelock.getSignerCount(), multiSigTimelock.getSignerCount() + 1); // Invariant: count increases
        }

        // Invariant: Never exceed max signers
        assertLe(multiSigTimelock.getSignerCount(), multiSigTimelock.getMaximumSignerCount());
    }

    function testFuzz_RevokeSigningRole(address randomSigner) public grantSigningRoles {
        // Assume the randomSigner is one of the existing signers (except owner to avoid last signer revert)
        // vm.assume(_account == SIGNER_TWO ||
        //     _account == SIGNER_THREE ||
        //     _account == SIGNER_FOUR ||
        //     _account == SIGNER_FIVE);
        //     vm.prank(multiSigTimelock.owner());

        uint256 initialCount = multiSigTimelock.getSignerCount();
        multiSigTimelock.revokeSigningRole(randomSigner);

        assertFalse(multiSigTimelock.hasRole(multiSigTimelock.getSigningRole(), randomSigner));
        assertEq(multiSigTimelock.getSignerCount(), initialCount - 1);

        // Invariant: At least 1 signer remains
        assertGe(multiSigTimelock.getSignerCount(), 1);
    }

    function check_3_signatures_should_pass(address to,uint256 value) grantSigningRoles public  {
        
        vm.assume(to != address(0) && to != address(multiSigTimelock));
        value = bound(value, 0, 150 ether);
        vm.deal(address(multiSigTimelock), 150 ether);
        
        address[5] memory signers = [
        multiSigTimelock.owner(),
        SIGNER_TWO,
        SIGNER_THREE,
        SIGNER_FOUR,
        SIGNER_FIVE
        ];
        uint256 balanceBefore = address(multiSigTimelock).balance;

        vm.prank(multiSigTimelock.owner());
        uint256 txnId = multiSigTimelock.proposeTransaction(to, value, "");
        
        vm.prank(multiSigTimelock.owner());
        multiSigTimelock.confirmTransaction(txnId);
     
        address secondSigner = signers[1];
        vm.prank(secondSigner);
        multiSigTimelock.confirmTransaction(txnId);

        address thirdSigner = signers[2];
        vm.prank(thirdSigner);
        multiSigTimelock.confirmTransaction(txnId);
       
        vm.warp(block.timestamp + 8 days);
        
        vm.prank(multiSigTimelock.owner());
        multiSigTimelock.executeTransaction(txnId);

        MultiSigTimelock.Transaction memory trx = multiSigTimelock.getTransaction(txnId);

        assert(trx.executed);
        uint256 balanceAfter = address(multiSigTimelock).balance;

        assertEq(balanceAfter, balanceBefore - value);
       
    }

    
    function check_if_2_signatures_will_not_executed(address to,uint256 value) grantSigningRoles public  {
        
        vm.assume(to != address(0) && to != address(multiSigTimelock));
        value = bound(value, 0, 1 ether);
        vm.deal(address(multiSigTimelock), 150 ether);
        
        uint256 balanceBefore = address(multiSigTimelock).balance;

        vm.prank(multiSigTimelock.owner());
        uint256 txnId = multiSigTimelock.proposeTransaction(to, value, "");
        
        vm.prank(SIGNER_TWO);
        multiSigTimelock.confirmTransaction(txnId);
     
        vm.prank(SIGNER_THREE);
        multiSigTimelock.confirmTransaction(txnId);

        
        vm.prank(multiSigTimelock.owner());
        try multiSigTimelock.executeTransaction(txnId){
            assert(false);
        }catch{}

        MultiSigTimelock.Transaction memory trx = multiSigTimelock.getTransaction(txnId);

        assert(!trx.executed);
        uint256 balanceAfter = address(multiSigTimelock).balance;

        assertEq(balanceAfter, balanceBefore);
       
    }

    function check_propose_access_control(address caller, address to, uint256 value, bytes calldata data) public {
    vm.assume(caller != multiSigTimelock.owner());
  
    vm.prank(caller);   
    try multiSigTimelock.proposeTransaction(to, value, data) {
        assert(false);
    } catch {
        assert(true);
    }}

function check_cannot_grant_role_via_proposal(address maliciousSigner, uint256 trxId) public {
    
    MultiSigTimelock.Transaction memory trx = multiSigTimelock.getTransaction(trxId);
    
    bytes memory maliciousData = abi.encodeWithSelector(multiSigTimelock.grantSigningRole.selector, maliciousSigner);
    
    if (trx.to == address(multiSigTimelock) && keccak256(trx.data) == keccak256(maliciousData)) {
        
        vm.prank(address(multiSigTimelock)); 
        multiSigTimelock.executeTransaction(trxId);
        assert(!multiSigTimelock.hasRole(multiSigTimelock.getSigningRole(), maliciousSigner));
    }
}



}

    


