// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Test, console2} from "forge-std/Test.sol";
import {MultiSigTimelock} from "src/MultiSigTimelock.sol";
import {EthRejector} from "test/utils/EthRejector.sol";
import {TestTimelockDelay} from "test/utils/TestTimelockDelay.sol";
import {DeployMultiSigTimelock} from "script/DeployMultiSigTimelock.s.sol";
import {GrantSigningRole} from "script/GrantSigningRole.s.sol";
import {ProposeTransactionScript} from "script/Interact.s.sol";
import {ConfirmTransactionScript} from "script/Interact.s.sol";
import {ExecuteTransactionScript} from "script/Interact.s.sol";
import {EthRefunder} from "test/utils/EthRefunder.sol";

contract MultiSigTimeLockTest is Test {
    MultiSigTimelock multiSigTimelock;
    EthRejector ethRejector;
    TestTimelockDelay testTimelockDelay;
    EthRefunder ethRefunder;

    DeployMultiSigTimelock deployer;
    GrantSigningRole grantor;

    address public OWNER = address(this);
    address public SIGNER_TWO = makeAddr("signer_two");
    address public SIGNER_THREE = makeAddr("signer_three");
    address public SIGNER_FOUR = makeAddr("signer_four");
    address public SIGNER_FIVE = makeAddr("signer_five");

    address public SPENDER_ONE = makeAddr("spender_one");
    address public SPENDER_TWO = makeAddr("spender_two");

    uint256 public OWNER_BALANCE_ONE = 0.5 ether;
    uint256 public OWNER_BALANCE_TWO = 5 ether;
    uint256 public OWNER_BALANCE_THREE = 50 ether;
    uint256 public OWNER_BALANCE_FOUR = 500 ether;

    function setUp() public {
        multiSigTimelock = new MultiSigTimelock();
        // console2.log(msg.sender, address(this));
        // multiSigTimelock.trans
        ethRejector = new EthRejector();
        // ethRefunder = new EthRefunder();
    }

    //////////////////////////////
    /// SIGNING ROLE TESTS   /////
    //////////////////////////////
    function testOwnerIsAutoSigner() public view {
        // ASSERT
        // After deployment, owner(address(this))- in the case, should be first signer
        assertEq(multiSigTimelock.getSignerCount(), 1);
        assertTrue(multiSigTimelock.hasRole(multiSigTimelock.getSigningRole(), address(this)));
    }

    function testGrantSigningRoles() public {
        // ARRANGE
        uint256 signerCount = 5;
        address[] memory signersArray = new address[](5);

        // ACT
        signersArray[0] = OWNER;
        multiSigTimelock.grantSigningRole(SIGNER_TWO);
        signersArray[1] = SIGNER_TWO;
        multiSigTimelock.grantSigningRole(SIGNER_THREE);
        signersArray[2] = SIGNER_THREE;
        multiSigTimelock.grantSigningRole(SIGNER_FOUR);
        signersArray[3] = SIGNER_FOUR;
        multiSigTimelock.grantSigningRole(SIGNER_FIVE);
        signersArray[4] = SIGNER_FIVE;

        // ASSERT
        assertEq(multiSigTimelock.getSignerCount(), signerCount);
        assertEq(abi.encodePacked(multiSigTimelock.getSigners()), abi.encodePacked(signersArray));
    }

    function testGrantSigningRoleRevertsIfMoreThanFiveAddress() public {
        // ARRANGE
        address notAllowedAddress = makeAddr("notAllowedAddress");

        // ACT
        multiSigTimelock.grantSigningRole(SIGNER_TWO);
        multiSigTimelock.grantSigningRole(SIGNER_THREE);
        multiSigTimelock.grantSigningRole(SIGNER_FOUR);
        multiSigTimelock.grantSigningRole(SIGNER_FIVE);

        // ASSERT
        vm.expectRevert(MultiSigTimelock.MultiSigTimelock__MaximumSignersReached.selector);
        multiSigTimelock.grantSigningRole(notAllowedAddress);
    }

    function testGrantSigningRoleRevertsIfAlreadyASigner() public {
        // ACT
        multiSigTimelock.grantSigningRole(SIGNER_TWO);
        multiSigTimelock.grantSigningRole(SIGNER_THREE);
        multiSigTimelock.grantSigningRole(SIGNER_FOUR);

        // ASSERT
        vm.expectRevert(MultiSigTimelock.MultiSigTimelock__AccountIsAlreadyASigner.selector);
        multiSigTimelock.grantSigningRole(SIGNER_FOUR);
    }

    function testGrantSigningRoleRevertsIfZeroAddresses() public {
        vm.expectRevert(MultiSigTimelock.MultiSigTimelock__InvalidAddress.selector);
        multiSigTimelock.grantSigningRole(address(0));
    }

    modifier grantSigningRoles() {
        multiSigTimelock.grantSigningRole(SIGNER_TWO);
        multiSigTimelock.grantSigningRole(SIGNER_THREE);
        multiSigTimelock.grantSigningRole(SIGNER_FOUR);
        multiSigTimelock.grantSigningRole(SIGNER_FIVE);
        _;
    }

    /////////////////////////////////////
    /// REVOKE SIGNING ROLE TESTS   /////
    /////////////////////////////////////
    function testRevokeSigningRole() public grantSigningRoles {
        multiSigTimelock.revokeSigningRole(SIGNER_TWO);
        multiSigTimelock.revokeSigningRole(SIGNER_THREE);
        multiSigTimelock.revokeSigningRole(SIGNER_FOUR);
        multiSigTimelock.revokeSigningRole(SIGNER_FIVE);
    }

    function testRevokeSigningRoleRevertsIfNotASigner() public grantSigningRoles {
        multiSigTimelock.revokeSigningRole(SIGNER_TWO);
        multiSigTimelock.revokeSigningRole(SIGNER_THREE);
        multiSigTimelock.revokeSigningRole(SIGNER_FOUR);

        vm.expectRevert(MultiSigTimelock.MultiSigTimelock__AccountIsNotASigner.selector);
        multiSigTimelock.revokeSigningRole(SIGNER_FOUR);
    }

    function testRevokeSigningRoleRevertsIfZeroAddresses() public grantSigningRoles {
        vm.expectRevert(MultiSigTimelock.MultiSigTimelock__InvalidAddress.selector);
        multiSigTimelock.revokeSigningRole(address(0));
    }

    function testRevokeSigningRoleRevertsIfOnlyOneSigner() public {
        vm.expectRevert(MultiSigTimelock.MultiSigTimelock__CannotRevokeLastSigner.selector);
        multiSigTimelock.revokeSigningRole(address(this));
    }

    /////////////////////////////////////
    /// PROPOSE TRANSACTION TESTS   /////
    /////////////////////////////////////
    function testOwnerCanProposeTransaction() public {
        // ARRANGE
        vm.deal(OWNER, OWNER_BALANCE_ONE);

        // ACT & ASSERT
        vm.prank(OWNER);
        uint256 txnId = multiSigTimelock.proposeTransaction(SPENDER_ONE, OWNER_BALANCE_ONE, hex"");
        console2.log("This is the first transaction ID", txnId);
        assertEq(txnId, 0);

        vm.prank(OWNER);
        uint256 txnIdTwo = multiSigTimelock.proposeTransaction(SPENDER_ONE, OWNER_BALANCE_ONE, hex"");
        console2.log("This is the second transaction ID", txnIdTwo);
        assertEq(txnIdTwo, 1);
    }

    function testProposeTransactionRevertsIfZeroAddress() public {
        // ARRANGE
        vm.deal(OWNER, OWNER_BALANCE_ONE);

        // ACT & ASSERT
        vm.prank(OWNER);
        vm.expectRevert(MultiSigTimelock.MultiSigTimelock__InvalidAddress.selector);
        multiSigTimelock.proposeTransaction(address(0), OWNER_BALANCE_ONE, hex"");
    }

    function testProposeTransactionRevertsIfNonOwner() public {
        // ARRANGE
        address nonOwner = makeAddr("non_owner");

        // ACT & ASSERT
        vm.prank(nonOwner);
        vm.expectRevert();
        multiSigTimelock.proposeTransaction(SPENDER_ONE, OWNER_BALANCE_ONE, hex"");
    }

    modifier proposeTransactionSuccessfuly() {
        vm.deal(OWNER, OWNER_BALANCE_ONE);
        vm.prank(OWNER);
        uint256 txnId = multiSigTimelock.proposeTransaction(SPENDER_ONE, OWNER_BALANCE_ONE, hex"");
        _;
    }

    /////////////////////////////////////
    /// CONFIRM TRANSACTION TESTS   /////
    /////////////////////////////////////
    function testSignerCanConfirmTransaction() public grantSigningRoles {
        // ARRANGE
        vm.deal(OWNER, OWNER_BALANCE_ONE);
        vm.prank(OWNER);
        uint256 txnId = multiSigTimelock.proposeTransaction(SPENDER_ONE, OWNER_BALANCE_ONE, hex"");

        // ACT
        vm.prank(OWNER);
        multiSigTimelock.confirmTransaction(txnId);
        vm.prank(SIGNER_TWO);
        multiSigTimelock.confirmTransaction(txnId);
        vm.prank(SIGNER_THREE);
        multiSigTimelock.confirmTransaction(txnId);
        vm.prank(SIGNER_FOUR);
        multiSigTimelock.confirmTransaction(txnId);
        vm.prank(SIGNER_FIVE);
        multiSigTimelock.confirmTransaction(txnId);
    }

    function testConfirmTransactionRevertsIfAlreadySigned() public grantSigningRoles {
        // ARRANGE
        vm.deal(OWNER, OWNER_BALANCE_ONE);
        vm.prank(OWNER);
        uint256 txnId = multiSigTimelock.proposeTransaction(SPENDER_ONE, OWNER_BALANCE_ONE, hex"");

        // ACT
        vm.prank(OWNER);
        multiSigTimelock.confirmTransaction(txnId);
        vm.prank(OWNER);
        vm.expectRevert(MultiSigTimelock.MultiSigTimeLock__UserAlreadySigned.selector);
        multiSigTimelock.confirmTransaction(txnId);
    }

    function testConfirmTransactionRevertsIfTransactionDoesNotExists() public grantSigningRoles {
        // ARRANGE
        vm.deal(OWNER, OWNER_BALANCE_ONE);
        vm.prank(OWNER);
        uint256 txnId = multiSigTimelock.proposeTransaction(SPENDER_ONE, OWNER_BALANCE_ONE, hex"");

        // ACT
        vm.prank(OWNER);
        vm.expectRevert(
            abi.encodeWithSelector(MultiSigTimelock.MultiSigTimelock__TransactionDoesNotExist.selector, txnId + 1)
        );
        multiSigTimelock.confirmTransaction(txnId + 1);
    }

    function testConfirmTransactionRevertsIfNonSigner() public grantSigningRoles {
        // ARRANGE
        address nonSigner = makeAddr("non_owner");
        vm.deal(OWNER, OWNER_BALANCE_ONE);
        vm.prank(OWNER);
        uint256 txnId = multiSigTimelock.proposeTransaction(SPENDER_ONE, OWNER_BALANCE_ONE, hex"");

        // ACT
        vm.prank(nonSigner);
        vm.expectRevert();
        multiSigTimelock.confirmTransaction(txnId);
    }

    function testConfirmTransactionRevertsIfTransactionHasExecuted() public grantSigningRoles {
        // ARRANGE
        vm.deal(address(multiSigTimelock), OWNER_BALANCE_TWO);
        vm.prank(OWNER);
        uint256 txnId = multiSigTimelock.proposeTransaction(SPENDER_ONE, OWNER_BALANCE_ONE, hex"");

        // ACT & ASSERT
        vm.prank(OWNER);
        multiSigTimelock.confirmTransaction(txnId);
        vm.prank(SIGNER_TWO);
        multiSigTimelock.confirmTransaction(txnId);
        vm.prank(SIGNER_THREE);
        multiSigTimelock.confirmTransaction(txnId);
        vm.prank(SIGNER_FOUR);
        multiSigTimelock.confirmTransaction(txnId);
        vm.prank(SIGNER_FIVE);
        multiSigTimelock.confirmTransaction(txnId);

        vm.prank(OWNER);
        multiSigTimelock.executeTransaction(txnId);

        vm.prank(OWNER);
        vm.expectRevert(abi.encodePacked(MultiSigTimelock.MultiSigTimelock__TransactionAlreadyExecuted.selector, txnId));
        multiSigTimelock.confirmTransaction(txnId);
    }

    // only role tests will be written after i finish the execute function
    /////////////////////////////////////
    /// REVOKE CONFIRMATION TESTS    /////
    /////////////////////////////////////
    function testSignerCanRevokeConfirmation() public grantSigningRoles {
        // ARRANGE
        vm.deal(OWNER, OWNER_BALANCE_ONE);
        vm.prank(OWNER);
        uint256 txnId = multiSigTimelock.proposeTransaction(SPENDER_ONE, OWNER_BALANCE_ONE, hex"");

        // ACT
        vm.prank(OWNER);
        multiSigTimelock.confirmTransaction(txnId);
        vm.prank(SIGNER_TWO);
        multiSigTimelock.confirmTransaction(txnId);
        vm.prank(SIGNER_THREE);
        multiSigTimelock.confirmTransaction(txnId);
        vm.prank(SIGNER_FOUR);
        multiSigTimelock.confirmTransaction(txnId);
        vm.prank(SIGNER_FIVE);
        multiSigTimelock.confirmTransaction(txnId);

        vm.prank(OWNER);
        multiSigTimelock.revokeConfirmation(txnId);
        vm.prank(SIGNER_TWO);
        multiSigTimelock.revokeConfirmation(txnId);
        vm.prank(SIGNER_THREE);
        multiSigTimelock.revokeConfirmation(txnId);
        vm.prank(SIGNER_FOUR);
        multiSigTimelock.revokeConfirmation(txnId);
        vm.prank(SIGNER_FIVE);
        multiSigTimelock.revokeConfirmation(txnId);
    }

    function testRevokeConfirmationRevertsIfNotSignedOrAlreadyRevoked() public grantSigningRoles {
        // ARRANGE
        vm.deal(OWNER, OWNER_BALANCE_ONE);
        vm.prank(OWNER);
        uint256 txnId = multiSigTimelock.proposeTransaction(SPENDER_ONE, OWNER_BALANCE_ONE, hex"");

        // ACT
        vm.prank(OWNER);
        vm.expectRevert(MultiSigTimelock.MultiSigTimeLock__UserHasNotSigned.selector);
        multiSigTimelock.revokeConfirmation(txnId);

        vm.prank(OWNER);
        multiSigTimelock.confirmTransaction(txnId);
        vm.prank(OWNER);
        multiSigTimelock.revokeConfirmation(txnId);
        vm.prank(OWNER);
        vm.expectRevert(MultiSigTimelock.MultiSigTimeLock__UserHasNotSigned.selector);
        multiSigTimelock.revokeConfirmation(txnId);
    }

    function testRevokeConfirmationRevertsIfTransactionDoesNotExists() public grantSigningRoles {
        // ARRANGE
        vm.deal(OWNER, OWNER_BALANCE_ONE);
        vm.prank(OWNER);
        uint256 txnId = multiSigTimelock.proposeTransaction(SPENDER_ONE, OWNER_BALANCE_ONE, hex"");

        // ACT
        vm.prank(OWNER);
        multiSigTimelock.confirmTransaction(txnId);

        vm.prank(OWNER);
        vm.expectRevert(
            abi.encodeWithSelector(MultiSigTimelock.MultiSigTimelock__TransactionDoesNotExist.selector, txnId + 1)
        );
        multiSigTimelock.revokeConfirmation(txnId + 1);
    }

    function testRevokeConfirmationRevertsIfNonSigner() public grantSigningRoles {
        // ARRANGE
        address nonSigner = makeAddr("non_owner");
        vm.deal(OWNER, OWNER_BALANCE_ONE);
        vm.prank(OWNER);
        uint256 txnId = multiSigTimelock.proposeTransaction(SPENDER_ONE, OWNER_BALANCE_ONE, hex"");

        // ACT
        vm.prank(OWNER);
        multiSigTimelock.confirmTransaction(txnId);

        vm.prank(nonSigner);
        vm.expectRevert();
        multiSigTimelock.revokeConfirmation(txnId);
    }

    function testRevokeConfirmationRevertsIfTransactionHasExecuted() public grantSigningRoles {
        // ARRANGE
        vm.deal(address(multiSigTimelock), OWNER_BALANCE_TWO);
        vm.prank(OWNER);
        uint256 txnId = multiSigTimelock.proposeTransaction(SPENDER_ONE, OWNER_BALANCE_ONE, hex"");

        // ACT & ASSERT
        vm.prank(OWNER);
        multiSigTimelock.confirmTransaction(txnId);
        vm.prank(SIGNER_TWO);
        multiSigTimelock.confirmTransaction(txnId);
        vm.prank(SIGNER_THREE);
        multiSigTimelock.confirmTransaction(txnId);
        vm.prank(SIGNER_FOUR);
        multiSigTimelock.confirmTransaction(txnId);
        vm.prank(SIGNER_FIVE);
        multiSigTimelock.confirmTransaction(txnId);

        vm.prank(OWNER);
        multiSigTimelock.executeTransaction(txnId);

        vm.prank(OWNER);
        vm.expectRevert(abi.encodePacked(MultiSigTimelock.MultiSigTimelock__TransactionAlreadyExecuted.selector, txnId));
        multiSigTimelock.revokeConfirmation(txnId);
    }

    ///////////////////////////////////////
    /// EXECUTE TRANSACTION TESTS    /////
    /////////////////////////////////////
    function testExecuteTransactionSuccessfully() public grantSigningRoles {
        // ARRANGE
        // vm.deal(OWNER, OWNER_BALANCE_TWO); //
        vm.deal(address(multiSigTimelock), OWNER_BALANCE_TWO);
        console2.log("OWNER BALANCE: ", OWNER.balance);
        vm.prank(OWNER);
        uint256 txnId = multiSigTimelock.proposeTransaction(SPENDER_ONE, OWNER_BALANCE_ONE, hex"");

        // ACT
        vm.prank(OWNER);
        multiSigTimelock.confirmTransaction(txnId);
        vm.prank(SIGNER_TWO);
        multiSigTimelock.confirmTransaction(txnId);
        vm.prank(SIGNER_THREE);
        multiSigTimelock.confirmTransaction(txnId);
        vm.prank(SIGNER_FOUR);
        multiSigTimelock.confirmTransaction(txnId);
        vm.prank(SIGNER_FIVE);
        multiSigTimelock.confirmTransaction(txnId);

        vm.prank(OWNER);
        multiSigTimelock.executeTransaction(txnId);
    }

    function testExecuteTransactionRevertsIfLessThanTheRequiredConfirmations() public grantSigningRoles {
        // ARRANGE
        // vm.deal(OWNER, OWNER_BALANCE_TWO); //
        vm.deal(address(multiSigTimelock), OWNER_BALANCE_TWO);
        vm.prank(OWNER);
        uint256 txnId = multiSigTimelock.proposeTransaction(SPENDER_ONE, OWNER_BALANCE_ONE, hex"");

        // ACT
        vm.prank(OWNER);
        multiSigTimelock.confirmTransaction(txnId);
        vm.prank(SIGNER_TWO);
        multiSigTimelock.confirmTransaction(txnId);

        vm.prank(OWNER);
        vm.expectRevert(
            abi.encodeWithSelector(
                MultiSigTimelock.MultiSigTimelock__InsufficientConfirmations.selector,
                multiSigTimelock.getRequiredConfirmations(),
                multiSigTimelock.getTransaction(txnId).confirmations
            )
        );
        multiSigTimelock.executeTransaction(txnId);
    }

    function testExecuteTransactionRevertsIfTimelockHasNotExpired() public grantSigningRoles {
        // ARRANGE
        // vm.deal(OWNER, OWNER_BALANCE_TWO); //
        vm.deal(address(multiSigTimelock), OWNER_BALANCE_THREE);
        vm.prank(OWNER);
        uint256 txnId = multiSigTimelock.proposeTransaction(SPENDER_ONE, OWNER_BALANCE_TWO, hex"");

        // ACT
        vm.prank(OWNER);
        multiSigTimelock.confirmTransaction(txnId);
        vm.prank(SIGNER_TWO);
        multiSigTimelock.confirmTransaction(txnId);
        vm.prank(SIGNER_THREE);
        multiSigTimelock.confirmTransaction(txnId);

        vm.prank(OWNER);
        vm.expectRevert();
        multiSigTimelock.executeTransaction(txnId);
    }

    function testExecuteTransactionRevertsIfExecutionFails() public grantSigningRoles {
        // ARRANGE
        // vm.deal(OWNER, OWNER_BALANCE_TWO); //
        ethRejector = new EthRejector();
        vm.deal(address(multiSigTimelock), OWNER_BALANCE_THREE);
        vm.prank(OWNER);
        uint256 txnId = multiSigTimelock.proposeTransaction(address(ethRejector), OWNER_BALANCE_ONE, hex"");

        // ACT
        vm.prank(OWNER);
        multiSigTimelock.confirmTransaction(txnId);
        vm.prank(SIGNER_TWO);
        multiSigTimelock.confirmTransaction(txnId);
        vm.prank(SIGNER_THREE);
        multiSigTimelock.confirmTransaction(txnId);

        vm.prank(OWNER);
        vm.expectRevert(MultiSigTimelock.MultiSigTimelock__ExecutionFailed.selector);
        multiSigTimelock.executeTransaction(txnId);
    }

    function testExecuteTransactionRevertsIfNotEnoughBalance() public grantSigningRoles {
        // ARRANGE
        // vm.deal(OWNER, OWNER_BALANCE_TWO); //
        vm.deal(address(multiSigTimelock), 0);
        vm.prank(OWNER);
        uint256 txnId = multiSigTimelock.proposeTransaction(SPENDER_ONE, OWNER_BALANCE_ONE, hex"");

        // ACT
        vm.prank(OWNER);
        multiSigTimelock.confirmTransaction(txnId);
        vm.prank(SIGNER_TWO);
        multiSigTimelock.confirmTransaction(txnId);
        vm.prank(SIGNER_THREE);
        multiSigTimelock.confirmTransaction(txnId);

        vm.prank(OWNER);
        vm.expectRevert(
            abi.encodeWithSelector(
                MultiSigTimelock.MultiSigTimelock__InsufficientBalance.selector, address(multiSigTimelock).balance
            )
        );
        multiSigTimelock.executeTransaction(txnId);
    }

    ///////////////////////////////
    /// RECEIVE FUNCTION TEST /////
    ///////////////////////////////
    function testReceiveFunction() public {
        // ARRANGE
        vm.deal(OWNER, OWNER_BALANCE_FOUR);

        // ACT
        (bool success,) = address(multiSigTimelock).call{value: OWNER_BALANCE_FOUR}("");
        require(success, "Transfer failed.");

        // ASSERT
        assertEq(address(multiSigTimelock).balance, OWNER_BALANCE_FOUR);
    }

    ///////////////////////////////
    /// TIMELOCKDELAY     TEST /////
    ///////////////////////////////
    function testTimeLockDelayReturnsCorrectValues() public {
        // ARRANGE
        testTimelockDelay = new TestTimelockDelay();
        uint256 sevenDaysTimeDelayAmount = 100 ether;
        uint256 twoDaysTimeDelayAmount = 10 ether;
        // uint256 oneDayTimeDelayAmount = 1 ether;

        // ACT & ASSERT
        assertEq(testTimelockDelay.getTimelockDelay(sevenDaysTimeDelayAmount), multiSigTimelock.getSevenDaysTimeDelay());
        assertEq(testTimelockDelay.getTimelockDelay(twoDaysTimeDelayAmount), multiSigTimelock.getTwoDaysTimeDelay());
    }

    //////////////////////////////
    /// GETTER FUNCTIONS TEST /////
    //////////////////////////////
    function testGetTimeDelay() public view {
        // ARRANGE
        uint256 sevenDaysTimeDelay = 7 days;
        uint256 twoDaysTimeDelay = 2 days;
        uint256 oneDayTimeDelay = 1 days;

        // ACT & ASSERT
        assertEq(multiSigTimelock.getSevenDaysTimeDelay(), sevenDaysTimeDelay);
        assertEq(multiSigTimelock.getTwoDaysTimeDelay(), twoDaysTimeDelay);
        assertEq(multiSigTimelock.getOneDayTimeDelay(), oneDayTimeDelay);
    }

    function testGetMaxSignerCount() public view {
        // ARRANGE
        uint256 maxSignerCount = 5;

        // ACT & ASSERT
        assertEq(multiSigTimelock.getMaximumSignerCount(), maxSignerCount);
    }

    ///////////////////////////////
    /// SCRIPT           TEST /////
    ///////////////////////////////
    function testDeployScript() public {
        deployer = new DeployMultiSigTimelock();
        MultiSigTimelock deployedContract = deployer.deployMultiSigTimelock();
        MultiSigTimelock deployedContractWithRun = deployer.run();
        assertTrue(address(deployedContract) != address(0));
        assertTrue(address(deployedContractWithRun) != address(0));
    }

    modifier deployScript() {
        deployer = new DeployMultiSigTimelock();
        _;
    }

    function testGrantSigningRoleScript() public {
        deployer = new DeployMultiSigTimelock();
        // MultiSigTimelock deployedContract = deployer.deployMultiSigTimelock();
        MultiSigTimelock deployedContractWithRun = deployer.run();

        grantor = new GrantSigningRole();
        // grantor.run();
        grantor.grantSigningRole(payable(address(deployedContractWithRun)));
        assertEq(deployedContractWithRun.getSignerCount(), 5);
    }

    function testProposeTransactionScript() public {
        deployer = new DeployMultiSigTimelock();
        MultiSigTimelock deployedContractWithRun = deployer.run();

        grantor = new GrantSigningRole();
        grantor.grantSigningRole(payable(address(deployedContractWithRun)));

        ProposeTransactionScript proposer = new ProposeTransactionScript();
        proposer.proposeTransaction(payable(address(deployedContractWithRun)));
        // assertEq(deployedContractWithRun.getTransactionCount(), 1);
    }

    function testConfirmTransactionScript() public {
        deployer = new DeployMultiSigTimelock();
        MultiSigTimelock deployedContractWithRun = deployer.run();

        grantor = new GrantSigningRole();
        grantor.grantSigningRole(payable(address(deployedContractWithRun)));

        ProposeTransactionScript proposer = new ProposeTransactionScript();
        proposer.proposeTransaction(payable(address(deployedContractWithRun)));

        ConfirmTransactionScript confirmer = new ConfirmTransactionScript();
        confirmer.confirmTransaction(payable(address(deployedContractWithRun)), 0);
        assertEq(deployedContractWithRun.getTransaction(0).confirmations, 1);
    }

    function testNoZero() public grantSigningRoles {
        vm.prank(OWNER);

        multiSigTimelock.revokeSigningRole(OWNER);
        multiSigTimelock.revokeSigningRole(SIGNER_TWO);
        multiSigTimelock.revokeSigningRole(SIGNER_THREE);
        multiSigTimelock.revokeSigningRole(SIGNER_FOUR);
        multiSigTimelock.revokeSigningRole(SIGNER_FIVE);

        address[5] memory signers = multiSigTimelock.getSigners();
        for (uint256 i = 0; i < 5; i++) {
            console2.log("signer", i, signers[i]);
        }
    }

    function testAllSignerCanCallRenounceRole() public grantSigningRoles {
        bytes32 role = multiSigTimelock.getSigningRole();
        vm.prank(SIGNER_TWO);
        multiSigTimelock.renounceRole(role, SIGNER_TWO);

        vm.prank(SIGNER_THREE);
        multiSigTimelock.renounceRole(role, SIGNER_THREE);

        vm.prank(SIGNER_FOUR);
        multiSigTimelock.renounceRole(role, SIGNER_FOUR);

        uint256 signerCount = multiSigTimelock.getSignerCount();
        console2.log(signerCount);
        address[5] memory signers = multiSigTimelock.getSigners();

        for (uint256 i = 0; i < signerCount; i++) {
            assert(multiSigTimelock.hasRole(multiSigTimelock.getSigningRole(), signers[i]));
        }

        vm.expectRevert();
        vm.prank(OWNER);
        multiSigTimelock.grantSigningRole(SIGNER_TWO);
    }

    function testNoAccoutingSystem() public grantSigningRoles {
        vm.deal(address(multiSigTimelock), 10 ether);

        vm.startPrank(OWNER);
        uint256 trxId_1 = multiSigTimelock.proposeTransaction(SIGNER_TWO, 8 ether, "");
        multiSigTimelock.confirmTransaction(trxId_1);

        uint256 gasBefore1 = gasleft();
        uint256 trxId_2 = multiSigTimelock.proposeTransaction(SIGNER_TWO, 8 ether, "");
        multiSigTimelock.confirmTransaction(trxId_2);
        uint256 gasAfter1 = gasleft();
        uint256 gasWaste1 = gasBefore1 - gasAfter1;

        vm.stopPrank();

        vm.startPrank(SIGNER_TWO);
        multiSigTimelock.confirmTransaction(trxId_1);

        uint256 gasBefore2 = gasleft();
        multiSigTimelock.confirmTransaction(trxId_2);
        uint256 gasAfter2 = gasleft();
        uint256 gasWaste2 = gasBefore2 - gasAfter2;
        vm.stopPrank();

        vm.startPrank(SIGNER_THREE);
        multiSigTimelock.confirmTransaction(trxId_1);

        uint256 gasBefore3 = gasleft();
        multiSigTimelock.confirmTransaction(trxId_2);
        uint256 gasAfter3 = gasleft();
        uint256 gasWaste3 = gasBefore3 - gasAfter3;
        vm.stopPrank();

        vm.warp(block.timestamp + 1 days);

        vm.startPrank(OWNER);
        multiSigTimelock.executeTransaction(trxId_1);

        MultiSigTimelock.Transaction memory trx1 = multiSigTimelock.getTransaction(trxId_1);
        assert(trx1.confirmations >= 3);
        assert(trx1.executed);

        vm.expectRevert();
        uint256 gasBefore4 = gasleft();
        multiSigTimelock.executeTransaction(trxId_2);
        uint256 gasAfter4 = gasleft();
        uint256 gasWaste4 = gasBefore4 - gasAfter4;

        vm.stopPrank();

        MultiSigTimelock.Transaction memory trx2 = multiSigTimelock.getTransaction(trxId_2);
        assert(trx2.confirmations >= 3);
        assert(!trx2.executed);

        uint256 gasWasteTotal = gasWaste1 + gasWaste2 + gasWaste3 + gasWaste4;

        console2.log("gas waste 1:", gasWaste1);
        console2.log("gas waste 2:", gasWaste2);
        console2.log("gas waste 3:", gasWaste3);
        console2.log("gas waste 4:", gasWaste4);
        console2.log("gas waste total:", gasWasteTotal);
    }

    function testCentralization() public grantSigningRoles {
        vm.deal(address(multiSigTimelock), 100 ether);

        // assume owner have another two wallet
        address OWNER_SECOND_WALLET = makeAddr("owner_2");
        address OWNER_THIRD_WALLET = makeAddr("owner_3");

        vm.startPrank(OWNER);
        // revoke the other signers
        multiSigTimelock.revokeSigningRole(SIGNER_TWO);
        multiSigTimelock.revokeSigningRole(SIGNER_THREE);
        // grant his other wallet signing roll
        multiSigTimelock.grantSigningRole(OWNER_SECOND_WALLET);
        multiSigTimelock.grantSigningRole(OWNER_THIRD_WALLET);
        //transfer ownership to another wallet from owner
        multiSigTimelock.transferOwnership(OWNER_SECOND_WALLET);
        vm.stopPrank();

        // new owner of the contract
        vm.startPrank(OWNER_SECOND_WALLET);
        // malicious propose
        uint256 trx_Id = multiSigTimelock.proposeTransaction(OWNER_THIRD_WALLET, 100 ether, "");
        multiSigTimelock.confirmTransaction(trx_Id);
        vm.stopPrank();

        // owner still have the SigningRole
        vm.prank(OWNER);
        multiSigTimelock.confirmTransaction(trx_Id);

        vm.warp(block.timestamp + 7 days);

        vm.startPrank(OWNER_THIRD_WALLET);
        multiSigTimelock.confirmTransaction(trx_Id);
        multiSigTimelock.executeTransaction(trx_Id);

        //drain the money
        assertEq(address(multiSigTimelock).balance, 0);

        MultiSigTimelock.Transaction memory trx = multiSigTimelock.getTransaction(trx_Id);
        assert(trx.confirmations >= 3);
        assert(trx.executed);
    }

    function testRevokeSigningRoleDoesNotAffectExistingConfirmations() public grantSigningRoles {
        vm.deal(address(multiSigTimelock), 100 ether);
        address recipient = makeAddr("recipient");

        vm.prank(OWNER);
        uint256 trx_Id = multiSigTimelock.proposeTransaction(recipient, 100 ether, "");

        vm.prank(SIGNER_TWO);
        multiSigTimelock.confirmTransaction(trx_Id);
        vm.prank(SIGNER_THREE);
        multiSigTimelock.confirmTransaction(trx_Id);
        vm.prank(SIGNER_FOUR);
        multiSigTimelock.confirmTransaction(trx_Id);

        vm.prank(OWNER);
        multiSigTimelock.revokeSigningRole(SIGNER_TWO);

        vm.warp(block.timestamp + 7 days);
        vm.prank(SIGNER_FOUR);
        multiSigTimelock.executeTransaction(trx_Id);

        MultiSigTimelock.Transaction memory trx = multiSigTimelock.getTransaction(trx_Id);
        assert(trx.confirmations >= 3);
        assert(trx.executed);
    }

    function testTransferToSelf() public grantSigningRoles {
        vm.deal(address(multiSigTimelock), 100 ether);
        address recipient = makeAddr("recipient");

        vm.prank(OWNER);
        uint256 trx_Id_1 = multiSigTimelock.proposeTransaction(address(multiSigTimelock), 95 ether, "");

        vm.prank(SIGNER_TWO);
        multiSigTimelock.confirmTransaction(trx_Id_1);
        vm.prank(SIGNER_THREE);
        multiSigTimelock.confirmTransaction(trx_Id_1);
        vm.prank(SIGNER_FOUR);
        multiSigTimelock.confirmTransaction(trx_Id_1);

        uint256 balanceBefore = address(multiSigTimelock).balance;

        vm.warp(block.timestamp + 7 days);
        vm.prank(OWNER);
        multiSigTimelock.executeTransaction(trx_Id_1);

        uint256 balanceAfter = address(multiSigTimelock).balance;

        assertGt(balanceBefore, balanceAfter);
    }

    function test_RevertOnFailedExecutionAndStateRollback() public grantSigningRoles {
        vm.deal(address(multiSigTimelock), 10 ether);

        vm.prank(OWNER);
        uint256 txId = multiSigTimelock.proposeTransaction(address(ethRejector), 1 ether, "0x1234");

        vm.prank(SIGNER_TWO);
        multiSigTimelock.confirmTransaction(txId);
        vm.prank(SIGNER_THREE);
        multiSigTimelock.confirmTransaction(txId);
        vm.prank(SIGNER_FOUR);
        multiSigTimelock.confirmTransaction(txId);

        vm.warp(block.timestamp + 7 days);

        vm.expectRevert();
        vm.prank(OWNER);
        multiSigTimelock.executeTransaction(txId);

        uint256 gasBefore = gasleft();
        vm.expectRevert();
        vm.prank(SIGNER_FOUR);
        multiSigTimelock.executeTransaction(txId);
        uint256 gasAfter = gasleft();

        MultiSigTimelock.Transaction memory txn = multiSigTimelock.getTransaction(txId);

        assertEq(txn.executed, false);

        console2.log("gas waste:", gasBefore - gasAfter);
    }

    function testproposeSplitTransactions() public grantSigningRoles {
        vm.deal(address(multiSigTimelock), 150 ether);
        address recipient = makeAddr("recipient");
        uint256 amountToSend = 9.9 ether;
        uint256 timesToSend = 12;

        uint256 BalanceRecipientBefore = recipient.balance;
        vm.prank(OWNER);
        for (uint256 i = 0; i < timesToSend; i++) {
            multiSigTimelock.proposeTransaction(recipient, amountToSend, "i");
        }

        address[3] memory signersToConfirm = [OWNER, SIGNER_TWO, SIGNER_THREE];
        for (uint256 s = 0; s < signersToConfirm.length; s++) {
            vm.startPrank(signersToConfirm[s]);
            for (uint256 i = 0; i < timesToSend; i++) {
                multiSigTimelock.confirmTransaction(i);
            }
            vm.stopPrank();
        }

        vm.warp(block.timestamp + 1 days);

        vm.prank(OWNER);
        for (uint256 i = 0; i < timesToSend; i++) {
            multiSigTimelock.executeTransaction(i);
        }

        uint256 BalanceRecipientAfter = recipient.balance;

        assertEq(BalanceRecipientAfter, BalanceRecipientBefore + amountToSend * timesToSend);
        console2.log("BalanceRecipientAfter:", BalanceRecipientAfter);
    }
}
