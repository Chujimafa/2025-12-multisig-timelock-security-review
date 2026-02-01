
## High

### [H-1] Ghost Signers in `s_signers` list lead to permanent Multi-Sig Wallet Lock
**Description:**
The `MultiSigTimelock` contract inherits from OpenZeppelin's `AccessControl` contract for permission management. AccessControl includes a public function `renounceRole` which allows an signer to unilaterally relinquish its assigned role `SIGNING_ROLE` without authorization from the contract Owner.

However, `MultiSigTimelock` implements internal tracking of active signers through a custom `s_signerCount` counter and an `s_isSigner` mapping. Since the contract fails to override the inherited renounceRole function, any signer who renounces their role will trigger a state mismatch: the role is removed at the AccessControl level, but the internal `s_signerCount` and `s_isSigner` states remain unchanged.

```solidity
    function renounceRole(bytes32 role, address callerConfirmation) public virtual {
        if (callerConfirmation != _msgSender()) {
            revert AccessControlBadConfirmation();
        }
        _revokeRole(role, callerConfirmation);
    }
```
**Risk:**
- **Likelihood**: High
   Any signer can call function `renounceRole`.  

- **impact** :Renouncing roles prevents the quorum from being met and freezes transaction execution, while the stale s_signerCount blocks the Owner from adding new signers, effectively allowing the authorized signer count to drop to zero and bypassing the "at least one signer" safety rule.
   
**Proof of Concept:**: 
- Three signers unilaterally renounce their roles, proving they can exit without Owner approval.
- The test confirms "Ghost Signers" exist because the registry still lists addresses that no longer hold signing roles.
- The expectRevert proves the Owner is blocked from adding new signers because the stale counter falsely indicates the wallet is full.

place the following code in MultiSigTimelockTest.t.sol:
<details>
<summary>Proof of Code</summary>

```Solidity
    function testAllSignerCanCallRenounceRole() public grantSigningRoles {
        bytes32 role = multiSigTimelock.getSigningRole();
        // 3 signer renounceRole
        vm.prank(SIGNER_TWO);
        multiSigTimelock.renounceRole(role, SIGNER_TWO);
        vm.prank(SIGNER_THREE);
        multiSigTimelock.renounceRole(role, SIGNER_THREE);
        vm.prank(SIGNER_FOUR);
        multiSigTimelock.renounceRole(role, SIGNER_FOUR);

        
        uint256 signerCount = multiSigTimelock.getSignerCount();
        console2.log(signerCount);
        address[5] memory signers = multiSigTimelock.getSigners();
        // there are signers in Signer list which do not have role
        for (uint256 i = 0; i < signerCount; i++) {
           assert(multiSigTimelock.hasRole(multiSigTimelock.getSigningRole(),signers[i]));
       }   
        // owner cannot add new Signer
       vm.expectRevert();
        vm.prank(OWNER);
       multiSigTimelock.grantSigningRole(SIGNER_TWO);
    }

```
</details>

**Recommended Mitigation:**: Override the function `renounceRole` to disable it for all users.

```diff
+    function renounceRole(bytes32 role, address account) public virtual override {
+        revert;
+    }
```
### [H-2] Centralization Risk: Excessive Owner Privileges Lead to Governance Bypass

**Description:**
The contract lacks sufficient restrictions on the Owner's privileges, leading to a critical centralization risk. The Owner maintains absolute authority to unilaterally change the contract's ownership and modify the signingRole by adding or revoking signers at will. This excessive power allows a malicious Owner to replace legitimate signers with controlled addresses, satisfying the multi-signature requirement to bypass security protocols.


**impact**
1. Transfer Ownership: Change the contract's Owner at any time without consensus.
2. Manipulate Signing Roles: Arbitrarily call grantSigningRole and revokeSigningRole. This allows a malicious owner to remove legitimate signers and replace them with controlled "sybil" accounts.
   
**Proof of Concept:**: 
The Owner can unilaterally revoke two honest signers and grant signing roles to two controlled sub-wallets. After transferring contract ownership to one of these sub-wallets, the Owner would maintain signing authority across three separate accounts. They could then propose a transfer of all funds to their own address and provide all three required confirmations using these controlled wallets, bypassing the multisig consensus to drain the vault.

place the following code in MultiSigTimelockTest.t.sol:
<details>
<summary>Proof of Code</summary>

```solidity
    function testCentralization() public grantSigningRoles {

         vm.deal(address(multiSigTimelock), 100 ether);

        // assume owner have another two wallet
        address OWNER_SECOND_WALLET= makeAddr("owner_2");
        address OWNER_THIRD_WALLET= makeAddr("owner_3");

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
        uint256 trx_Id=multiSigTimelock.proposeTransaction(OWNER_THIRD_WALLET,100 ether,"");
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
        assertEq(address(multiSigTimelock).balance,0);

        MultiSigTimelock.Transaction memory trx = multiSigTimelock.getTransaction(trx_Id);
        assert(trx.confirmations >= 3);
        assert(trx.executed);

    }
```
</details>

**Recommended Mitigation:**Remove the `onlyOwner` modifier from sensitive administrative functions and replace it with a `onlySelf` modifier that restricts access to the contract itself. Functions such as `grantSigningRole`, `revokeSigningRole`, and `transferOwnership` should only be executable via the `executeTransaction`.

```diff
+    modifier onlySelf() {
+        require(msg.sender == address(this), "Must be executed via multisig process");
+        _;
+    }

```

### [H-3] Single-transaction value-based delay logic can be bypassed via transaction splitting
**Description:**:
The `_executeTransaction` logic only validates the timelock for individual transfers and fails to track the cumulative value of multiple transactions over time. This allows an attacker to bypass long delay requirements by splitting one large high-risk transfer into several small transactions. Because each small transaction stays below the value threshold, the security window is never triggered, allowing significant funds to be drained much faster than intended. 
**Risk:**

- **Likelihood** Although only the Owner can propose, the risk becomes reality if the Owner turns malicious or their private key is compromised.
- **impact** completely nullifies the Timelock protection, allowing the treasury to be drained instantly and depriving the protocol of the intended emergency response window.
**Proof of Concept:**: 
  This test splits a single large 118.8 ETH transfer into 12 small transactions to bypass the 7-day delay. By keeping each transaction under the value threshold, it forces the contract to apply a 1-day delay instead, allowing the total funds to be drained 6 days earlier than intended.

place the following code in MultiSigTimelockTest.t.sol:
<details>
<summary>Proof of Code</summary>

```solidity
function testproposeSplitTransactions() public grantSigningRoles {
        vm.deal(address(multiSigTimelock), 150 ether);
        address recipient = makeAddr("recipient");
        uint256 amountToSend = 9.9 ether;
        uint256 timesToSend = 12;
        // send 12 proposetrnasaction total 118,8 ether
        uint256 BalanceRecipientBefore = recipient.balance;
        vm.prank(OWNER);
        for(uint256 i=0;i<timesToSend;i++){
            multiSigTimelock.proposeTransaction(recipient,amountToSend,"i");            
        }
        //3 signer confirm all the transaction
        address[3] memory signersToConfirm = [OWNER, SIGNER_TWO, SIGNER_THREE];
        for(uint256 s=0; s < signersToConfirm.length; s++) {
            vm.startPrank(signersToConfirm[s]);
            for(uint256 i=0; i < timesToSend; i++) {
                 multiSigTimelock.confirmTransaction(i);
        }
        vm.stopPrank();
      }
        //only pass 1 days
        vm.warp(block.timestamp + 1 days);

        vm.prank(OWNER);
         for(uint256 i=0;i<timesToSend;i++){
            multiSigTimelock.executeTransaction(i);            
        }

        uint256 BalanceRecipientAfter = recipient.balance;
        // reciepient get all 118,8 ether just in one day
        assertEq(BalanceRecipientAfter,BalanceRecipientBefore + amountToSend*timesToSend);
        console2.log("BalanceRecipientAfter:", BalanceRecipientAfter);

    }
```
</details>

**Recommended Mitigation:** Implement a global s_totalPendingAmount to track cumulative outflow within a rolling 24-hour window. The logic ensures that the delay is determined by the total volume of all pending and recent transactions, preventing attackers from bypassing long security delays by splitting large transfers into multiple small ones.

```diff
+   uint256 public s_totalPendingAmount;
+   uint256 public s_lastResetTime;

-   function _getTimelockDelay(uint256 value) public pure returns (uint256) {
+   function _getTimelockDelay(uint256 value) public returns (uint256) {
+       if (block.timestamp >= s_lastResetTime + 24 hours) {
+           s_totalPendingAmount = 0;
+           s_lastResetTime = block.timestamp;
+       }
+       s_totalPendingAmount += value;

        uint256 sevenDaysTimeDelayAmount = 100 ether;
        uint256 twoDaysTimeDelayAmount = 10 ether;
        uint256 oneDayTimeDelayAmount = 1 ether;

-       if (value >= sevenDaysTimeDelayAmount) {
+       if (s_totalPendingAmount >= sevenDaysTimeDelayAmount) {
            return SEVEN_DAYS_TIME_DELAY;
-       } else if (value >= twoDaysTimeDelayAmount) {
+       } else if (s_totalPendingAmount >= twoDaysTimeDelayAmount) {
            return TWO_DAYS_TIME_DELAY;
-       } else if (value >= oneDayTimeDelayAmount) {
+       } else if (s_totalPendingAmount >= oneDayTimeDelayAmount) {
            return ONE_DAY_TIME_DELAY;
        } else {
            return NO_TIME_DELAY;
        }
    }

    }
```



## Medium

### [M-1] Missing Accounting Logic Leads to Gas Waste and Zombie Transactions
**Description:**
The contract lacks an internal accounting ledger. The `proposeTransaction` function does not verify if the value is valid or if it exceeds the contract's available balance. Furthermore, `executeTransaction` only checks `address(this).balance` instead of verifying the actual usable funds. This allows multiple invalid transactions to be proposed, leading to significant Gas waste as signers expend resources on transactions destined to fail. Additionally, it causes management chaos, flooding the multisig queue with unexecutable "zombie transactions.

``` solidity
 function _executeTransaction(uint256 txnId) internal {
        ...

@>        if (txn.value > address(this).balance) {
@>               revert MultiSigTimelock__InsufficientBalance(address(this).balance);
        }
```

**Risk:**
- **Likelihood** High
  The contract fails to verify the actual available balance, allowing owners to create transactions that are destined to fail due to the lack of fund tracking.
- **impact**
1. Gas Waste: Signers lose non-refundable gas fees confirming transactions destined to fail.
2. Operational DoS: The queue is cluttered with "zombie transactions," hindering the identification of valid operations.
3. Fund Blocking: Pending high-value proposals may obscure or delay urgent, executable transactions.
  
**Proof of Concept:**: 
The owner created two transactions with a total value exceeding the contract balance. Due to the lack of balance checks, both were successfully proposed and confirmed. However, only the first transaction could execute; the second one inevitably reverted due to insufficient funds. As a result, a transaction destined to fail wasted **199,680** Gas.


place the following code in MultiSigTimelockTest.t.sol:
<details>
<summary> Proof Of Code </summary>

```solidity
    function testNoAccoutingSystem() public grantSigningRoles {
        vm.deal(address(multiSigTimelock), 10 ether);

        // owner propose and confirm 2 transaction
        vm.startPrank(OWNER);
        uint256 trxId_1 = multiSigTimelock.proposeTransaction(SIGNER_TWO, 8 ether, "");
        multiSigTimelock.confirmTransaction(trxId_1);

        uint256 gasBefore1 = gasleft();
        uint256 trxId_2 = multiSigTimelock.proposeTransaction(SIGNER_TWO, 8 ether, "");
        multiSigTimelock.confirmTransaction(trxId_2);
        uint256 gasAfter1 = gasleft();
        uint256 gasWaste1 = gasBefore1 - gasAfter1;

        vm.stopPrank();

        // 2 other signer confirm the transaction
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

        // pass the locked time
        vm.warp(block.timestamp + 1 days);

        // execute the two transaction
        vm.startPrank(OWNER);
        multiSigTimelock.executeTransaction(trxId_1);
        // trx 1 will success
        MultiSigTimelock.Transaction memory trx1 = multiSigTimelock.getTransaction(trxId_1);
        assert(trx1.confirmations >= 3);
        assert(trx1.executed);
        // trx2 will fail
        vm.expectRevert();
        uint256 gasBefore4 = gasleft();
        multiSigTimelock.executeTransaction(trxId_2);
        uint256 gasAfter4 = gasleft();
        uint256 gasWaste4 = gasBefore4 - gasAfter4;

        vm.stopPrank();
        // trx2 is valid and can get all the confirmation, but will revert
        MultiSigTimelock.Transaction memory trx2 = multiSigTimelock.getTransaction(trxId_2);
        assert(trx2.confirmations >= 3);
        assert(!trx2.executed);
        // total gas spend for the trx2
        uint256 gasWasteTotal = gasWaste1 + gasWaste2 + gasWaste3 + gasWaste4;

        console2.log("gas waste 1:", gasWaste1);
        console2.log("gas waste 2:", gasWaste2);
        console2.log("gas waste 3:", gasWaste3);
        console2.log("gas waste 4:", gasWaste4);
        console2.log("gas waste total:", gasWasteTotal);
    }
```
```
Logs:
  gas waste 1: 132994
  gas waste 2: 30128
  gas waste 3: 30128
  gas waste 4: 6430
  gas waste total: 199680

```
</details>

**Recommended Mitigation:**
Implement a state variable `s_totalPendingAmount` to track funds committed to active proposals.

```diff
+   uint256 private s_totalPendingAmount;

    function _proposeTransaction(address to, uint256 value, bytes memory data) internal returns (uint256) {

     // check value is valid
+    if (value > address(this).balance - s_totalPendingAmount){
+       revert}
     
     .....
    // update pending value
+    s_totalPendingAmount += value}

    function _executeTransaction(uint256 txnId) internal {

        ....
        // update pending value
+       s_totalPendingAmount -= value      
        (bool success,) = payable(txn.to).call{value: txn.value}(txn.data);
        if (!success) {
            revert MultiSigTimelock__ExecutionFailed();
        }
    }


```

### [M-2] Revoked Signer’s Confirmation Remains Valid for Transaction Execution

**Description:**
The contract fails to invalidate existing confirmations when a user's `signingRole` is revoked. Due to the timelock, a proposal remains pending long enough for a signer's status to change. Consequently, a transaction can still reach the required threshold and be executed using approvals from individuals who no longer hold administrative privileges. This creates a state inconsistency where revoked members still influence outcomes during the delay period.

**Risk:**
- **Likelihood**
 This is a realistic risk when a signer is revoked for dishonest or malicious behavior, as their existing confirmations remain active and can still be used to reach the execution threshold for pending transactions. 
- **impact**
 The multisig consensus is compromised. Transactions can be executed using "stale" approvals from untrusted parties, allowing a revoked signer to still reach the quorum and authorize fund transfers or critical parameter changes. 

**Proof of Concept:**

place the following code in MultiSigTimelockTest.t.sol:
<details>
<summary> Proof Of Code </summary>

```solidity
  function testRevokeSigningRoleDoesNotAffectExistingConfirmations() grantSigningRoles public  {
        
     vm.deal(address(multiSigTimelock), 100 ether);
     address recipient = makeAddr("recipient");
    // propose a transaction
    vm.prank(OWNER);
    uint256 trx_Id=multiSigTimelock.proposeTransaction(recipient,100 ether,"");
    // 3 signers confirm the transaction
    vm.prank(SIGNER_TWO);
    multiSigTimelock.confirmTransaction(trx_Id);
    vm.prank(SIGNER_THREE);
    multiSigTimelock.confirmTransaction(trx_Id);
    vm.prank(SIGNER_FOUR);
    multiSigTimelock.confirmTransaction(trx_Id);
    // revoke the SigningRole from SIGNER_TWO
    vm.prank(OWNER);
    multiSigTimelock.revokeSigningRole(SIGNER_TWO);
    
    vm.warp(block.timestamp + 7 days);
    vm.prank(SIGNER_FOUR);
    multiSigTimelock.executeTransaction(trx_Id);
    // Transaction go through
    MultiSigTimelock.Transaction memory trx = multiSigTimelock.getTransaction(trx_Id);
    assert(trx.confirmations >= 3);
    assert(trx.executed);
    }

```

**Recommended Mitigation:**: The `_executeTransaction` function should verify that all confirmations originate from accounts that currently hold the `signingRole` at the time of execution.

```diff
    function _executeTransaction(uint256 txnId) internal {
-        if (txn.confirmations < REQUIRED_CONFIRMATIONS) {
-            revert MultiSigTimelock__InsufficientConfirmations(REQUIRED_CONFIRMATIONS, txn.-         confirmations);
-        }

+    uint256 validConfirmations = 0;
+    for (uint256 i = 0; i < s_signers.length; i++) {
+        address signer = s_signers[i];
+        // Check if the address is still an active signer AND previously confirmed this txn
+        if (hasRole(SIGNING_ROLE, signer) && s_signatures[txnId][signer]) {
+            validConfirmations++;
+      }
+  }+
+  if (validConfirmations < REQUIRED_CONFIRMATIONS) {
+    revert MultiSigTimelock__InsufficientConfirmations(REQUIRED_CONFIRMATIONS, txn.     +confirmations);}

       
    }
```

## Low

### [L-1] Transaction Revert on Execution Failure Leading to Repeated Gas Waste
**Description:**
The contract implements a strict atomic execution logic in `_executeTransaction`. If the external interaction fails, the entire transaction is reverted. Consequently, the state update `txn.executed = true` is rolled back, causing the transaction to remain in a "pending" state `executed == false` indefinitely. This prevents the transaction from being marked as "failed" and allows for repetitive execution attempts.

``` solidity
 function _executeTransaction(uint256 txnId) internal {
@>       if (!success) {
@>           revert MultiSigTimelock__ExecutionFailed();
        }
```

**Risk:**
**Likelihood**: Medium
It is highly common for users to propose transactions with incorrect calldata or wrong parameters. Since these transactions never expire, they will stay in the "unexecuted" state forever.

**Impact**: Low
There is no direct loss of funds because the revert protects the ETH. However, it causes permanent Gas waste as signers may repeatedly try to execute the "stuck" transaction, and it clutters the contract state with "zombie" entries.

**Proof of Concept:**: 
Transferring funds to the EthRejector contract triggers a revert on all incoming payments. The execution fails and the status remains false without being updated. Multiple signers attempting to execute the transaction result in continuous reverts and wasted gas fees.

<details>
<summary> Proof Of Code </summary>

EthRejector:

``` solidity
contract EthRejector {
    receive() external payable {
        revert("Always fails");
    }
}

```
place the following code in MultiSigTimelockTest.t.sol:

``` solidity
    function test_RevertOnFailedExecutionAndStateRollback() public  grantSigningRoles  {
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
        
        console2.log("gas waste:", gasBefore- gasAfter);
    }
```

```
Logs:
  gas waste: 37624
```
</details>

**Recommended Mitigation:**
Eliminate the revert logic by setting `executed = true` before the external call. If the call fails, emit a `TransactionFailed` event instead of reverting. this ensures the status is permanently updated on-chain, preventing redundant execution attempts and saving gas for other signers.

```diff
    function _executeTransaction(uint256 txnId) internal {
        Transaction storage txn = s_transactions[txnId];

        // 3. Mark as executed BEFORE the external call (prevent reentrancy)
        txn.executed = true;

        // INTERACTIONS
        // 4. Execute the transaction
        (bool success,) = payable(txn.to).call{value: txn.value}(txn.data);

-        if (!success) {
-            revert MultiSigTimelock__ExecutionFailed();
-        }
-        emit TransactionExecuted(txnId, txn.to, txn.value);

+     if (success) {
+          emit TransactionExecuted(txnId, txn.to, txn.value);
+     } else{
+         emit TransactionFailed(txnId, txn.to, txn.value);
+     }
```