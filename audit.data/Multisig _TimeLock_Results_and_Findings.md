# Audit Contest Summary: [Multisig TimeLock]

This document summarizes the results and key findings from my participation in the `Codehawk` audit contest, held for the `Multisig-TimeLock` codebase.

- [Audit Contest Summary: \[Multisig TimeLock\]](#audit-contest-summary-multisig-timelock)
  - [1. Overview \& Project Details](#1-overview--project-details)
  - [2. Contest Performance Summary](#2-contest-performance-summary)
- [Detailed Audit Findings (Valid Submissions)](#detailed-audit-findings-valid-submissions)
    - [\[H-1\] Single-transaction value-based delay logic can be bypassed via transaction splitting](#h-1-single-transaction-value-based-delay-logic-can-be-bypassed-via-transaction-splitting)
    - [\[M-1\] Revoked Signer’s Confirmation Remains Valid for Transaction Execution](#m-1-revoked-signers-confirmation-remains-valid-for-transaction-execution)
    - [\[L-1\] Ghost Signers in `s_signers` list lead to permanent Multi-Sig Wallet Lock](#l-1-ghost-signers-in-s_signers-list-lead-to-permanent-multi-sig-wallet-lock)


## 1. Overview & Project Details

| Field               | Detail                                                                                       |
| :------------------ | :------------------------------------------------------------------------------------------- |
| **Project Audited** | **Multisig TimeLock**                                                                        |
| **Contest Period**  | 2025/12/18 – 2025/12/15                                                                      |
| **Codebase Link**   | [2025-12-multisig-timelock](https://github.com/CodeHawks-Contests/2025-12-multisig-timelock) |
| **Final Report**    | [Final Report](https://codehawks.cyfrin.io/c/2025-12-multisig-timelock/results?t=report)     |


---

## 2. Contest Performance Summary

This section provides a statistical breakdown of my submission compared to the final results.
| Category            | My Valid Findings |  Total in Contest   |
| :------------------ | :---------------: | :-----------------: |
| **High Severity**   |       **1**       |          2          |
| **Medium Severity** |       **1**       |          6          |
| **Medium Severity** |       **1**       |          5          |
| **Overall Rank**    |     **10th**      | **57 Participants** |

---

# Detailed Audit Findings (Valid Submissions)

### [H-1] Single-transaction value-based delay logic can be bypassed via transaction splitting
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



### [M-1] Revoked Signer’s Confirmation Remains Valid for Transaction Execution

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

### [L-1] Ghost Signers in `s_signers` list lead to permanent Multi-Sig Wallet Lock
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