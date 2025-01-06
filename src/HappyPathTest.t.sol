// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;
import {ISimpleGuardianManager} from "./ISimpleGuardianManager.sol";
import "forge-std/console.sol";
import { BaseTest } from "./SimpleRecoveryBast.t.sol";
import { EmailAuthMsg, EmailProof } from "@zk-email/ether-email-auth-contracts/src/EmailAuth.sol";
// abstract contract SimpleRecoveryModuleTest is BaseTest {function testHappyPathRecoveryWithVerifierAndDKIM() public {
//     // **Step 1:** Configure recovery for `account1`
//     address;
//     uint256;
//     ISimpleGuardianManager.GuardianType;

//    guardians[0] = eoaGuardian1; // EOA Guardian 1
//     guardians[1] = eoaGuardian2; // EOA Guardian 2
//     guardians[2] = emailGuardian1; // Email Verified Guardian

//     weights[0] = 1; // Weight for EOA Guardian 1
//     weights[1] = 1; // Weight for EOA Guardian 2
//     weights[2] = 1; // Weight for Email Verified Guardian

//     guardianTypes[0] = ISimpleGuardianManager.GuardianType.EOA; // Type: EOA
//     guardianTypes[1] = ISimpleGuardianManager.GuardianType.EOA; // Type: EOA
//     guardianTypes[2] = ISimpleGuardianManager.GuardianType.EmailVerified; // Type: Email Verified

//     uint256 recoveryThreshold = 2; // Require 2 out of 3 approvals
//     uint256 recoveryDelay = 1 days;
//     uint256 recoveryExpiry = 7 days;

//     vm.startPrank(owner1); // Simulate as the account owner
//     recoveryModule.configureRecovery(
//         guardians,
//         weights,
//         guardianTypes,
//         recoveryThreshold,
//         recoveryDelay,
//         recoveryExpiry
//     );
//     vm.stopPrank();

//     // **Step 2:** Prepare recovery data (new owner)
//     bytes memory recoveryCalldata = abi.encodeWithSelector(
//         recoveryModule.selector(),
//         newOwner
//     );
//     bytes memory recoveryData = abi.encode(
//         accountAddress1,
//         recoveryCalldata
//     );

//     // **Step 3:** Approve recovery by EOA Guardian 1
//     bytes32 messageHash = keccak256(abi.encode(accountAddress1, 0, recoveryCalldata));
//     bytes memory eoaSignature = signEOAGuardian(messageHash, eoaGuardian1);
//     vm.prank(eoaGuardian1);
//     recoveryModule.processRecovery(eoaGuardian1, 0, recoveryCalldata, bytes32(0));
//     //  if (getCommandHandlerType() == CommandHandlerType.SafeRecoveryCommandHandler) {
//     //         string memory accountString = CommandUtils.addressToChecksumHexString(account);
//     //         string memory oldOwnerString = CommandUtils.addressToChecksumHexString(owner1);
//     //         string memory newOwnerString = CommandUtils.addressToChecksumHexString(newOwner1);
//     //         command = string.concat(
//     //             "Recover account ",
//     //             accountString,
//     //             " from old owner ",
//     //             oldOwnerString,
//     //             " to new owner ",
//     //             newOwnerString
//     //         );

//     //         commandParamsForRecovery = new bytes[](3);
//     //         commandParamsForRecovery[0] = abi.encode(accountAddress1);
//     //         commandParamsForRecovery[1] = abi.encode(owner1);
//     //         commandParamsForRecovery[2] = abi.encode(newOwner1);
//     //     }
//         bytes32 nullifier = generateNewNullifier();
//     // **Step 4:** Email guardian provides a valid ZKP proof (with DKIM validation)
//        EmailProof memory validProof = generateMockEmailProof(command, nullifier, accountSalt1);
//     dkimRegistry.setDKIMPublicKeyHash("gmail.com", PUBLIC_KEY_HASH, zkEmailDeployer, new bytes(0));

//     EmailProof memory proof = EmailProof({
//         accountSalt: accountSalt1,
//         proof: validProof,
//         emailNullifier: bytes32(0)
//     });

//     EmailAuthMsg memory emailAuthMsg = EmailAuthMsg({
//         templateId: uint256(keccak256(abi.encode("RECOVERY_TEMPLATE"))),
//         commandParams: abi.encode(accountAddress1),
//         proof: proof
//     });

//     vm.prank(emailGuardian1);
//     recoveryModule.handleAcceptanceV2(emailAuthMsg, 0, eoaSignature);

//     // **Step 5:** Fast-forward time and complete the recovery
//     vm.warp(block.timestamp + 2 days);
//     vm.prank(newOwner);
//     recoveryModule.completeRecovery(accountAddress1, recoveryData);

//     // **Step 6:** Verify ownership transfer
//     assertEq((accountAddress1).owner(), newOwner, "Ownership not transferred to new owner");
// }


// function signEOAGuardian(bytes32 messageHash, address signer) internal view returns (bytes memory) {
//     // Simulate signing using EOA private key (mock signature logic)
//     (uint8 v, bytes32 r, bytes32 s) = vm.sign(uint256(uint160(signer)), messageHash);
//     return abi.encodePacked(r, s, v);
// }
//   function generateNewNullifier() public returns (bytes32) {
//         return keccak256(abi.encode(nullifierCount++));
//     }
// }


    contract RecoveryTest is BaseTest {
        function setUp() public override {
              bytes memory isInstalledContext = "";  // Empty context or set as needed
    bytes memory data = abi.encode(
        isInstalledContext,  // Context
        guardians,           // Guardian addresses
        weights,             // Guardian weights
        guardianTypes,       // Guardian types (EOA or EmailVerified)
        threshold,           // Threshold for recovery
        delay,               // Delay for recovery
        expiry               // Expiry for recovery
    );

    // Prank to simulate the call from accountAddress1
    vm.prank(accountAddress1);
    recoveryModule.onInstall(data);
        }

        function testFullRecoveryProcess() public {
            // 1. EOA Guardian 1 casts their vote
            bytes memory recoverySignature1 = signRecoveryData(eoaGuardian1, recoveryData);
            vm.prank(eoaGuardian1);
            recoveryModule.testProcessRecovery(eoaGuardian1, 0, encodeCommandParams());

            // 2. Email Guardian casts their vote (emailAuth verification)
            EmailProof memory emailProof = generateMockEmailProof("RECOVER", recoveryDataHash, accountSalt1);
          EmailAuthMsg memory emailAuthMsg = EmailAuthMsg({
    templateId: uint256(keccak256(abi.encode("ACCEPTANCE"))),
    commandParams: encodeCommandParams(),
    skippedCommandPrefix: 0,  // Use the appropriate value for the prefix
    proof: emailProof
});
            bytes memory emailSignature = abi.encodePacked("fake_email_signature");

            vm.prank(emailGuardian1);
            recoveryModule.handleAcceptanceV2(emailAuthMsg, 0, emailSignature);

            // Assert that the guardians' approvals reached the threshold
            (, , uint256 currentWeight, ) = recoveryModule.getRecoveryRequest(accountAddress1);
            assertEq(currentWeight, 2, "Threshold weight not reached");

            // 3. Complete recovery after the delay period
            skip(delay + 1);  // Fast-forward time to simulate delay passing
            vm.prank(address(0x123));  // Any external address can trigger the completion
            recoveryModule.completeRecovery(accountAddress1, recoveryData);

            // Assert that the account was recovered to `newOwner`
            address newOwnerAccount = validator.owners(accountAddress1);
            assertEq(newOwnerAccount, newOwner, "Recovery did not set the new owner correctly");

            emit log("Recovery completed successfully");
        }

        /// Helper function to sign recovery data for EOAs
        function signRecoveryData(address signer, bytes memory data) internal returns (bytes memory) {
            bytes32 messageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(data)));
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(uint256(uint160(signer)), messageHash);
            return abi.encodePacked(r, s, v);
        }

        /// Helper function to encode the commandParams for processRecovery
        function encodeCommandParams() internal pure returns (bytes[] memory) {
            bytes[] memory commandParams;
            commandParams[0] = abi.encode("account1");
            commandParams[1] = abi.encode("validator_recovery");
            return commandParams;
        }
    }
