// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

// import "forge-std/console2.sol";
// import { ModuleKitHelpers, ModuleKitUserOp } from "modulekit/ModuleKit.sol";
// import { MODULE_TYPE_EXECUTOR, MODULE_TYPE_VALIDATOR } from "modulekit/external/ERC7579.sol";

// import { IEmailRecoveryManager } from "src/interfaces/IEmailRecoveryManager.sol";
// import { EmailRecoveryModule } from "src/modules/EmailRecoveryModule.sol";
// import { OwnableValidator } from "src/test/OwnableValidator.sol";
// import { GuardianStorage, GuardianStatus } from "src/libraries/EnumerableGuardianMap.sol";
// import { UnitBase } from "../UnitBase.t.sol";

// contract ZkEmailRecovery_validateRecoverySubjectTemplates_Test is UnitBase {
//     using ModuleKitHelpers for *;
//     using ModuleKitUserOp for *;

//     OwnableValidator validator;
//     EmailRecoveryModule recoveryModule;
//     address recoveryModuleAddress;

//     function setUp() public override {
//         super.setUp();

//         validator = new OwnableValidator();
//         recoveryModule =
//             new EmailRecoveryModule{ salt: "test salt"
// }(address(emailRecoveryManager));
//         recoveryModuleAddress = address(recoveryModule);

//         instance.installModule({
//             moduleTypeId: MODULE_TYPE_VALIDATOR,
//             module: address(validator),
//             data: abi.encode(owner, recoveryModuleAddress)
//         });
//         // Install recovery module - configureRecovery is called on `onInstall`
//         instance.installModule({
//             moduleTypeId: MODULE_TYPE_EXECUTOR,
//             module: recoveryModuleAddress,
//             data: abi.encode(address(validator), guardians, guardianWeights, threshold, delay,
// expiry)
//         });
//     }

//     function test_ValidateRecoverySubjectTemplates_RevertWhen_InvalidTemplateIndex() public {
//         uint256 invalidTemplateIdx = 1;

//         bytes[] memory subjectParams = new bytes[](3);
//         subjectParams[0] = abi.encode(accountAddress);
//         subjectParams[1] = abi.encode(newOwner);
//         subjectParams[2] = abi.encode(recoveryModuleAddress);

//         vm.expectRevert(IEmailRecoveryManager.InvalidTemplateIndex.selector);
//         emailRecoveryManager.exposed_validateRecoverySubjectTemplates(invalidTemplateIdx,
// subjectParams);
//     }

//     function test_ValidateAcceptanceSubjectTemplates_RevertWhen_NoSubjectParams() public {
//         bytes[] memory emptySubjectParams;

//         vm.expectRevert(IEmailRecoveryManager.InvalidSubjectParams.selector);
//         emailRecoveryManager.exposed_validateRecoverySubjectTemplates(templateIdx,
// emptySubjectParams);
//     }

//     function test_ValidateAcceptanceSubjectTemplates_RevertWhen_TooManySubjectParams() public {
//         bytes[] memory subjectParams = new bytes[](4);
//         subjectParams[0] = abi.encode(accountAddress);
//         subjectParams[1] = abi.encode(newOwner);
//         subjectParams[2] = abi.encode(recoveryModuleAddress);
//         subjectParams[3] = abi.encode("extra param");

//         vm.expectRevert(IEmailRecoveryManager.InvalidSubjectParams.selector);
//         emailRecoveryManager.exposed_validateRecoverySubjectTemplates(templateIdx,
// subjectParams);
//     }

//     function test_ProcessRecovery_RevertWhen_InvalidNewOwner() public {
//         bytes[] memory subjectParams = new bytes[](3);
//         subjectParams[0] = abi.encode(accountAddress);
//         subjectParams[1] = abi.encode(address(0));
//         subjectParams[2] = abi.encode(recoveryModuleAddress);

//         vm.expectRevert(IEmailRecoveryManager.InvalidNewOwner.selector);
//         emailRecoveryManager.exposed_validateRecoverySubjectTemplates(templateIdx,
// subjectParams);
//     }

//     function test_ProcessRecovery_RevertWhen_RecoveryModuleAddressIsZero() public {
//         bytes[] memory subjectParams = new bytes[](3);
//         subjectParams[0] = abi.encode(accountAddress);
//         subjectParams[1] = abi.encode(newOwner);
//         subjectParams[2] = abi.encode(address(0));

//         vm.expectRevert(IEmailRecoveryManager.InvalidRecoveryModule.selector);
//         emailRecoveryManager.exposed_validateRecoverySubjectTemplates(templateIdx,
// subjectParams);
//     }

//     function test_ProcessRecovery_RevertWhen_RecoveryModuleNotEqualToExpectedAddress() public {
//         bytes[] memory subjectParams = new bytes[](3);
//         subjectParams[0] = abi.encode(address(1));
//         subjectParams[1] = abi.encode(newOwner);
//         subjectParams[2] = abi.encode(recoveryModuleAddress); // recovery module is valid, but
// not
//             // for the owner passed in

//         vm.expectRevert(IEmailRecoveryManager.InvalidRecoveryModule.selector);
//         emailRecoveryManager.exposed_validateRecoverySubjectTemplates(templateIdx,
// subjectParams);
//     }

//     function test_ProcessRecovery_Succeeds() public {
//         bytes[] memory subjectParams = new bytes[](3);
//         subjectParams[0] = abi.encode(accountAddress);
//         subjectParams[1] = abi.encode(newOwner);
//         subjectParams[2] = abi.encode(recoveryModuleAddress);

//         address account =
//             emailRecoveryManager.exposed_validateRecoverySubjectTemplates(templateIdx,
// subjectParams);
//         assertEq(account, accountAddress);
//     }
// }
