//SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { EmailAccountRecovery } from
    "@zk-email/ether-email-auth-contracts/src/EmailAccountRecovery.sol";

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import { ERC7579ExecutorBase } from "@rhinestone/modulekit/src/Modules.sol";

/**
 * @title ModularRecovery
 * @notice A simplified recovery module for ERC7579 accounts supporting multiple verification methods
 */
contract ModularRecoveryManager is EmailAccountRecovery, Ownable{
  using EnumerableSet for EnumerableSet.AddressSet;
  uint256 public constant MINIMUM_RECOVERY_WINDOW = 2 days;
  uint256 public immutable minimumDelay;

  uint public constant CANCEL_EXPIRED_RECOVERY_COOLDOWN = 1 days;

//   struct RecoveryConfig {
//     uint256 delay;
//     uint256 expiry;
//   }

//   struct RecoveryRequest {
//     uint256 executeAfter;
//     uint256 executeBefore;
//     uint256 currentWeight;
//     bytes32 recoveryDataHash;
//     EnumerableSet.AddressSet guardianVoted;
//   }

  mapping(address account => RecoveryConfig recoveryCongif) internal recoveryConfigs;
  mapping(address account => RecoveryRequest recoveryRequest) internal recoveryRequests;

  constructor(
    address _verifier,
    address _dkimregistry,
    address _emailAuthImpl,
    uint256 _minimumDelay
      ) {
        if (_verifier == address(0)) {
            revert InvalidVerifier();

        }
        if (_emailAuthImpl == address(0)) {
            revert InvalidEmailAuthImpl();
        }
        if (_dkimregistry == address(0)) {
            revert InvalidDKIMRegistry();
        }
        verifier = _verifier;

        emailAuthImpl = _emailAuthImpl;
        dkimRegistry = _dkimregistry;
        minimumDelay = _minimumDelay;
      }

//     /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
//     /*                           EVENTS                           */
//     /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

// event RecoveryConfigured(address indexed account, uint256 guardianCount, uint256 totalWeight, uint256 threshold);
// event GuardianAccepted(address indexed account, address indexed guardian);
// event RecoveryRequestStarted(address indexed account, address indexed guardian, uint256 executeBefore, bytes32 recoveryDataHash);
// event GuardianVoted(address indexed account, address indexed guardian);
// event RecoveryRequestComplete(address indexed account, address indexed guardian, uint256 executeAfter, uint256 executeBefore, bytes32 recoveryDataHash);
// event RecoveryCompleted(address indexed account);
// event RecoveryCancelled(address indexed account);
// event RecoveryRequestStarted(address indexed account, address indexed guardian, uint256 executeBefore, bytes32 recoveryDataHash);
// event RecoveryExecuted(address indexed account, address indexed validator);

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                           ERRORS                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/
// error InvalidVerifier();
// error InvalidEmailAuthImpl();
// error InvalidDKIMRegistry();
// error SetupAlreadyCalled();
// error DelayLessThanMinimumDelay(uint256 delay, uint256 minimumDelay);
// error DelayMoreThanExpiry(uint256 delay, uint256 expiry);
// error RecoveryWindowTooShort(uint256 recoveryWindow);
// error NoRecoveryInProcess();
// error RecoveryIsNotActivated();
// error InvalidTemplateIndex(uint256 templateIdx, uint256 expectedTemplateIdx);
// error InvalidCommadparams(uint256 paramsLength, uint256 expectedParamsLength);
// error InvalidGuardianStatus();
// error GuardianAlreadyVoted();
// error InvalidRecoveryDataHash();
// error InvalidAccountAddress();
// error NoRecoveryConfigured();
// error NotEnoughApprovals();
// error RecoveryRequestExpired();
// error InvalidSelector();
// error AccountNotConfigured();


     /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          FUNCTIONS                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

  function getRecoveryConfig(address account) external view returns (RecoveryConfig memory){
    return recoveryConfigs[account];
  }
// need to add accounts to the mapping reocveryconfigs and recoveryRequests
  function getRecoveryRequest(address account) external view returns ( uint256 executeAfter,
    uint256 executeBefore,
    uint256 currentWeight,
    bytes32 recoveryDataHash){
        return (
            recoveryRequests[account].executeAfter,
            recoveryRequests[account].executeBefore,
            recoveryRequests[account].currentWeight,
            recoveryRequests[account].recoveryDataHash
        );
    }

     function hasGuardianVoted(address account, address guardian) external view returns (bool){
        return recoveryRequests[account].guardianVoted.contains(guardian);
     }
function configureRecovery(
    address[] memory guardians,
    uint256[] memory weights,
    uint256 threshold,
    uint256 delay,
    uint256 expiry
) internal {
    address account = msg.sender;

    if(guardianConfigs[account].threshold > 0){
        revert SetupAlreadyCalled();

    }
    (uint256 guardianCount, uint256 totalWeight) = setupGuardians(account, guardians, weights, threshold);
    RecoveryConfig memory recoveryConfig = RecoveryConfig(delay, expiry);
  
    if(guardianConfigs[account].threshold == 0){
        revert AccountNotConfigured();

    }
    if(recoveryConfig.delay <minimumDelay){
        revert DelayLessThanMinimumDelay(recoveryConfig.delay, minimumDelay);
    }
    if(recoveryConfig.expiry < recoveryConfig.delay + MINIMUM_RECOVERY_WINDOW){
        revert RecoveryWindowTooShort(recoveryConfig.expiry - recoveryConfig.delay);
    }
    if(recoveryConfig.delay > recoveryConfig.expiry){
        revert DelayMoreThanExpiry(recoveryConfig.delay, recoveryConfig.expiry);
    }
recoveryConfigs[account] = recoveryConfig;
    emit RecoveryConfigured(account, guardianCount, totalWeight, threshold);


}
// function acceptGuardian
//function getguardian
//i've not added prev config lets see if it shoudl be added or not.
function processRecovery(address guardian, uint256 templateIdx, bytes[] calldata commandParams) internal override {
if(templateIdx != 0){
    revert InvalidTemplateIndex(templateIdx, 0);
}
if (commandParams.length != 1){
    revert InvalidCommandParams(commandParams.length, 1);
}
address accountInEmail = abi.decode(commandParams[0], (address));
    if(!isActivated(account)) {
        revert RecoveryIsNotActivated();
    }
    GuardianConfig memory guardianConfig = guardianConfigs[account];
    if (guardianConfig.threshold > guardianConfig.acceptedWeight){
        revert ThresholdExceedsAcceptedWeight(guardianConfig.threshold, guardianConfig.acceptedWeight);
    }

    GuardianStorage memory guardianStorage = getGuardian(account, guardian);
    if(guardianStorage.status != GuardianStatus.ACCCEPTED){
        revert InvalidGuardianStatus();
    }
    RecoveryRequest storage recoveryRequest = recoveryRequests[account];
    bytes32 reocveryDataHash = StringUtils.hexToBytes32(abi.decide(connadParams[1],(string)));
    if(hasGuardianVoted(account, guardian)){
        revert GuardianAlreadyVoted();
    }
    if (recoveryRequest.reocveryDataHash == bytes32(0)){
        recoveryRequest.recoveryDataHash = recoveryDataHash;
        uint256 executeBefore = block.timestamp + recoveryConfigs[account].expiry;
        recoveryRequest.executeBefore = executeBefore;
        emit RecoveryRequestStarted(account, guardian, executeBefore, recoveryDataHash);
    }
    if(recoveryRequest.recoveryDataHash != recoveryDataHash){
        revert InvalidRecoveryDataHash();
    }
    recoveryRequest.currentWeight += guardianStorage.weight;
    recoveryRequest.guardianVoted.add(guardian);
    emit GuardianVoted(account, guardian);
    if(recoveryRequest.currentWeight >= guardianConfig.threshold){
        uint256 executeAfter = block.timestamp + recoveryConfigs[account].delay;
        recoveryRequest.executeAfter = executeAfter;
        emit RecoveryRequestComplete(account, guardian, executeAfter, recoveryRequest.executeBefore, recoveryDataHash);
    }
}
function recoverycomplte(
    address account, bytes calldata recoveryData) external override {
      if (account == address(0)){
        revert InvalidAccountAddress();

      }
      RecoveryRequest storage recoveryRequest = recoveryRequests[account];
if(guardianConfigs[account].threshold == 0){
    revert NoRecoveryConfigured();
}
if (recoveryRequest.currentWeight <guardianConfigs[account].threshold){
    revert NotEnoughApprovals();
}
if (block.timestamp < recoveryRequest.executeAfter){
    revert DelayNotPassed(block.timestamp, recoveryRequest.executeAfter);
}
if(block.timestamp >= recoveryRequest.executeBefore){
revert RecoveryRequestExpired();}
if (keccak256(recoveryData != recoveryRequest.recoveryDataHash)){
    revert InvalidRecoveryDataHash();}

exitandclearRecovery(account);
recover(account, recoveryData);
emit RecoveryCompleted(account);
    }

    function recover (address account, bytes calldata recoveryData) internal virtual{
        (, bytes memory recoveryCalldata) = abi.decode(recoveryData, (address, bytes));
        bytes4 calldataSelector;
        assembly {
            calldataSelector := mload(add(recoveryCalldata, 32))
        }
        if(calldataSelector != selector){
            revert InvalidSelector();
        }
        _execute({account: account, to: validator, value: 0, data: recoveryCalldata});
        emit RecoveryExecuted(account, validator);
    }

    function exitandclearRecovery(address account) external {
        if(recoveryRequest[msg.sender].currentWeight == 0){
            revert NoRecoveryInProcess();
        }
        RecoveryRequest storage recoveryRequest = recoveryRequests[account];
        // address[] memory guardiansVoted = recoveryRequest.guardianVoted.values();
        uint256 voteCount = recoveryRequest.guardianVoted.values().length;
        for (uint256 i= 0; i< voteCount; i++){
            recoveryRequest.guardianVoted.remove(guardiansVoted[i]);

        }
        delete recoveryRequests[account];
      emit RecoveryCancelled(account);
    }

 function handleAcceptanceV2(EmailAuthMsg memory emailAuthMsg, uint templateIdx) external{
 address recoveredAccount = extractRecoveredAccountFromAcceptanceCommand(
            emailAuthMsg.commandParams,
            templateIdx
        );
        require(recoveredAccount != address(0), "invalid account in email");
  bool isEOAGuardian    = emailAuthMsg.proof.accountSalt == bytes32(0);
  address guardian;
  if(isEOAGuardian){
     // For EOA-based guardian, directly use the signer address
     guardian = emailAuthMsg.proof.signer;
     require(guardian != address(0), "invalid guardian address");

         // EOA Verification: Ensure the message is signed correctly by the guardian
         bytes32 messagehash = keccak256(abi.encode(recoverAcccount, templateIdx, emailAuthmsg.commandParams));
         require(
            recoverSigner(messageHash, emailAuthMsg.proof.signature) == guardian,
            "inavalid EOA signature"
         );

  }
  else {
 guardian = computeEmailAuthAddress(
            recoveredAccount,
            emailAuthMsg.proof.accountSalt
        );
            uint templateId = computeAcceptanceTemplateId(templateIdx);
        require(templateId == emailAuthMsg.templateId, "invalid template id");
        require(emailAuthMsg.proof.isCodeExist == true, "isCodeExist is false");

        EmailAuth guardianEmailAuth;
        if (guardian.code.length == 0) {
            address proxyAddress = deployEmailAuthProxy(
                recoveredAccount,
                emailAuthMsg.proof.accountSalt
            );
            guardianEmailAuth = EmailAuth(proxyAddress);
            guardianEmailAuth.initDKIMRegistry(dkim());
            guardianEmailAuth.initVerifier(verifier());
            for (
                uint idx = 0;
                idx < acceptanceCommandTemplates().length;
                idx++
            ) {
                guardianEmailAuth.insertCommandTemplate(
                    computeAcceptanceTemplateId(idx),
                    acceptanceCommandTemplates()[idx]
                );
            }
            for (uint idx = 0; idx < recoveryCommandTemplates().length; idx++) {
                guardianEmailAuth.insertCommandTemplate(
                    computeRecoveryTemplateId(idx),
                    recoveryCommandTemplates()[idx]
                );
            }
        } else {
            guardianEmailAuth = EmailAuth(payable(address(guardian)));
            require(
                guardianEmailAuth.controller() == address(this),
                "invalid controller"
            );
        }
             // An assertion to confirm that the authEmail function is executed successfully
        // and does not return an error.
        guardianEmailAuth.authEmail(emailAuthMsg);
  }
    acceptGuardian(
            guardian,
            templateIdx,
            emailAuthMsg.commandParams,
            emailAuthMsg.proof.emailNullifier
        );
 }




}