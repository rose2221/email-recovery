//SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { EmailAccountRecovery } from
    "@zk-email/ether-email-auth-contracts/src/EmailAccountRecovery.sol";
import {ISimpleRecoveryToolManager} from "./ISimpleRecoveryTool.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import "email-recovery/node_modules/.pnpm/@zk-email+ether-email-auth-contracts@1.0.2/node_modules/@zk-email/ether-email-auth-contracts/src/EmailAuth.sol";
import {SimpleGuardianManager} from "./SimpleGuardianManager.sol";
import { GuardianStorage, GuardianStatus } from "./libraries/EnumerableGuardianMap.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@zk-email/ether-email-auth-contracts/src/libraries/StringUtils.sol";
// import "./SimpleRecoveryToolinstaller.sol";
/**
 * @title ModularRecovery
 * @notice A simplified recovery module for ERC7579 accounts supporting multiple verification methods
 */
abstract contract ModularRecoveryManager is EmailAccountRecovery, Ownable,  SimpleGuardianManager , ISimpleRecoveryToolManager {
  using EnumerableSet for EnumerableSet.AddressSet;
  uint256 public constant MINIMUM_RECOVERY_WINDOW = 2 days;
  uint256 public immutable minimumDelay;

    address public immutable commandHandler;
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
  bool public killSwitchEnabled;
  mapping(address account => RecoveryConfig recoveryConfig) internal recoveryConfigs;
  mapping(address account => RecoveryRequest recoveryRequest) internal recoveryRequests;
// bytes4 public immutable selector;
  constructor(
    address _verifier,
    address _dkimRegistry,
       address _commandHandler,
    address _emailAuthImpl,
    uint256 _minimumDelay,
     address _killSwitchAuthorizer
      ) 
      Ownable(_killSwitchAuthorizer)
      {
        if (_verifier == address(0)) {
            revert InvalidVerifier();

        }
        if (_emailAuthImpl == address(0)) {
            revert InvalidEmailAuthImpl();
        }
        if (_dkimRegistry == address(0)) {
            revert InvalidDKIMRegistry();
        }
           if (_commandHandler == address(0)) {
            revert InvalidCommandHandler();
        }
        if (_killSwitchAuthorizer == address(0)) {
            revert InvalidKillSwitchAuthorizer();
        }
        verifierAddr = _verifier;
   dkimAddr = _dkimRegistry;
        emailAuthImplementationAddr = _emailAuthImpl;
        commandHandler = _commandHandler;
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

function hasGuardianVoted(address account, address guardian) public view returns (bool){
        return recoveryRequests[account].guardianVoted.contains(guardian);
     }
function configureRecovery(
    address[] memory guardians,
    uint256[] memory weights,
     GuardianType[] memory guardianTypes,
    uint256 threshold,
    uint256 delay,
    uint256 expiry
) internal {
    address account = msg.sender;

    if(guardianConfigs[account].threshold > 0){
        revert SetupAlreadyCalled();

    }
    (uint256 guardianCount, uint256 totalWeight) = setupGuardians(account, guardians, weights, guardianTypes, threshold);
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
function processRecovery(address guardian, uint256 templateIdx, bytes[] memory commandParams, bytes32 ) internal override {
if(templateIdx != 0){
    revert InvalidTemplateIndex(templateIdx, 0);
}
if (commandParams.length != 1){
    revert InvalidCommandParams(commandParams.length, 1);
}
address account = abi.decode(commandParams[0], (address));
    if(!isActivated(account)) {
        revert RecoveryIsNotActivated();
    }
    GuardianConfig memory guardianConfig = guardianConfigs[account];
    if (guardianConfig.threshold > guardianConfig.acceptedWeight){
        revert ThresholdExceedsAcceptedWeight(guardianConfig.threshold, guardianConfig.acceptedWeight);
    }

    GuardianStorage memory guardianStorage = getGuardian(account, guardian);
    if(guardianStorage.status != GuardianStatus.ACCEPTED){
        revert InvalidGuardianStatus();
    }
    RecoveryRequest storage recoveryRequest = recoveryRequests[account];
    bytes32 recoveryDataHash = StringUtils.hexToBytes32(abi.decode(commandParams[1],(string)));
    if(hasGuardianVoted(account, guardian)){
        revert GuardianAlreadyVoted();
    }
    if (recoveryRequest.recoveryDataHash == bytes32(0)){
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
function completeRecovery(
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
 bytes32 recoveryDataHash = keccak256(recoveryData);
        if (recoveryDataHash != recoveryRequest.recoveryDataHash) {
            revert InvalidRecoveryDataHash();
        }

exitandclearRecovery(account);
recover(account, recoveryData);
emit RecoveryCompleted(account);
    }
  /**
     * @notice Called during completeRecovery to finalize recovery. Contains implementation-specific
     * logic to recover an account
     * @dev this is the only function that must be implemented by consuming contracts to use the
     * email recovery manager. This does not encompass other important logic such as module
     * installation, that logic is specific to each implementation and must be implemeted separately
     * @param account The address of the account for which the recovery is being completed
     * @param recoveryData The data that is passed to recover the validator or account.
     * recoveryData = abi.encode(validatorOrAccount, recoveryFunctionCalldata). Although, it is
     * possible to design an account/module using this manager without encoding the validator or
     * account, depending on how the `handler.parseRecoveryDataHash()` and `recover()` functions
     * are implemented
     */
    function recover(address account, bytes calldata recoveryData) internal virtual;

 

    function exitandclearRecovery(address account) public {
        if(recoveryRequests[msg.sender].currentWeight == 0){
            revert NoRecoveryInProcess();
        }
        RecoveryRequest storage recoveryRequest = recoveryRequests[account];
       address[] memory guardiansVoted = recoveryRequest.guardianVoted.values();
        uint256 voteCount = guardiansVoted.length;
        for (uint256 i= 0; i< voteCount; i++){
            recoveryRequest.guardianVoted.remove(guardiansVoted[i]);

        }
        delete recoveryRequests[account];
      emit RecoveryCancelled(account);
    }
// function hexToBytes32(string memory source) internal pure returns (bytes32 result) {
//     bytes memory tempBytes = bytes(source);
//     if (tempBytes.length == 0) {
//         revert("Empty string");
//     }
//     require(tempBytes.length <= 32, "String too long");
//     assembly {
//         result := mload(add(source, 32))
//     }
// }

 function handleAcceptanceV2(EmailAuthMsg memory emailAuthMsg, uint templateIdx,  bytes memory signature) external{
 address recoveredAccount = extractRecoveredAccountFromAcceptanceCommand(
            emailAuthMsg.commandParams,
            templateIdx
        );
        require(recoveredAccount != address(0), "invalid account in email");
  bool isEOAGuardian    = emailAuthMsg.proof.accountSalt == bytes32(0);
  address guardian;
  if(isEOAGuardian){
     // For EOA-based guardian, directly use the signer address
     
    //  require(guardian != address(0), "invalid guardian address");

         // EOA Verification: Ensure the message is signed correctly by the guardian
         bytes32 messageHash = keccak256(abi.encode(recoveredAccount, templateIdx, emailAuthMsg.commandParams));
       guardian = recoverSigner(messageHash, signature);
        require(guardian != address(0), "invalid guardian address");

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
   updateGuardianStatus(recoveredAccount, guardian, GuardianStatus.ACCEPTED);
        guardianConfigs[recoveredAccount].acceptedWeight += guardiansStorage.weight;

        emit GuardianAccepted(recoveredAccount, guardian);
 }
 /**
 * @notice Recovers the signer of a message using ECDSA.
 * @param messageHash The hash of the message signed by the EOA guardian.
 * @param signature The signature produced by the EOA guardian.
 * @return The address of the signer.
 */
function recoverSigner(bytes32 messageHash, bytes memory  signature) internal pure  returns(address){
bytes32 ethSignesMessageHash = keccak256(abi.encodedPacked("\x19Ethereum Signed Message:\n32", messageHash));
(bytes32 r, bytes32 s, uint8 v)= splitSignature(signature);
return ecrecover(ethSignesMessageHash, v, r, s);

}
/**
 * @notice Splits an ECDSA signature into its components (r, s, v).
 * @param sig The full signature.
 * @return r The r component of the signature.
 * @return s The s component of the signature.
 * @return v The v component of the signature.
 */
function splitSignature(bytes memory sig) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
    require(sig.length == 65, "invalid signature length");
    assembly {
        r := mload(add(sig, 0x20))
        s := mload(add(sig, 0x40))
        v := byte(0, mload(add(sig, 0x60)))
    }



}
  /// @notice Processes the recovery based on an email from the guardian.
    /// @dev Verify the provided email auth message for a deployed guardian's EmailAuth contract and a specific command template for recovery.
    /// Requires that the guardian is already deployed, and the template ID corresponds to the `templateId` in the given email auth message. Once validated.
    /// @param emailAuthMsg The email auth message for recovery.
    /// @param templateIdx The index of the command template for recovery, which should match with the command in the given email auth message.
    function handleRecovery(
        EmailAuthMsg memory emailAuthMsg,
        uint templateIdx
    ) external {
        address recoveredAccount = extractRecoveredAccountFromRecoveryCommand(
            emailAuthMsg.commandParams,
            templateIdx
        );
        require(recoveredAccount != address(0), "invalid account in email");
        address guardian;
        bool isEOAGuardian    = emailAuthMsg.proof.accountSalt == bytes32(0);
        if(isEOAGuardian){
            guardian = verifyEOAGuardian(emailAuthMsg.Proof);
        }
        else{

        guardian = computeEmailAuthAddress(
            recoveredAccount,
            emailAuthMsg.proof.accountSalt
        );

        // Check if the guardian is deployed
        require(address(guardian).code.length > 0, "guardian is not deployed");
        }
        uint templateId = uint256(
            keccak256(
                abi.encode(
                    EMAIL_ACCOUNT_RECOVERY_VERSION_ID,
                    "RECOVERY",
                    templateIdx
                )
            )
        );
        require(templateId == emailAuthMsg.templateId, "invalid template id");
if(!isEOAGuardian){
        EmailAuth guardianEmailAuth = EmailAuth(payable(address(guardian)));

        // An assertion to confirm that the authEmail function is executed successfully
        // and does not return an error.
        guardianEmailAuth.authEmail(emailAuthMsg);
}

        processRecovery(
            guardian,
            templateIdx,
            emailAuthMsg.commandParams,
            emailAuthMsg.proof.emailNullifier
        );
    }

    function verifyEOAGuardian(EmailProof memory proof)internal view returns (address){
        bytes32 hash = keccak256(abi.encode(proof.accountSalt, EMAIL_ACCOUNT_RECOVERY_VERSION_ID)
    ).toEthSignedMessageHash();
    // Recover signer address
    address signer = ECDSA.recover(hash, proof.signature);

    // Ensure the signer is an EOA
    require(signer.code.length == 0, "guardian must be an EOA");

    return signer;
    }
}