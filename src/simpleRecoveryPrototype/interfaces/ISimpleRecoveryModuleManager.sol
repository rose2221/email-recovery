// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { EnumerableSet } from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

interface ISimpleRecoveryModuleManager {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                     TYPE DECLARATIONS                      */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /**
     * A struct representing the values required for recovery configuration.
     * Config should be maintained over subsequent recovery attempts unless explicitly modified.
     */
    struct RecoveryConfig {
        uint256 delay; // the time from when the threshold for a recovery request has passed (when
        // the attempt is successful), until the recovery request can be executed. The delay can
        // be used to give the account owner time to react in case a malicious recovery
        // attempt is started by a guardian.
        uint256 expiry; // the time from when a recovery request is started until the recovery
        // request becomes invalid. The recovery expiry encourages the timely execution of
        // successful recovery attempts and reduces the risk of unauthorized access through
        // stale or outdated requests. After the recovery expiry has passed, anyone can cancel
        // the recovery request.
    }

    /**
     * A struct representing the values required for a recovery request.
     * The request state should be maintained over a single recovery attempt unless
     * explicitly modified. It should be deleted after a recovery attempt has been processed.
     */
    struct RecoveryRequest {
        uint256 executeAfter; // the timestamp from which the recovery request can be executed.
        uint256 executeBefore; // the timestamp from which the recovery request becomes invalid.
        uint256 currentWeight; // total weight of all guardian approvals for the recovery request.
        bytes32 recoveryDataHash; // the keccak256 hash of the recovery data used to execute the
        // recovery attempt.
        EnumerableSet.AddressSet guardianVoted; // the set of guardians who have voted for the
        // recovery request. Must be looped through manually to delete each value.
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                           EVENTS                            */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    event RecoveryConfigured(
        address indexed account, 
        uint256 guardianCount, 
        uint256 totalWeight, 
        uint256 threshold
    );

    event GuardianAccepted(address indexed account, address indexed guardian);
    event RecoveryRequestStarted(
        address indexed account, 
        address indexed guardian, 
        uint256 executeBefore, 
        bytes32 recoveryDataHash
    );

    event GuardianVoted(address indexed account, address indexed guardian);
    event RecoveryRequestComplete(
        address indexed account, 
        address indexed guardian, 
        uint256 executeAfter, 
        uint256 executeBefore, 
        bytes32 recoveryDataHash
    );

    event RecoveryCompleted(address indexed account);
    event RecoveryCancelled(address indexed account);
    event RecoveryDeInitialized(address indexed account);
    event RecoveryExecuted(address indexed account, address indexed validator);

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                           ERRORS                            */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    error InvalidVerifier();
    error InvalidEmailAuthImpl();
    error InvalidDKIMRegistry();
    error SetupAlreadyCalled();
    error InvalidCommandHandler();
    error InvalidKillSwitchAuthorizer();
    error DelayLessThanMinimumDelay(uint256 delay, uint256 minimumDelay);
    error DelayMoreThanExpiry(uint256 delay, uint256 expiry);
    error RecoveryWindowTooShort(uint256 recoveryWindow);
    error NoRecoveryInProcess();
    error RecoveryIsNotActivated();
    error InvalidTemplateIndex(uint256 templateIdx, uint256 expectedTemplateIdx);
    error InvalidCommadparams(uint256 paramsLength, uint256 expectedParamsLength);
    error InvalidGuardianStatus();
    error GuardianAlreadyVoted();
    error InvalidRecoveryDataHash();
    error InvalidAccountAddress();
    error NoRecoveryConfigured();
    error NotEnoughApprovals();
    error RecoveryRequestExpired();
    error InvalidSelector();
    error AccountNotConfigured();
    error DelayNotPassed(uint256 blockTimestamp, uint256 executeAfter);
    error RecoveryHasNotExpired(address account, uint256 blockTimestamp, uint256 executeBefore);

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          FUNCTIONS                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function killSwitchEnabled() external returns (bool);

    function getRecoveryConfig(address account) external view returns (RecoveryConfig memory);

    function getRecoveryRequest(
        address account
    )
        external
        view
        returns (
            uint256 executeAfter,
            uint256 executeBefore,
            uint256 currentWeight,
            bytes32 recoveryDataHash
        );

    function hasGuardianVoted(address account, address guardian) external view returns (bool);

    function exitandclearRecovery(address account) external;
}
