// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { ERC7579ExecutorBase } from "@rhinestone/modulekit/src/Modules.sol";
import { IERC7579Account } from "erc7579/interfaces/IERC7579Account.sol";
import { IModule } from "erc7579/interfaces/IERC7579Module.sol";
import { ISafe } from "../interfaces/ISafe.sol";
import { IEmailRecoveryModule } from "../interfaces/IEmailRecoveryModule.sol";
import { EmailRecoveryManager } from "../EmailRecoveryManager.sol";
import { GuardianManager } from "../GuardianManager.sol";

/**
 * @title EmailRecoveryModule
 * @notice This contract provides a simple mechanism for recovering account validators by
 * permissioning certain functions to be called on validators. It facilitates recovery by
 * integration with the email recovery manager contract. The module defines how a recovery request
 * is executed on a validator, while the recovery manager defines what a valid recovery request is.
 *
 * This recovery module targets a specific validator, so this contract should be deployed per
 * validator
 */
contract EmailRecoveryModule is EmailRecoveryManager, ERC7579ExecutorBase, IEmailRecoveryModule {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    CONSTANTS & STORAGE                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /**
     * Validator being recovered
     */
    address public immutable validator;

    /**
     * function selector that is called when recovering validator
     */
    bytes4 public immutable selector;

    /**
     * Account address to authorized validator
     */
    mapping(address account => bool isAuthorized) internal authorized;

    event RecoveryExecuted(address indexed account, address indexed validator);

    error InvalidSelector(bytes4 selector);
    error InvalidOnInstallData();
    error InvalidValidator(address validator);
    error RecoveryNotAuthorizedForAccount();

    constructor(
        address verifier,
        address dkimRegistry,
        address emailAuthImpl,
        address subjectHandler,
        address _validator,
        bytes4 _selector
    )
        EmailRecoveryManager(verifier, dkimRegistry, emailAuthImpl, subjectHandler)
    {
        if (_validator == address(0)) {
            revert InvalidValidator(_validator);
        }
        if (
            _selector == IModule.onUninstall.selector || _selector == IModule.onInstall.selector
                || _selector == IERC7579Account.execute.selector
                || _selector == ISafe.setFallbackHandler.selector
                || _selector == ISafe.setGuard.selector || _selector == bytes4(0)
        ) {
            revert InvalidSelector(_selector);
        }

        validator = _validator;
        selector = _selector;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          CONFIG                            */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /**
     * Initializes the module with the threshold and guardians
     * @dev You cannot install this module during account deployment as it breaks the 4337
     * validation rules. ERC7579 does not mandate that executors abide by the validation rules
     * during account setup  - if required, install this module after the account has been setup. The
     * data is encoded as follows: abi.encode(isInstalledContext, guardians, weights, threshold,
     * delay, expiry)
     * @param data encoded data for recovery configuration
     */
    function onInstall(bytes calldata data) external {
        if (data.length == 0) revert InvalidOnInstallData();
        (
            bytes memory isInstalledContext,
            address[] memory guardians,
            uint256[] memory weights,
            uint256 threshold,
            uint256 delay,
            uint256 expiry
        ) = abi.decode(data, (bytes, address[], uint256[], uint256, uint256, uint256));

        if (
            !IERC7579Account(msg.sender).isModuleInstalled(
                TYPE_VALIDATOR, validator, isInstalledContext
            )
        ) {
            revert InvalidValidator(validator);
        }
        authorized[msg.sender] = true;

        configureRecovery(guardians, weights, threshold, delay, expiry);
    }

    /**
     * Handles the uninstallation of the module and clears the recovery configuration
     * @dev the data parameter is not used
     */
    function onUninstall(bytes calldata /* data */ ) external {
        authorized[msg.sender] = false;
        deInitRecoveryModule(msg.sender);
    }

    /**
     * Check if the module is initialized
     * @param account The smart account to check
     * @return true if the module is initialized, false otherwise
     */
    function isInitialized(address account) external view returns (bool) {
        return getGuardianConfig(account).threshold != 0;
    }

    /**
     * Check if the recovery module is authorized to recover the account
     * @param account The smart account to check
     * @return true if the module is authorized, false otherwise
     */
    function isAuthorizedToBeRecovered(address account) external view returns (bool) {
        return authorized[account];
    }

    /**
     * Check if a recovery request can be initiated based on guardian acceptance
     * @param account The smart account to check
     * @return true if the recovery request can be started, false otherwise
     */
    function canStartRecoveryRequest(address account) external view returns (bool) {
        GuardianConfig memory guardianConfig = getGuardianConfig(account);

        return guardianConfig.acceptedWeight >= guardianConfig.threshold;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                        MODULE LOGIC                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /**
     * @notice Executes recovery on a validator. Called from the recovery manager
     * @param account The account to execute recovery for
     * @param recoveryCalldata The recovery calldata that should be executed on the validator
     * being recovered
     */
    function recover(address account, bytes calldata recoveryCalldata) internal override {
        if (!authorized[account]) {
            revert RecoveryNotAuthorizedForAccount();
        }

        bytes4 calldataSelector = bytes4(recoveryCalldata[:4]);
        if (calldataSelector != selector) {
            revert InvalidSelector(calldataSelector);
        }

        _execute({ account: account, to: validator, value: 0, data: recoveryCalldata });

        emit RecoveryExecuted(account, validator);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         METADATA                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /**
     * Returns the name of the module
     * @return name of the module
     */
    function name() external pure returns (string memory) {
        return "ZKEmail.EmailRecoveryModule";
    }

    /**
     * Returns the version of the module
     * @return version of the module
     */
    function version() external pure returns (string memory) {
        return "0.0.1";
    }

    /**
     * Returns the type of the module
     * @param typeID type of the module
     * @return true if the type is a module type, false otherwise
     */
    function isModuleType(uint256 typeID) external pure returns (bool) {
        return typeID == TYPE_EXECUTOR;
    }
}
