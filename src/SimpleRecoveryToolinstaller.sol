// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { ERC7579ExecutorBase } from "@rhinestone/modulekit/src/Modules.sol";
import { IERC7579Account } from "erc7579/interfaces/IERC7579Account.sol";
import { ISimpleRecoveryToolManager } from "./ISimpleRecoveryTool.sol";
import { ModularRecoveryManager} from "./SimpleRecoveryTool.sol";
import { IEmailRecoveryModule } from "./interfaces/IEmailRecoveryModule.sol";
import { ISimpleGuardianManager } from "./ISimpleGuardianManager.sol";


 contract  SimpleRecoveryModule is  ModularRecoveryManager, ERC7579ExecutorBase, IEmailRecoveryModule {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    CONSTANTS & STORAGE                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

 
 address public immutable validator;
    /**
     * function selector that is called when recovering validator
     */
    bytes4 public immutable selector;

    // event RecoveryExecuted(address indexed account, address indexed validator);

    // error InvalidSelector(bytes4 selector);
    error InvalidOnInstallData();
    error InvalidValidator(address validator);

    constructor(
        address verifier,
        address dkimRegistry,
        address emailAuthImpl,
        address commandHandler,
        uint256 minimumDelay,
        address killSwitchAuthorizer,
       address _validator,
        bytes4 _selector
    )
        ModularRecoveryManager(
            verifier,
            dkimRegistry,
            emailAuthImpl,
            commandHandler,
            minimumDelay,
            killSwitchAuthorizer
        )
    {
         validator = _validator;
        selector = _selector;
    }
      /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          CONFIG                            */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/


       /**
     * @notice Initializes the module with the threshold, guardians and other configuration
     * @dev You cannot install this module during account deployment as it breaks the 4337
     * validation rules. ERC7579 does not mandate that executors abide by the validation rules
     * during account setup - if required, install this module after the account has been setup. The
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
                    ISimpleGuardianManager.GuardianType[] memory guardianTypes,
                    uint256 threshold,
                    uint256 delay,
                    uint256 expiry
                ) = abi.decode(data, (bytes, address[], uint256[], ISimpleGuardianManager.GuardianType[], uint256, uint256, uint256));
        
                configureRecovery(guardians, weights, guardianTypes, threshold, delay, expiry);
            }
   
    function onUninstall(bytes calldata /* data */ ) external {
        deInitRecoveryModule();
    }
  function isInitialized(address account) external view returns (bool) {
        return getGuardianConfig(account).threshold != 0;
    }
    /**
     * @notice Returns the type of the module
     * @param typeID type of the module
     * @return bool true if the type is a module type, false otherwise
     */
    function isModuleType(uint256 typeID) external pure returns (bool) {
        return typeID == TYPE_EXECUTOR;
    }

    /**
     * @notice Check if a recovery request can be initiated based on guardian acceptance
     * @param account The smart account to check
     * @return bool True if the recovery request can be started, false otherwise
     */
    function canStartRecoveryRequest(address account) external view returns (bool) {
        GuardianConfig memory guardianConfig = getGuardianConfig(account);

        return guardianConfig.threshold > 0
            && guardianConfig.acceptedWeight >= guardianConfig.threshold;
    }
   function recover (address account, bytes calldata recoveryData) internal virtual override{
        (, bytes memory recoveryCalldata) = abi.decode(recoveryData, (address, bytes));
        bytes4 calldataSelector;
        assembly {
            calldataSelector := mload(add(recoveryCalldata, 32))
        }
        if(calldataSelector != selector){
            revert InvalidSelector();
        }
        _execute({account: account, to: validator, value: 0, data: recoveryCalldata});
        emit RecoveryExecuted(account, account);
    }
    function testProcessRecovery(
        address guardian,
        uint256 templateIdx,
        bytes[] memory commandParams
    ) external {
        processRecovery(guardian, templateIdx, commandParams, "");
    }
 }
   
