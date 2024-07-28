// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { console2 } from "forge-std/console2.sol";
import { SentinelListLib } from "sentinellist/SentinelList.sol";
import { UniversalEmailRecoveryModule } from "src/modules/UniversalEmailRecoveryModule.sol";

contract UniversalEmailRecoveryModuleHarness is UniversalEmailRecoveryModule {
    using SentinelListLib for SentinelListLib.SentinelList;

    constructor(address emailRecoveryManager) UniversalEmailRecoveryModule(emailRecoveryManager) { }

    function workaround_validatorsPush(address account, address validator) external {
        validators[account].push(validator);
        validatorCount[account]++;
    }

    function workaround_validatorsContains(
        address account,
        address validator
    )
        external
        returns (bool)
    {
        return validators[account].contains(validator);
    }

    function exposed_allowedSelectors(
        address validator,
        address account
    )
        external
        view
        returns (bytes4)
    {
        return allowedSelectors[validator][account];
    }
}
