// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;
import { EmailAccountRecovery } from
    "@zk-email/ether-email-auth-contracts/src/EmailAccountRecovery.sol";
// import {Test} from "forge-std/Test.sol";
import { Test } from "forge-std/Test.sol";
import { RhinestoneModuleKit, AccountInstance } from "modulekit/ModuleKit.sol";
import {SimpleRecoveryModule} from "./SimpleRecoveryToolinstaller.sol";
import  "./ISimpleGuardianManager.sol";
// import {SimpleEmailVerifier} from "./SimpleEmailVerifier.sol";
 import {SimplifiedDKIMRegistry} from "./DKIMRegistry.sol";
import {
    EmailAuth,
    EmailAuthMsg,
    EmailProof
} from "@zk-email/ether-email-auth-contracts/src/EmailAuth.sol";
import { EmailAccountRecovery } from
    "@zk-email/ether-email-auth-contracts/src/EmailAccountRecovery.sol";
import { EmailRecoveryUniversalFactory } from "src/factories/EmailRecoveryUniversalFactory.sol";
import { CommandUtils } from "@zk-email/ether-email-auth-contracts/src/libraries/CommandUtils.sol";
import { UserOverrideableDKIMRegistry } from "@zk-email/contracts/UserOverrideableDKIMRegistry.sol";
import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";
import { UniversalEmailRecoveryModuleHarness } from
    "../test/unit/UniversalEmailRecoveryModuleHarness.sol";
import { MockGroth16Verifier } from "src/test/MockGroth16Verifier.sol";
import { OwnableValidator } from "src/test/OwnableValidator.sol";
import {ISimpleGuardianManager} from "./ISimpleGuardianManager.sol";
import "forge-std/console.sol";

abstract contract BaseTest is RhinestoneModuleKit, Test{
    using Strings for uint256;

    // Core contracts
    address public zkEmailDeployer;
    SimpleRecoveryModule public recoveryModule;
     SimplifiedDKIMRegistry public dkimRegistry;
    MockGroth16Verifier public verifier;
    EmailAuth public emailAuthImpl;

     OwnableValidator public validator;
    address public validatorAddress;
    
    // // Mock Account contracts
    // MockAccount public account1;
    // MockAccount public account2;
    // MockAccount public account3;

    // EOA Guardians
    address public eoaGuardian1;
    address public eoaGuardian2;
    address public eoaGuardian3;

    // Email Guardians
    address public emailGuardian1;
    address public emailGuardian2;
    address public emailGuardian3;

    // Account owners
    address public owner1;
    address public owner2;
    address public owner3;
    address public newOwner;
     AccountInstance public instance1;
    AccountInstance public instance2;
    AccountInstance public instance3;
      address public accountAddress1;
    address public accountAddress2;
    address public accountAddress3;
    address public killSwitchAuthorizer;

     // public Account salts
    bytes32 public accountSalt1;
    bytes32 public accountSalt2;
    bytes32 public accountSalt3;

    // Configuration
    bytes32[] public accountSalts;
    address[] public guardians;
    uint256[] public weights;
   ISimpleGuardianManager.GuardianType[] public guardianTypes;

    uint256 public threshold;
    uint256 public delay;
    uint256 public expiry;
     uint256 public totalWeight;
    
    // Email verification constants
    string public constant DOMAIN_NAME = "gmail.com";
    bytes32 public constant PUBLIC_KEY_HASH = bytes32(uint256(1));
    uint256 public constant MINIMUM_DELAY = 12 hours;
    bytes4 public constant RECOVERY_SELECTOR = bytes4(keccak256("executeRecovery(address)"));


    // Other variables
    // address public killSwitchAuthorizer;
    bytes public recoveryData;
    bytes32 public recoveryDataHash;
    uint256 public nullifierCount;
bytes public recoveryCalldata;
    function setUp() public virtual {
            init();
            console.log("Debug: Address of instance1.account", address(instance1.account));
        // Setup accounts and owners
      // create owners
      UniversalEmailRecoveryModuleHarness emailRecoveryModule;
    // emailRecoveryModule = new UniversalEmailRecoveryModuleHarness();

console.log("Debug: Address of instance1.account", address(instance1.account));
        owner1 = vm.createWallet("owner1").addr;
        owner2 = vm.createWallet("owner2").addr;
        owner3 = vm.createWallet("owner3").addr;
         newOwner = vm.createWallet("newOwner").addr;

            // Deploy and fund the accounts
        instance1 = makeAccountInstance("account1");
        instance2 = makeAccountInstance("account2");
        instance3 = makeAccountInstance("account3");
               accountAddress1 = instance1.account;
        accountAddress2 = instance2.account;
        accountAddress3 = instance3.account;
        vm.deal(address(instance1.account), 10 ether);
        vm.deal(address(instance2.account), 10 ether);
        vm.deal(address(instance3.account), 10 ether);

            accountSalt1 = keccak256(abi.encode("account salt 1"));
        accountSalt2 = keccak256(abi.encode("account salt 2"));
        accountSalt3 = keccak256(abi.encode("account salt 3"));

             zkEmailDeployer = vm.addr(1);
        killSwitchAuthorizer = vm.addr(2);
require(accountAddress1 != address(0), "accountAddress1 not initialized");

             vm.startPrank(zkEmailDeployer);
      
        SimplifiedDKIMRegistry simplifiedDKIMRegistry = new SimplifiedDKIMRegistry();
        ERC1967Proxy dkimProxy = new ERC1967Proxy(
            address(simplifiedDKIMRegistry),
            abi.encodeCall(
                simplifiedDKIMRegistry.initialize, (zkEmailDeployer, zkEmailDeployer)
            )
        );
        dkimRegistry = SimplifiedDKIMRegistry(address(dkimProxy));

        dkimRegistry.setDKIMPublicKeyHash(DOMAIN_NAME, PUBLIC_KEY_HASH, zkEmailDeployer, new bytes(0));

        verifier = new MockGroth16Verifier();
        emailAuthImpl = new EmailAuth();
        vm.stopPrank();

        // Setup EOA guardians
        eoaGuardian1 = makeAddr("eoaGuardian1");
        eoaGuardian2 = makeAddr("eoaGuardian2");
        eoaGuardian3 = makeAddr("eoaGuardian3");

        // Setup account salts for email guardians
        accountSalts = new bytes32[](3);
        accountSalts[0] = keccak256(abi.encode("salt1"));
        accountSalts[1] = keccak256(abi.encode("salt2"));
        accountSalts[2] = keccak256(abi.encode("salt3"));

        // // Compute email guardian addresses
        emailGuardian1 = emailRecoveryModule.computeEmailAuthAddress(address(accountAddress1), accountSalts[0]);
        emailGuardian2 = emailRecoveryModule.computeEmailAuthAddress(address(accountAddress2), accountSalts[1]);
        emailGuardian3 = emailRecoveryModule.computeEmailAuthAddress(address(accountAddress3), accountSalts[2]);

       
        

        // Setup mixed guardians (2 EOA, 1 Email)
        guardians = new address[](3);
        weights = new uint256[](3);
        guardianTypes = new ISimpleGuardianManager.GuardianType[](3);

        // EOA Guardian 1
        guardians[0] = eoaGuardian1;
        weights[0] = 1;
        guardianTypes[0] = ISimpleGuardianManager.GuardianType.EOA;

        // EOA Guardian 2
        guardians[1] = eoaGuardian2;
        weights[1] = 1;
        guardianTypes[1] = ISimpleGuardianManager.GuardianType.EOA;

        // Email Guardian
        guardians[2] = emailGuardian1;
        weights[2] = 1;
        guardianTypes[2] = ISimpleGuardianManager.GuardianType.EmailVerified;

        // Set recovery configuration
        threshold = 2;
        delay = 1 days;
        expiry = 7 days;

        // Prepare recovery data
        recoveryData = abi.encode(
            address(accountAddress1),
            abi.encodeWithSelector(RECOVERY_SELECTOR, newOwner)
        );
        recoveryDataHash = keccak256(recoveryData);

        // Deploy recovery module
        recoveryModule = new SimpleRecoveryModule(
            address(verifier),
            address(dkimRegistry),
            address(0), // emailAuthImpl
            address(0), // commandHandler
            MINIMUM_DELAY,
            killSwitchAuthorizer,
            address(accountAddress1), // Initial validator
            RECOVERY_SELECTOR
        );
    }
    // function computeEmailAuthAddress(
    //     address account,
    //     bytes32 accountSalt
    // )
    //     public
    //     view
    //     virtual
    //     returns (address);

    function generateMockEmailProof(
        string memory command,
        bytes32 nullifier,
        bytes32 accountSalt
    )
        public
        view
        returns (EmailProof memory)
    {
        EmailProof memory emailProof;
        emailProof.domainName = "gmail.com";
        emailProof.publicKeyHash = bytes32(
            vm.parseUint(
                "6632353713085157925504008443078919716322386156160602218536961028046468237192"
            )
        );
        emailProof.timestamp = block.timestamp;
        emailProof.maskedCommand = command;
        emailProof.emailNullifier = nullifier;
        emailProof.accountSalt = accountSalt;
        emailProof.isCodeExist = true;
        emailProof.proof = bytes("0");

        return emailProof;
    }

}

 // // Deploy core contracts
        // killSwitchAuthorizer = makeAddr("killSwitchAuthorizer");
        // verifier = new SimpleEmailVerifier();
        // zkEmailDeployer = vm.addr(1);
        // killSwitchAuthorizer = vm.addr(2);

        // vm.startPrank(zkEmailDeployer);
      
        // UserOverrideableDKIMRegistry overrideableDkimImpl = new UserOverrideableDKIMRegistry();
        // ERC1967Proxy dkimProxy = new ERC1967Proxy(
        //     address(overrideableDkimImpl),
        //     abi.encodeCall(
        //         overrideableDkimImpl.initialize, (zkEmailDeployer, zkEmailDeployer, setTimeDelay)
        //     )
        // );
        // dkimRegistry = UserOverrideableDKIMRegistry(address(dkimProxy));

        // dkimRegistry.setDKIMPublicKeyHash(DOMAIN_NAME, PUBLIC_KEY_HASH, zkEmailDeployer, new bytes(0));

        // verifier = new MockGroth16Verifier();
        // emailAuthImpl = new EmailAuth();
        // vm.stopPrank();
        

        // // Setup DKIM registry
        // vm.prank(dkimRegistry.owner());
        // dkimRegistry.setDKIMPublicKeyHash(DOMAIN_NAME, PUBLIC_KEY_HASH);
//  function computeEmailAuthAddress(
    //     address account,
    //     bytes32 accountSalt
    // )
    //     public
    //     view
    //     override
    //     returns (address)
    // {
    //     return emailRecoveryModule.computeEmailAuthAddress(account, accountSalt);
    // }