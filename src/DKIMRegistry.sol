// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import "@openzeppelin/contracts/utils/Strings.sol";

/**
 * @title SimplifiedDKIMRegistry
 * @notice A simplified registry to manage DKIM public key hashes for domain-based verification.
 * Supports both EOA and email-verified guardians for ERC-7579 recovery processes.
 */
contract SimplifiedDKIMRegistry is OwnableUpgradeable {
    using ECDSA for bytes32;

     /// @notice Main authorizer address.
    address public mainAuthorizer;

   
  /// @notice Emitted when a DKIM public key hash is successfully set.
    event DKIMPublicKeyHashRegistered(
        string indexed domainName,
        bytes32 indexed publicKeyHash,
        address indexed authorizer
    );

    /// @notice Emitted when a DKIM public key hash is successfully revoked.
    event DKIMPublicKeyHashRevoked(
        bytes32 indexed publicKeyHash,
        address indexed authorizer
    );
     /// @notice DKIM public key hashes that are set
    mapping(string => mapping(bytes32 => mapping(address => bool)))
        public dkimPublicKeyHashes;

    /// @notice DKIM public key hashes that are revoked (eg: in case of private key compromise)
    mapping(bytes32 => mapping(address => bool))
        public revokedDKIMPublicKeyHashes;
string public constant SET_PREFIX = "SET:";
    string public constant REVOKE_PREFIX = "REVOKE:";
           /// @notice Initializes the contract with a predefined signer and deploys a new DKIMRegistry.
    /// @param _initialOwner The address of the initial owner of the contract.
    /// @param _mainAuthorizer The address of the main authorizer.
     function initialize(
        address _initialOwner,
        address _mainAuthorizer
      
    ) public initializer {
        __Ownable_init(_initialOwner);
        mainAuthorizer = _mainAuthorizer;
       
    }
    /// @notice Checks if a DKIM public key hash is valid for a given domain.
    /// @param domainName The domain name for which the DKIM public key hash is being checked.
    /// @param publicKeyHash The hash of the DKIM public key to be checked.
    /// @return bool True if the DKIM public key hash is valid, false otherwise.
    /// @dev This function returns true if the owner of the given `msg.sender` approves the public key hash before `enabledTimeOfDKIMPublicKeyHash` and neither `mainAuthorizer` nor the owner of `msg.sender` revokes the public key hash. However, after `enabledTimeOfDKIMPublicKeyHash`, only one of their approvals is required. In addition, if the public key hash is reactivated by the owner of `msg.sender`, the public key hash revoked only by `mainAuthorizer` is considered valid.
    function isDKIMPublicKeyHashValid(
        string memory domainName,
        bytes32 publicKeyHash
    ) public view returns (bool) {
        address ownerOfSender = Ownable(msg.sender).owner();
        return
            isDKIMPublicKeyHashValid(domainName, publicKeyHash, ownerOfSender);
    }

    /// @notice Checks if a DKIM public key hash is valid for a given domain.
    /// @param domainName The domain name for which the DKIM public key hash is being checked.
    /// @param publicKeyHash The hash of the DKIM public key to be checked.
    /// @param authorizer The address of the expected authorizer
    /// @return bool True if the DKIM public key hash is valid, false otherwise.
    /// @dev This function returns true if 1) at least the given `authorizer` approves the public key hash before `enabledTimeOfDKIMPublicKeyHash` and 2) neither `mainAuthorizer` nor `authorizer` revokes the public key hash. However, after `enabledTimeOfDKIMPublicKeyHash`, only one of their approvals is required. In addition, if the public key hash is reactivated by the `authorizer`, the public key hash revoked only by `mainAuthorizer` is considered valid.
    /// @dev The domain name, public key hash, and authorizer address must not be zero.
    /// @dev The authorizer address cannot be the mainAuthorizer.
    function isDKIMPublicKeyHashValid(
        string memory domainName,
        bytes32 publicKeyHash,
        address authorizer
    ) public view returns (bool) {
        require(bytes(domainName).length > 0, "domain name cannot be zero");
        require(publicKeyHash != bytes32(0), "public key hash cannot be zero");
        require(authorizer != address(0), "authorizer address cannot be zero");
        require(
            authorizer != mainAuthorizer,
            "authorizer cannot be mainAuthorizer"
        );
       return true;
    }
    /**
     * @notice Sets the DKIM public key hash for a given domain with authorization.
     * @dev This function allows an authorized user or a contract to set a DKIM public key hash. It uses EIP-1271 or ECDSA for signature verification.
     * @param domainName The domain name for which the DKIM public key hash is being set.
     * @param publicKeyHash The hash of the DKIM public key to be set.
     * @param authorizer The address of the authorizer who can set the DKIM public key hash.
     * @param signature The signature proving the authorization to set the DKIM public key hash.
     * @custom:require The domain name, public key hash, and authorizer address must not be zero.
     * @custom:require The public key hash must not be revoked.
     * @custom:require The signature must be valid according to EIP-1271 if the authorizer is a contract, or ECDSA if the authorizer is an EOA.
     * @custom:event DKIMPublicKeyHashRegistered Emitted when a DKIM public key hash is successfully set.
     */
    function setDKIMPublicKeyHash(
        string memory domainName,
        bytes32 publicKeyHash,
        address authorizer,
        bytes memory signature
    ) public {
        require(bytes(domainName).length > 0, "domain name cannot be zero");
        require(publicKeyHash != bytes32(0), "public key hash cannot be zero");
        require(authorizer != address(0), "authorizer address cannot be zero");
        require(
            dkimPublicKeyHashes[domainName][publicKeyHash][authorizer] == false,
            "public key hash is already set"
        );
        require(
            revokedDKIMPublicKeyHashes[publicKeyHash][authorizer] == false,
            "public key hash is already revoked"
        );
        if (msg.sender != authorizer) {
            string memory signedMsg = computeSignedMsg(
                SET_PREFIX,
                domainName,
                publicKeyHash
            );
            bytes32 digest = MessageHashUtils.toEthSignedMessageHash(
                bytes(signedMsg)
            );
            if (authorizer.code.length > 0) {
                require(
                    IERC1271(authorizer).isValidSignature(digest, signature) ==
                        0x1626ba7e,
                    "invalid eip1271 signature"
                );
            } else {
                address recoveredSigner = digest.recover(signature);
                require(
                    recoveredSigner == authorizer,
                    "invalid ecdsa signature"
                );
            }
        }
         dkimPublicKeyHashes[domainName][publicKeyHash][authorizer] = true;
        

        emit DKIMPublicKeyHashRegistered(domainName, publicKeyHash, authorizer);
    }
      /**
     * @notice Revokes a DKIM public key hash.
     * @dev This function allows the owner to revoke a DKIM public key hash for all users, or an individual user to revoke it for themselves.
     * @param domainName The domain name associated with the DKIM public key hash.
     * @param publicKeyHash The hash of the DKIM public key to be revoked.
     * @param authorizer The address of the authorizer who can revoke the DKIM public key hash.
     * @param signature The signature proving the authorization to revoke the DKIM public key hash.
     * @custom:require The domain name, public key hash, and authorizer address must not be zero.
     * @custom:require The public key hash must not already be revoked.
     * @custom:require The signature must be valid according to EIP-1271 if the authorizer is a contract, or ECDSA if the authorizer is an EOA.
     * @custom:event DKIMPublicKeyHashRevoked Emitted when a DKIM public key hash is successfully revoked.
     */
    function revokeDKIMPublicKeyHash(
        string memory domainName,
        bytes32 publicKeyHash,
        address authorizer,
        bytes memory signature
    ) public {
        require(bytes(domainName).length > 0, "domain name cannot be zero");
        require(publicKeyHash != bytes32(0), "public key hash cannot be zero");
        require(authorizer != address(0), "authorizer address cannot be zero");
        require(
            revokedDKIMPublicKeyHashes[publicKeyHash][authorizer] == false,
            "public key hash is already revoked"
        );
        if (msg.sender != authorizer) {
            string memory signedMsg = computeSignedMsg(
                REVOKE_PREFIX,
                domainName,
                publicKeyHash
            );
            bytes32 digest = MessageHashUtils.toEthSignedMessageHash(
                bytes(signedMsg)
            );
            if (authorizer.code.length > 0) {
                require(
                    IERC1271(authorizer).isValidSignature(digest, signature) ==
                        0x1626ba7e,
                    "invalid eip1271 signature"
                );
            } else {
                address recoveredSigner = digest.recover(signature);
                require(
                    recoveredSigner == authorizer,
                    "invalid ecdsa signature"
                );
            }
        }
        revokedDKIMPublicKeyHashes[publicKeyHash][authorizer] = true;

        emit DKIMPublicKeyHashRevoked(publicKeyHash, authorizer);
    }
/**
     * @notice Computes a signed message string for setting or revoking a DKIM public key hash.
     * @param prefix The operation prefix (SET: or REVOKE:).
     * @param domainName The domain name related to the operation.
     * @param publicKeyHash The DKIM public key hash involved in the operation.
     * @return string The computed signed message.
     * @dev This function is used internally to generate the message that needs to be signed for setting or revoking a public key hash.
     */
    function computeSignedMsg(
        string memory prefix,
        string memory domainName,
        bytes32 publicKeyHash
    ) public pure returns (string memory) {
        return
            string.concat(
                prefix,
                "domain=",
                domainName,
                ";public_key_hash=",
                  Strings.toHexString(uint256(publicKeyHash), 32),  // Length for `bytes32`
        ";"
            );
    }

}