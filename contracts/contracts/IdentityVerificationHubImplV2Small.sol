// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {ImplRoot} from "./upgradeable/ImplRoot.sol";
import {SelfStructs} from "./libraries/SelfStructs.sol";
import {GenericProofStruct} from "./interfaces/IRegisterCircuitVerifier.sol";
import {CustomVerifier} from "./libraries/CustomVerifier.sol";
import {GenericFormatter} from "./libraries/GenericFormatter.sol";
import {AttestationId} from "./constants/AttestationId.sol";
import {IVcAndDiscloseCircuitVerifier} from "./interfaces/IVcAndDiscloseCircuitVerifier.sol";
import {IVcAndDiscloseAadhaarCircuitVerifier} from "./interfaces/IVcAndDiscloseCircuitVerifier.sol";
import {ISelfVerificationRoot} from "./interfaces/ISelfVerificationRoot.sol";
import {IIdentityRegistryV1} from "./interfaces/IIdentityRegistryV1.sol";
import {IIdentityRegistryIdCardV1} from "./interfaces/IIdentityRegistryIdCardV1.sol";
import {IIdentityRegistryAadhaarV1} from "./interfaces/IIdentityRegistryAadhaarV1.sol";
import {IRegisterCircuitVerifier} from "./interfaces/IRegisterCircuitVerifier.sol";
import {IAadhaarRegisterCircuitVerifier} from "./interfaces/IRegisterCircuitVerifier.sol";
import {IDscCircuitVerifier} from "./interfaces/IDscCircuitVerifier.sol";
import {CircuitConstantsV2} from "./constants/CircuitConstantsV2.sol";
import {Formatter} from "./libraries/Formatter.sol";
import {IdentityVerificationLibrary} from "./IdentityVerificationLibrary.sol";

contract IdentityVerificationHubImplV2Small is ImplRoot {
    /// @custom:storage-location erc7201:self.storage.IdentityVerificationHub
    struct IdentityVerificationHubStorage {
        uint256 _circuitVersion;
        mapping(bytes32 attestationId => address registry) _registries;
        mapping(bytes32 attestationId => mapping(uint256 sigTypeId => address registerCircuitVerifier)) _registerCircuitVerifiers;
        mapping(bytes32 attestationId => mapping(uint256 sigTypeId => address dscCircuitVerifier)) _dscCircuitVerifiers;
        mapping(bytes32 attestationId => address discloseVerifiers) _discloseVerifiers;
    }

    /// @custom:storage-location erc7201:self.storage.IdentityVerificationHubV2
    struct IdentityVerificationHubV2Storage {
        mapping(bytes32 configId => SelfStructs.VerificationConfigV2) _v2VerificationConfigs;
    }
    // We should consider to add bridge address
    // address bridgeAddress;

    /// @dev keccak256(abi.encode(uint256(keccak256("self.storage.IdentityVerificationHub")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant IDENTITYVERIFICATIONHUB_STORAGE_LOCATION =
        0x2ade7eace21710c689ddef374add52ace9783e33bac626e58e73a9d190173d00;

    /// @dev keccak256(abi.encode(uint256(keccak256("self.storage.IdentityVerificationHubV2")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant IDENTITYVERIFICATIONHUBV2_STORAGE_LOCATION =
        0xf9b5980dcec1a8b0609576a1f453bb2cad4732a0ea02bb89154d44b14a306c00;

    /// @notice The AADHAAR registration window around the current block timestamp.
    uint256 public AADHAAR_REGISTRATION_WINDOW = 20;

    /**
     * @notice Returns the storage struct for the main IdentityVerificationHub.
     * @dev Uses ERC-7201 storage pattern for upgradeable contracts.
     * @return $ The storage struct reference.
     */
    function _getIdentityVerificationHubStorage() private pure returns (IdentityVerificationHubStorage storage $) {
        assembly {
            $.slot := IDENTITYVERIFICATIONHUB_STORAGE_LOCATION
        }
    }

    /**
     * @notice Returns the storage struct for IdentityVerificationHub V2 features.
     * @dev Uses ERC-7201 storage pattern for upgradeable contracts.
     * @return $ The V2 storage struct reference.
     */
    function _getIdentityVerificationHubV2Storage() private pure returns (IdentityVerificationHubV2Storage storage $) {
        assembly {
            $.slot := IDENTITYVERIFICATIONHUBV2_STORAGE_LOCATION
        }
    }

    // ====================================================
    // Constructor
    // ====================================================

    /**
     * @notice Constructor that disables initializers for the implementation contract.
     * @dev This prevents the implementation contract from being initialized directly.
     * The actual initialization should only happen through the proxy.
     */
    constructor() {
        _disableInitializers();
    }

    // ====================================================
    // Initializer
    // ====================================================

    /**
     * @notice Initializes the Identity Verification Hub V2 contract for upgrade.
     * @dev Sets up the contract state including circuit version and emits initialization event.
     * This function is used when upgrading from V1 to V2, hence uses reinitializer(2).
     * The circuit version is set to 2 for V2 hub compatibility.
     */
    function initialize() external reinitializer(11) {
        __ImplRoot_init();

        // Initialize circuit version to 2 for V2 hub
        IdentityVerificationHubStorage storage $ = _getIdentityVerificationHubStorage();
        $._circuitVersion = 2;

        emit IdentityVerificationLibrary.HubInitializedV2();
    }

    // ====================================================
    // External Functions
    // ====================================================

    /**
     * @notice Registers a commitment using a register circuit proof.
     * @dev Verifies the register circuit proof and then calls the Identity Registry to register the commitment.
     * @param attestationId The attestation ID.
     * @param registerCircuitVerifierId The identifier for the register circuit verifier to use.
     * @param registerCircuitProof The register circuit proof data.
     */
    function registerCommitment(
        bytes32 attestationId,
        uint256 registerCircuitVerifierId,
        GenericProofStruct memory registerCircuitProof
    ) external virtual onlyProxy {
        _verifyRegisterProof(attestationId, registerCircuitVerifierId, registerCircuitProof);
        IdentityVerificationHubStorage storage $ = _getIdentityVerificationHubStorage();
        if (attestationId == AttestationId.E_PASSPORT) {
            IIdentityRegistryV1($._registries[attestationId]).registerCommitment(
                attestationId,
                registerCircuitProof.pubSignals[CircuitConstantsV2.REGISTER_NULLIFIER_INDEX],
                registerCircuitProof.pubSignals[CircuitConstantsV2.REGISTER_COMMITMENT_INDEX]
            );
        } else if (attestationId == AttestationId.EU_ID_CARD) {
            IIdentityRegistryIdCardV1($._registries[attestationId]).registerCommitment(
                attestationId,
                registerCircuitProof.pubSignals[CircuitConstantsV2.REGISTER_NULLIFIER_INDEX],
                registerCircuitProof.pubSignals[CircuitConstantsV2.REGISTER_COMMITMENT_INDEX]
            );
        } else if (attestationId == AttestationId.AADHAAR) {
            IIdentityRegistryAadhaarV1($._registries[attestationId]).registerCommitment(
                registerCircuitProof.pubSignals[CircuitConstantsV2.AADHAAR_NULLIFIER_INDEX],
                registerCircuitProof.pubSignals[CircuitConstantsV2.AADHAAR_COMMITMENT_INDEX]
            );
        } else {
            revert IdentityVerificationLibrary.InvalidAttestationId();
        }
    }

    /**
     * @notice Registers a DSC key commitment using a DSC circuit proof.
     * @dev Verifies the DSC proof and then calls the Identity Registry to register the dsc key commitment.
     * @param dscCircuitVerifierId The identifier for the DSC circuit verifier to use.
     * @param dscCircuitProof The DSC circuit proof data.
     */
    function registerDscKeyCommitment(
        bytes32 attestationId,
        uint256 dscCircuitVerifierId,
        IDscCircuitVerifier.DscCircuitProof memory dscCircuitProof
    ) external virtual onlyProxy {
        _verifyDscProof(attestationId, dscCircuitVerifierId, dscCircuitProof);
        IdentityVerificationHubStorage storage $ = _getIdentityVerificationHubStorage();
        if (attestationId == AttestationId.E_PASSPORT) {
            IIdentityRegistryV1($._registries[attestationId]).registerDscKeyCommitment(
                dscCircuitProof.pubSignals[CircuitConstantsV2.DSC_TREE_LEAF_INDEX]
            );
        } else if (attestationId == AttestationId.EU_ID_CARD) {
            IIdentityRegistryIdCardV1($._registries[attestationId]).registerDscKeyCommitment(
                dscCircuitProof.pubSignals[CircuitConstantsV2.DSC_TREE_LEAF_INDEX]
            );
        } else {
            revert IdentityVerificationLibrary.InvalidAttestationId();
        }
    }

    /**
     * @notice Sets verification config in V2 storage (owner only)
     * @dev The configId is automatically generated from the config content using sha256(abi.encode(config))
     * @param config The verification configuration
     * @return configId The generated config ID
     */
    function setVerificationConfigV2(
        SelfStructs.VerificationConfigV2 memory config
    ) external virtual onlyProxy returns (bytes32 configId) {
        configId = generateConfigId(config);
        IdentityVerificationHubV2Storage storage $v2 = _getIdentityVerificationHubV2Storage();
        $v2._v2VerificationConfigs[configId] = config;

        emit IdentityVerificationLibrary.VerificationConfigV2Set(configId, config);
    }

    /**
     * @notice Updates the AADHAAR registration window.
     * @param window The new AADHAAR registration window.
     */
    function setAadhaarRegistrationWindow(uint256 window) external virtual onlyProxy onlyOwner {
        AADHAAR_REGISTRATION_WINDOW = window;
    }

    /**
     * @notice Main verification function with new structured input format.
     * @dev Orchestrates the complete verification process including proof validation and result handling.
     * This function decodes the input, executes the verification flow, and handles the result based on destination chain.
     * @param baseVerificationInput The base verification input containing header and proof data.
     * @param userContextData The user context data containing config ID, destination chain ID, user identifier, and additional data.
     */
    function verify(bytes calldata baseVerificationInput, bytes calldata userContextData) external virtual onlyProxy {
        (SelfStructs.HubInputHeader memory header, bytes memory proofData) = IdentityVerificationLibrary.decodeInput(baseVerificationInput);

        // Perform verification and get output along with user data
        (
            bytes memory output,
            uint256 destChainId,
            bytes memory userDataToPass,
            bytes32 configId,
            uint256 userIdentifier
        ) = _executeVerificationFlow(header, proofData, userContextData);

        // Use destChainId and userDataToPass returned from _executeVerificationFlow
        _handleVerificationResult(destChainId, output, userDataToPass);

        // Emit verification event for tracking
        emit IdentityVerificationLibrary.DisclosureVerified(
            msg.sender,
            header.contractVersion,
            header.attestationId,
            destChainId,
            configId,
            userIdentifier,
            output,
            userDataToPass
        );
    }

    /**
     * @notice Updates the registry address.
     * @param registryAddress The new registry address.
     */
    function updateRegistry(bytes32 attestationId, address registryAddress) external virtual onlyProxy onlyOwner {
        IdentityVerificationHubStorage storage $ = _getIdentityVerificationHubStorage();
        $._registries[attestationId] = registryAddress;
        emit IdentityVerificationLibrary.RegistryUpdated(attestationId, registryAddress);
    }

    /**
     * @notice Updates the VC and Disclose circuit verifier address.
     * @param vcAndDiscloseCircuitVerifierAddress The new VC and Disclose circuit verifier address.
     */
    function updateVcAndDiscloseCircuit(
        bytes32 attestationId,
        address vcAndDiscloseCircuitVerifierAddress
    ) external virtual onlyProxy onlyOwner {
        IdentityVerificationHubStorage storage $ = _getIdentityVerificationHubStorage();
        $._discloseVerifiers[attestationId] = vcAndDiscloseCircuitVerifierAddress;
        emit IdentityVerificationLibrary.VcAndDiscloseCircuitUpdated(attestationId, vcAndDiscloseCircuitVerifierAddress);
    }

    /**
     * @notice Updates the register circuit verifier for a specific signature type.
     * @param attestationId The attestation identifier.
     * @param typeId The signature type identifier.
     * @param verifierAddress The new register circuit verifier address.
     */
    function updateRegisterCircuitVerifier(
        bytes32 attestationId,
        uint256 typeId,
        address verifierAddress
    ) external virtual onlyProxy onlyOwner {
        IdentityVerificationHubStorage storage $ = _getIdentityVerificationHubStorage();
        $._registerCircuitVerifiers[attestationId][typeId] = verifierAddress;
        emit IdentityVerificationLibrary.RegisterCircuitVerifierUpdated(typeId, verifierAddress);
    }

    /**
     * @notice Updates the DSC circuit verifier for a specific signature type.
     * @param attestationId The attestation identifier.
     * @param typeId The signature type identifier.
     * @param verifierAddress The new DSC circuit verifier address.
     */
    function updateDscVerifier(
        bytes32 attestationId,
        uint256 typeId,
        address verifierAddress
    ) external virtual onlyProxy onlyOwner {
        IdentityVerificationHubStorage storage $ = _getIdentityVerificationHubStorage();
        $._dscCircuitVerifiers[attestationId][typeId] = verifierAddress;
        emit IdentityVerificationLibrary.DscCircuitVerifierUpdated(typeId, verifierAddress);
    }

    /**
     * @notice Batch updates register circuit verifiers.
     * @param attestationIds An array of attestation identifiers.
     * @param typeIds An array of signature type identifiers.
     * @param verifierAddresses An array of new register circuit verifier addresses.
     */
    function batchUpdateRegisterCircuitVerifiers(
        bytes32[] calldata attestationIds,
        uint256[] calldata typeIds,
        address[] calldata verifierAddresses
    ) external virtual onlyProxy onlyOwner {
        if (attestationIds.length != typeIds.length || attestationIds.length != verifierAddresses.length) {
            revert IdentityVerificationLibrary.LengthMismatch();
        }
        IdentityVerificationHubStorage storage $ = _getIdentityVerificationHubStorage();
        for (uint256 i = 0; i < attestationIds.length; i++) {
            $._registerCircuitVerifiers[attestationIds[i]][typeIds[i]] = verifierAddresses[i];
            emit IdentityVerificationLibrary.RegisterCircuitVerifierUpdated(typeIds[i], verifierAddresses[i]);
        }
    }

    /**
     * @notice Batch updates DSC circuit verifiers.
     * @param attestationIds An array of attestation identifiers.
     * @param typeIds An array of signature type identifiers.
     * @param verifierAddresses An array of new DSC circuit verifier addresses.
     */
    function batchUpdateDscCircuitVerifiers(
        bytes32[] calldata attestationIds,
        uint256[] calldata typeIds,
        address[] calldata verifierAddresses
    ) external virtual onlyProxy onlyOwner {
        if (attestationIds.length != typeIds.length || attestationIds.length != verifierAddresses.length) {
            revert IdentityVerificationLibrary.LengthMismatch();
        }
        IdentityVerificationHubStorage storage $ = _getIdentityVerificationHubStorage();
        for (uint256 i = 0; i < attestationIds.length; i++) {
            $._dscCircuitVerifiers[attestationIds[i]][typeIds[i]] = verifierAddresses[i];
            emit IdentityVerificationLibrary.DscCircuitVerifierUpdated(typeIds[i], verifierAddresses[i]);
        }
    }

    // ====================================================
    // External View Functions
    // ====================================================

    /**
     * @notice Returns the registry address for a given attestation ID.
     * @param attestationId The attestation ID to query.
     * @return The registry address associated with the attestation ID.
     */
    function registry(bytes32 attestationId) external view virtual onlyProxy returns (address) {
        IdentityVerificationHubStorage storage $ = _getIdentityVerificationHubStorage();
        return $._registries[attestationId];
    }

    /**
     * @notice Returns the disclose verifier address for a given attestation ID.
     * @param attestationId The attestation ID to query.
     * @return The disclose verifier address associated with the attestation ID.
     */
    function discloseVerifier(bytes32 attestationId) external view virtual onlyProxy returns (address) {
        IdentityVerificationHubStorage storage $ = _getIdentityVerificationHubStorage();
        return $._discloseVerifiers[attestationId];
    }

    /**
     * @notice Returns the register circuit verifier address for a given attestation ID and type ID.
     * @param attestationId The attestation ID to query.
     * @param typeId The type ID to query.
     * @return The register circuit verifier address associated with the attestation ID and type ID.
     */
    function registerCircuitVerifiers(
        bytes32 attestationId,
        uint256 typeId
    ) external view virtual onlyProxy returns (address) {
        IdentityVerificationHubStorage storage $ = _getIdentityVerificationHubStorage();
        return $._registerCircuitVerifiers[attestationId][typeId];
    }

    /**
     * @notice Returns the DSC circuit verifier address for a given attestation ID and type ID.
     * @param attestationId The attestation ID to query.
     * @param typeId The type ID to query.
     * @return The DSC circuit verifier address associated with the attestation ID and type ID.
     */
    function dscCircuitVerifiers(
        bytes32 attestationId,
        uint256 typeId
    ) external view virtual onlyProxy returns (address) {
        IdentityVerificationHubStorage storage $ = _getIdentityVerificationHubStorage();
        return $._dscCircuitVerifiers[attestationId][typeId];
    }

    /**
     * @notice Returns the merkle root timestamp for a given attestation ID and root.
     * @param attestationId The attestation ID to query.
     * @param root The merkle root to query.
     * @return The merkle root timestamp associated with the attestation ID and root.
     */
    function rootTimestamp(bytes32 attestationId, uint256 root) external view virtual onlyProxy returns (uint256) {
        IdentityVerificationHubStorage storage $ = _getIdentityVerificationHubStorage();
        address registryAddress = $._registries[attestationId];
        if (attestationId == AttestationId.E_PASSPORT) {
            return IIdentityRegistryV1(registryAddress).rootTimestamps(root);
        } else if (attestationId == AttestationId.EU_ID_CARD) {
            return IIdentityRegistryIdCardV1(registryAddress).rootTimestamps(root);
        } else if (attestationId == AttestationId.AADHAAR) {
            return IIdentityRegistryAadhaarV1(registryAddress).rootTimestamps(root);
        } else {
            revert IdentityVerificationLibrary.InvalidAttestationId();
        }
    }

    /**
     * @notice Returns the identity commitment merkle root for a given attestation ID.
     * @param attestationId The attestation ID to query.
     * @return The identity commitment merkle root associated with the attestation ID.
     */
    function getIdentityCommitmentMerkleRoot(bytes32 attestationId) external view virtual onlyProxy returns (uint256) {
        IdentityVerificationHubStorage storage $ = _getIdentityVerificationHubStorage();
        address registryAddress = $._registries[attestationId];

        if (attestationId == AttestationId.E_PASSPORT) {
            return IIdentityRegistryV1(registryAddress).getIdentityCommitmentMerkleRoot();
        } else if (attestationId == AttestationId.EU_ID_CARD) {
            return IIdentityRegistryIdCardV1(registryAddress).getIdentityCommitmentMerkleRoot();
        } else if (attestationId == AttestationId.AADHAAR) {
            return IIdentityRegistryAadhaarV1(registryAddress).getIdentityCommitmentMerkleRoot();
        } else {
            revert IdentityVerificationLibrary.InvalidAttestationId();
        }
    }

    /**
     * @notice Checks if a verification config exists
     * @param configId The configuration identifier
     * @return exists Whether the config exists
     */
    function verificationConfigV2Exists(bytes32 configId) external view virtual onlyProxy returns (bool exists) {
        SelfStructs.VerificationConfigV2 memory config = getVerificationConfigV2(configId);
        return generateConfigId(config) == configId;
    }

    // ====================================================
    // Public Functions
    // ====================================================

    /**
     * @notice Generates a config ID from a verification config
     * @param config The verification configuration
     * @return The generated config ID (sha256 hash of encoded config)
     */
    function generateConfigId(SelfStructs.VerificationConfigV2 memory config) public pure returns (bytes32) {
        return sha256(abi.encode(config));
    }

    // ====================================================
    // Internal Functions
    // ====================================================

    /**
     * @notice Executes the complete verification flow.
     * @dev Processes user context data, retrieves verification config, performs basic verification,
     * executes custom verification logic, and formats the output.
     * @param header The decoded hub input header containing verification parameters.
     * @param proofData The raw proof data to be decoded and verified.
     * @param userContextData The user-provided context data.
     * @return output The formatted verification output.
     * @return destChainId The destination chain identifier.
     * @return userDataToPass The remaining user data to pass through.
     */
    function _executeVerificationFlow(
        SelfStructs.HubInputHeader memory header,
        bytes memory proofData,
        bytes calldata userContextData
    )
        internal
        view
        returns (
            bytes memory output,
            uint256 destChainId,
            bytes memory userDataToPass,
            bytes32 configId,
            uint256 userIdentifier
        )
    {
        bytes memory remainingData;
        {
            (configId, destChainId, userIdentifier, remainingData) = IdentityVerificationLibrary.decodeUserContextData(userContextData);
        }

        {
            bytes memory config = _getVerificationConfigById(configId);

            bytes memory proofOutput = _basicVerification(
                header,
                IdentityVerificationLibrary.decodeVcAndDiscloseProof(proofData),
                userContextData,
                userIdentifier
            );

            SelfStructs.GenericDiscloseOutputV2 memory genericDiscloseOutput = CustomVerifier.customVerify(
                header.attestationId,
                config,
                proofOutput
            );

            output = IdentityVerificationLibrary.formatVerificationOutput(header.contractVersion, genericDiscloseOutput);
        }

        userDataToPass = remainingData;
    }

    /**
     * @notice Handles verification result based on destination chain.
     * @dev Routes the verification result to the appropriate handler based on whether
     * the destination is the current chain or requires cross-chain bridging.
     * @param destChainId The destination chain identifier.
     * @param output The verification output data.
     * @param userDataToPass The user data to pass to the result handler.
     */
    function _handleVerificationResult(uint256 destChainId, bytes memory output, bytes memory userDataToPass) internal {
        if (destChainId == block.chainid) {
            ISelfVerificationRoot(msg.sender).onVerificationSuccess(output, userDataToPass);
        } else {
            // Call external bridge
            // _handleBridge()
            revert IdentityVerificationLibrary.CrossChainIsNotSupportedYet();
        }
    }

    /**
     * @notice Unified basic verification function for both passport and ID card proofs.
     * @dev Performs four core verification steps: scopeCheck, rootCheck, currentDateCheck, groth16 proof verification
     * @param header The hub input header containing scope and attestation information
     * @param vcAndDiscloseProof The VC and Disclose proof data
     * @param userContextData The user context data for validation
     * @param userIdentifier The user identifier for proof validation
     * @return output The verification result encoded as bytes (PassportOutput or EuIdOutput)
     */
    function _basicVerification(
        SelfStructs.HubInputHeader memory header,
        GenericProofStruct memory vcAndDiscloseProof,
        bytes calldata userContextData,
        uint256 userIdentifier
    ) internal view returns (bytes memory output) {
        // Scope 1: Basic checks (scope and user identifier)
        CircuitConstantsV2.DiscloseIndices memory indices = CircuitConstantsV2.getDiscloseIndices(header.attestationId);
        {
            IdentityVerificationLibrary.performAttestationIdCheck(header.attestationId, vcAndDiscloseProof, indices);
            IdentityVerificationLibrary.performScopeCheck(header.scope, vcAndDiscloseProof, indices);
            IdentityVerificationLibrary.performUserIdentifierCheck(userContextData, vcAndDiscloseProof, indices);
        }

        // Scope 2: Root and date checks
        {
            _performRootCheck(header.attestationId, vcAndDiscloseProof, indices);
            _performOfacCheck(header.attestationId, vcAndDiscloseProof, indices);
            if (header.attestationId == AttestationId.AADHAAR) {
                IdentityVerificationLibrary.performNumericCurrentDateCheck(vcAndDiscloseProof, indices);
            } else {
                IdentityVerificationLibrary.performCurrentDateCheck(vcAndDiscloseProof, indices);
            }
        }

        // Scope 3: Groth16 proof verification
        _performGroth16ProofVerification(header.attestationId, vcAndDiscloseProof);

        // Scope 4: Create and return output
        {
            return IdentityVerificationLibrary.createVerificationOutput(header.attestationId, vcAndDiscloseProof, indices, userIdentifier);
        }
    }

    // ====================================================
    // Internal View Functions
    // ====================================================

    /**
     * @notice Gets verification config from V2 storage
     * @param configId The configuration identifier
     * @return The verification configuration
     */
    function getVerificationConfigV2(
        bytes32 configId
    ) public view virtual onlyProxy returns (SelfStructs.VerificationConfigV2 memory) {
        IdentityVerificationHubV2Storage storage $v2 = _getIdentityVerificationHubV2Storage();
        return $v2._v2VerificationConfigs[configId];
    }

    /**
     * @notice Gets verification config by configId
     */
    function _getVerificationConfigById(bytes32 configId) internal view returns (bytes memory config) {
        IdentityVerificationHubV2Storage storage $v2 = _getIdentityVerificationHubV2Storage();
        SelfStructs.VerificationConfigV2 memory verificationConfig = $v2._v2VerificationConfigs[configId];
        config = GenericFormatter.formatV2Config(verificationConfig);
        if (generateConfigId(verificationConfig) != configId) {
            revert IdentityVerificationLibrary.ConfigNotSet();
        }
        return config;
    }

    /**
     * @notice Verifies the register circuit proof.
     * @dev Uses the register circuit verifier specified by registerCircuitVerifierId.
     * @param attestationId The attestation ID.
     * @param registerCircuitVerifierId The identifier for the register circuit verifier.
     * @param registerCircuitProof The register circuit proof data.
     */
    function _verifyRegisterProof(
        bytes32 attestationId,
        uint256 registerCircuitVerifierId,
        GenericProofStruct memory registerCircuitProof
    ) internal view {
        IdentityVerificationHubStorage storage $ = _getIdentityVerificationHubStorage();
        address verifier = $._registerCircuitVerifiers[attestationId][registerCircuitVerifierId];
        if (verifier == address(0)) {
            revert IdentityVerificationLibrary.NoVerifierSet();
        }

        if (attestationId == AttestationId.E_PASSPORT) {
            if (
                !IIdentityRegistryV1($._registries[attestationId]).checkDscKeyCommitmentMerkleRoot(
                    registerCircuitProof.pubSignals[CircuitConstantsV2.REGISTER_MERKLE_ROOT_INDEX]
                )
            ) {
                revert IdentityVerificationLibrary.InvalidDscCommitmentRoot();
            }
        } else if (attestationId == AttestationId.EU_ID_CARD) {
            if (
                !IIdentityRegistryIdCardV1($._registries[attestationId]).checkDscKeyCommitmentMerkleRoot(
                    registerCircuitProof.pubSignals[CircuitConstantsV2.REGISTER_MERKLE_ROOT_INDEX]
                )
            ) {
                revert IdentityVerificationLibrary.InvalidDscCommitmentRoot();
            }
        } else if (attestationId == AttestationId.AADHAAR) {
            uint256 timestamp = registerCircuitProof.pubSignals[CircuitConstantsV2.AADHAAR_TIMESTAMP_INDEX];
            if (timestamp < (block.timestamp - (AADHAAR_REGISTRATION_WINDOW * 1 minutes))) {
                revert IdentityVerificationLibrary.InvalidUidaiTimestamp(block.timestamp, timestamp);
            }
            if (timestamp > (block.timestamp + (AADHAAR_REGISTRATION_WINDOW * 1 minutes))) {
                revert IdentityVerificationLibrary.InvalidUidaiTimestamp(block.timestamp, timestamp);
            }

            if (
                !IIdentityRegistryAadhaarV1($._registries[attestationId]).checkUidaiPubkey(
                    registerCircuitProof.pubSignals[CircuitConstantsV2.AADHAAR_UIDAI_PUBKEY_COMMITMENT_INDEX]
                )
            ) {
                revert IdentityVerificationLibrary.InvalidPubkey();
            }
        } else {
            revert IdentityVerificationLibrary.InvalidAttestationId();
        }

        if (attestationId == AttestationId.E_PASSPORT || attestationId == AttestationId.EU_ID_CARD) {
            require(registerCircuitProof.pubSignals.length == 3, "Invalid pubSignals length");
            uint256[3] memory pubSignals = [
                registerCircuitProof.pubSignals[0],
                registerCircuitProof.pubSignals[1],
                registerCircuitProof.pubSignals[2]
            ];
            if (
                !IRegisterCircuitVerifier(verifier).verifyProof(
                    registerCircuitProof.a,
                    registerCircuitProof.b,
                    registerCircuitProof.c,
                    pubSignals
                )
            ) {
                revert IdentityVerificationLibrary.InvalidRegisterProof();
            }
        } else if (attestationId == AttestationId.AADHAAR) {
            require(registerCircuitProof.pubSignals.length == 4, "Invalid pubSignals length");
            uint256[4] memory pubSignals = [
                registerCircuitProof.pubSignals[0],
                registerCircuitProof.pubSignals[1],
                registerCircuitProof.pubSignals[2],
                registerCircuitProof.pubSignals[3]
            ];

            if (
                !IAadhaarRegisterCircuitVerifier(verifier).verifyProof(
                    registerCircuitProof.a,
                    registerCircuitProof.b,
                    registerCircuitProof.c,
                    pubSignals
                )
            ) {
                revert IdentityVerificationLibrary.InvalidRegisterProof();
            }
        }
    }

    /**
     * @notice Verifies the passport DSC circuit proof.
     * @dev Uses the DSC circuit verifier specified by dscCircuitVerifierId.
     * @param dscCircuitVerifierId The identifier for the DSC circuit verifier.
     * @param dscCircuitProof The DSC circuit proof data.
     */
    function _verifyDscProof(
        bytes32 attestationId,
        uint256 dscCircuitVerifierId,
        IDscCircuitVerifier.DscCircuitProof memory dscCircuitProof
    ) internal view {
        IdentityVerificationHubStorage storage $ = _getIdentityVerificationHubStorage();
        address verifier = $._dscCircuitVerifiers[attestationId][dscCircuitVerifierId];
        if (verifier == address(0)) {
            revert IdentityVerificationLibrary.NoVerifierSet();
        }

        if (attestationId == AttestationId.E_PASSPORT) {
            if (
                !IIdentityRegistryV1($._registries[attestationId]).checkCscaRoot(
                    dscCircuitProof.pubSignals[CircuitConstantsV2.DSC_CSCA_ROOT_INDEX]
                )
            ) {
                revert IdentityVerificationLibrary.InvalidCscaRoot();
            }
        } else if (attestationId == AttestationId.EU_ID_CARD) {
            if (
                !IIdentityRegistryIdCardV1($._registries[attestationId]).checkCscaRoot(
                    dscCircuitProof.pubSignals[CircuitConstantsV2.DSC_CSCA_ROOT_INDEX]
                )
            ) {
                revert IdentityVerificationLibrary.InvalidCscaRoot();
            }
        } else {
            revert IdentityVerificationLibrary.InvalidAttestationId();
        }

        if (
            !IDscCircuitVerifier(verifier).verifyProof(
                dscCircuitProof.a,
                dscCircuitProof.b,
                dscCircuitProof.c,
                dscCircuitProof.pubSignals
            )
        ) {
            revert IdentityVerificationLibrary.InvalidDscProof();
        }
    }



    /**
     * @notice Performs identity commitment root verification
     */
    function _performRootCheck(
        bytes32 attestationId,
        GenericProofStruct memory vcAndDiscloseProof,
        CircuitConstantsV2.DiscloseIndices memory indices
    ) internal view {
        IdentityVerificationHubStorage storage $ = _getIdentityVerificationHubStorage();
        uint256 merkleRoot = vcAndDiscloseProof.pubSignals[indices.merkleRootIndex];

        address registryAddress = $._registries[attestationId];

        if (registryAddress == address(0)) {
            revert("Registry not set for attestation ID");
        }

        if (attestationId == AttestationId.E_PASSPORT) {
            if (!IIdentityRegistryV1($._registries[attestationId]).checkIdentityCommitmentRoot(merkleRoot)) {
                revert IdentityVerificationLibrary.InvalidIdentityCommitmentRoot();
            }
        } else if (attestationId == AttestationId.EU_ID_CARD) {
            if (!IIdentityRegistryIdCardV1($._registries[attestationId]).checkIdentityCommitmentRoot(merkleRoot)) {
                revert IdentityVerificationLibrary.InvalidIdentityCommitmentRoot();
            }
        } else if (attestationId == AttestationId.AADHAAR) {
            if (!IIdentityRegistryAadhaarV1($._registries[attestationId]).checkIdentityCommitmentRoot(merkleRoot)) {
                revert IdentityVerificationLibrary.InvalidIdentityCommitmentRoot();
            }
        } else {
            revert IdentityVerificationLibrary.InvalidAttestationId();
        }
    }

    function _performOfacCheck(
        bytes32 attestationId,
        GenericProofStruct memory vcAndDiscloseProof,
        CircuitConstantsV2.DiscloseIndices memory indices
    ) internal view {
        IdentityVerificationHubStorage storage $ = _getIdentityVerificationHubStorage();

        if (attestationId == AttestationId.E_PASSPORT) {
            if (
                !IIdentityRegistryV1($._registries[attestationId]).checkOfacRoots(
                    vcAndDiscloseProof.pubSignals[indices.passportNoSmtRootIndex],
                    vcAndDiscloseProof.pubSignals[indices.namedobSmtRootIndex],
                    vcAndDiscloseProof.pubSignals[indices.nameyobSmtRootIndex]
                )
            ) {
                revert IdentityVerificationLibrary.InvalidOfacRoots();
            }
        } else if (attestationId == AttestationId.EU_ID_CARD) {
            if (
                !IIdentityRegistryIdCardV1($._registries[attestationId]).checkOfacRoots(
                    vcAndDiscloseProof.pubSignals[indices.namedobSmtRootIndex],
                    vcAndDiscloseProof.pubSignals[indices.nameyobSmtRootIndex]
                )
            ) {
                revert IdentityVerificationLibrary.InvalidOfacRoots();
            }
        } else if (attestationId == AttestationId.AADHAAR) {
            if (
                !IIdentityRegistryAadhaarV1($._registries[attestationId]).checkOfacRoots(
                    vcAndDiscloseProof.pubSignals[indices.namedobSmtRootIndex],
                    vcAndDiscloseProof.pubSignals[indices.nameyobSmtRootIndex]
                )
            ) {
                revert IdentityVerificationLibrary.InvalidOfacRoots();
            }
        } else {
            revert IdentityVerificationLibrary.InvalidAttestationId();
        }
    }

    /**
     * @notice Performs Groth16 proof verification
     */
    function _performGroth16ProofVerification(
        bytes32 attestationId,
        GenericProofStruct memory vcAndDiscloseProof
    ) internal view {
        IdentityVerificationHubStorage storage $ = _getIdentityVerificationHubStorage();

        if (attestationId == AttestationId.E_PASSPORT || attestationId == AttestationId.EU_ID_CARD) {
            uint256[21] memory pubSignals;
            for (uint256 i = 0; i < 21; i++) {
                pubSignals[i] = vcAndDiscloseProof.pubSignals[i];
            }
            if (
                !IVcAndDiscloseCircuitVerifier($._discloseVerifiers[attestationId]).verifyProof(
                    vcAndDiscloseProof.a,
                    vcAndDiscloseProof.b,
                    vcAndDiscloseProof.c,
                    pubSignals
                )
            ) {
                revert IdentityVerificationLibrary.InvalidVcAndDiscloseProof();
            }
        } else if (attestationId == AttestationId.AADHAAR) {
            uint256[19] memory pubSignals;
            for (uint256 i = 0; i < 19; i++) {
                pubSignals[i] = vcAndDiscloseProof.pubSignals[i];
            }

            if (
                !IVcAndDiscloseAadhaarCircuitVerifier($._discloseVerifiers[attestationId]).verifyProof(
                    vcAndDiscloseProof.a,
                    vcAndDiscloseProof.b,
                    vcAndDiscloseProof.c,
                    pubSignals
                )
            ) {
                revert IdentityVerificationLibrary.InvalidVcAndDiscloseProof();
            }
        } else {
            revert IdentityVerificationLibrary.InvalidAttestationId();
        }
    }
}
