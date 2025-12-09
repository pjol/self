// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {GenericProofStruct} from "./interfaces/IRegisterCircuitVerifier.sol";
import {SelfStructs} from "./libraries/SelfStructs.sol";
import {CircuitConstantsV2} from "./constants/CircuitConstantsV2.sol";
import {Formatter} from "./libraries/Formatter.sol";
import {GenericFormatter} from "./libraries/GenericFormatter.sol";
import {AttestationId} from "./constants/AttestationId.sol";

library IdentityVerificationLibrary {
    /**
     * @notice Emitted when the Hub V2 is successfully initialized.
     */
    event HubInitializedV2();
    /**
     * @notice Emitted when a verification config V2 is set.
     * @param configId The configuration identifier (generated from config hash).
     * @param config The verification configuration that was set.
     */
    event VerificationConfigV2Set(bytes32 indexed configId, SelfStructs.VerificationConfigV2 config);
    /**
     * @notice Emitted when the registry address is updated.
     * @param attestationId The attestation identifier.
     * @param registry The new registry address.
     */
    event RegistryUpdated(bytes32 attestationId, address registry);
    /**
     * @notice Emitted when the VC and Disclose circuit verifier is updated.
     * @param attestationId The attestation identifier.
     * @param vcAndDiscloseCircuitVerifier The new VC and Disclose circuit verifier address.
     */
    event VcAndDiscloseCircuitUpdated(bytes32 attestationId, address vcAndDiscloseCircuitVerifier);
    /**
     * @notice Emitted when a register circuit verifier is updated.
     * @param typeId The signature type id.
     * @param verifier The new verifier address for the register circuit.
     */
    event RegisterCircuitVerifierUpdated(uint256 typeId, address verifier);
    /**
     * @notice Emitted when a DSC circuit verifier is updated.
     * @param typeId The signature type id.
     * @param verifier The new verifier address for the DSC circuit.
     */
    event DscCircuitVerifierUpdated(uint256 typeId, address verifier);

    /**
     * @notice Emitted when a verification is performed.
     * @param requestor The contract that initiated the verification request.
     * @param contractVersion The contract version used for verification output formatting.
     * @param attestationId The attestation identifier (E_PASSPORT or EU_ID_CARD).
     * @param destChainId The destination chain ID.
     * @param configId The configuration ID.
     * @param userIdentifier The user identifier.
     * @param output The formatted verification output containing proof results.
     * @param userDataToPass The user data passed through to the verification result handler.
     */
    event DisclosureVerified(
        address indexed requestor,
        uint8 indexed contractVersion,
        bytes32 indexed attestationId,
        uint256 destChainId,
        bytes32 configId,
        uint256 userIdentifier,
        bytes output,
        bytes userDataToPass
    );

    // ====================================================
    // Errors
    // ====================================================

    /// @notice Thrown when arrays have mismatched lengths in batch operations.
    /// @dev Ensures that all input arrays have the same length for batch updates.
    error LengthMismatch();

    /// @notice Thrown when no verifier is set for a given signature type.
    /// @dev Indicates that the mapping lookup for the verifier returned the zero address.
    error NoVerifierSet();

    /// @notice Thrown when the current date in the proof is not within the valid range.
    /// @dev Ensures that the provided proof's date is within one day of the expected start time.
    error CurrentDateNotInValidRange();

    /// @notice Thrown when the register circuit proof is invalid.
    /// @dev The register circuit verifier did not validate the provided proof.
    error InvalidRegisterProof();

    /// @notice Thrown when the DSC circuit proof is invalid.
    /// @dev The DSC circuit verifier did not validate the provided proof.
    error InvalidDscProof();

    /// @notice Thrown when the VC and Disclose proof is invalid.
    /// @dev The VC and Disclose circuit verifier did not validate the provided proof.
    error InvalidVcAndDiscloseProof();

    /// @notice Thrown when the provided identity commitment root is invalid.
    /// @dev Used in proofs to ensure that the identity commitment root matches the expected value in the registry.
    error InvalidIdentityCommitmentRoot();

    /// @notice Thrown when the provided DSC commitment root is invalid.
    /// @dev Used in proofs to ensure that the DSC commitment root matches the expected value in the registry.
    error InvalidDscCommitmentRoot();

    /// @notice Thrown when the provided CSCA root is invalid.
    /// @dev Indicates that the CSCA root from the DSC proof does not match the expected CSCA root.
    error InvalidCscaRoot();

    /// @notice Thrown when an invalid attestation ID is provided.
    /// @dev The attestation ID must be a supported type (e.g., E_PASSPORT or EU_ID_CARD).
    error InvalidAttestationId();

    /// @notice Thrown when the scope in the header doesn't match the scope in the proof.
    /// @dev Ensures that the scope value in the header matches the scope value in the proof.
    error ScopeMismatch();

    /// @notice Thrown when cross-chain verification is attempted but not yet supported.
    /// @dev Cross-chain bridging functionality is not implemented yet.
    error CrossChainIsNotSupportedYet();

    /// @notice Thrown when the input data is too short for decoding.
    /// @dev The input data must be at least 97 bytes (1 + 31 + 32 + 32 + 1 minimum).
    error InputTooShort();

    /// @notice Thrown when the user context data is too short for decoding.
    /// @dev The user context data must be at least 96 bytes (32 + 32 + 32 minimum).
    error UserContextDataTooShort();

    /// @notice Thrown when the user identifier hash does not match the proof user identifier.
    /// @dev Ensures that the user context data hash matches the user identifier in the proof.
    error InvalidUserIdentifierInProof();

    /// @notice Thrown when the verification config is not set.
    /// @dev Ensures that the verification config is set before performing verification.
    error ConfigNotSet();

    /// @notice Thrown when the pubkey is not valid.
    /// @dev Ensures that the pubkey is valid.
    error InvalidPubkey();

    /// @notice Thrown when the timestamp is invalid.
    /// @dev Ensures that the timestamp is within 20 minutes of the current block timestamp.
    error InvalidUidaiTimestamp(uint256 blockTimestamp, uint256 timestamp);

    /// @notice Thrown when the attestationId in the proof doesn't match the header.
    /// @dev Ensures that the attestationId in the proof matches the header.
    error AttestationIdMismatch();

    /// @notice Thrown when the ofac roots don't match.
    /// @dev Ensures that the ofac roots match.
    error InvalidOfacRoots();


    /**
     * @notice Performs current date validation
     */
    function performCurrentDateCheck(
        GenericProofStruct memory vcAndDiscloseProof,
        CircuitConstantsV2.DiscloseIndices memory indices
    ) external view {
        uint256[6] memory dateNum;
        for (uint256 i = 0; i < 6; i++) {
            dateNum[i] = vcAndDiscloseProof.pubSignals[indices.currentDateIndex + i];
        }

        uint256 currentTimestamp = Formatter.proofDateToUnixTimestamp(dateNum);
        uint256 startOfDay = _getStartOfDayTimestamp();
        uint256 endOfDay = startOfDay + 1 days - 1;

        if (currentTimestamp < startOfDay - 1 days + 1 || currentTimestamp > endOfDay + 1 days) {
            revert IdentityVerificationLibrary.CurrentDateNotInValidRange();
        }
    }

    function performNumericCurrentDateCheck(
        GenericProofStruct memory vcAndDiscloseProof,
        CircuitConstantsV2.DiscloseIndices memory indices
    ) external view {
        // date is going to be 2025, 12, 13
        uint256[3] memory dateNum;
        dateNum[0] = vcAndDiscloseProof.pubSignals[indices.currentDateIndex];
        dateNum[1] = vcAndDiscloseProof.pubSignals[indices.currentDateIndex + 1];
        dateNum[2] = vcAndDiscloseProof.pubSignals[indices.currentDateIndex + 2];

        uint256 currentTimestamp = Formatter.proofDateToUnixTimestampNumeric(dateNum);
        uint256 startOfDay = _getStartOfDayTimestamp();
        uint256 endOfDay = startOfDay + 1 days - 1;

        if (currentTimestamp < startOfDay - 1 days + 1 || currentTimestamp > endOfDay + 1 days) {
            revert IdentityVerificationLibrary.CurrentDateNotInValidRange();
        }
    }


    /**
     * @notice Decodes userContextData to extract configId, destChainId, and userIdentifier
     * @param userContextData User-defined data in format: | 32 bytes configId | 32 bytes destChainId | 32 bytes userIdentifier | data |
     * @return configId The configuration identifier
     * @return destChainId The destination chain identifier
     * @return userIdentifier The user identifier
     * @return remainingData The remaining data after the first 96 bytes
     */
    function decodeUserContextData(
        bytes calldata userContextData
    )
        external
        pure
        returns (bytes32 configId, uint256 destChainId, uint256 userIdentifier, bytes calldata remainingData)
    {
        if (userContextData.length < 96) {
            revert IdentityVerificationLibrary.UserContextDataTooShort();
        }
        configId = bytes32(userContextData[0:32]);
        destChainId = uint256(bytes32(userContextData[32:64]));
        userIdentifier = uint256(bytes32(userContextData[64:96]));
        remainingData = userContextData[96:];
    }

    /**
     * @notice Formats verification output based on contract version.
     * @dev Converts the generic disclosure output to the appropriate struct format based on version.
     * @param contractVersion The contract version to determine output format.
     * @param genericDiscloseOutput The generic disclosure output to format.
     * @return output The formatted output as bytes.
     */
    function formatVerificationOutput(
        uint256 contractVersion,
        SelfStructs.GenericDiscloseOutputV2 memory genericDiscloseOutput
    ) external pure returns (bytes memory output) {
        if (contractVersion == 2) {
            output = GenericFormatter.toV2Struct(genericDiscloseOutput);
        }
    }



    /**
     * @notice Retrieves the timestamp for the start of the current day.
     * @dev Calculated by subtracting the remainder of block.timestamp modulo 1 day.
     * @return The Unix timestamp representing the start of the day.
     */
    function _getStartOfDayTimestamp() internal view returns (uint256) {
        return block.timestamp - (block.timestamp % 1 days);
    }


    // ====================================================
    // external Pure Functions
    // ====================================================

    /**
     * @notice Decodes the input data to extract the header and proof data.
     * @param baseVerificationInput The input data to decode. Format: | 1 byte contractVersion | 31 bytes buffer | 32 bytes scope | 32 bytes attestationId | user defined data |
     * @return header The header of the input data.
     * @return proofData The proof data of the input data.
     */
    function decodeInput(
        bytes calldata baseVerificationInput
    ) external pure returns (SelfStructs.HubInputHeader memory header, bytes calldata proofData) {
        if (baseVerificationInput.length < 97) {
            revert IdentityVerificationLibrary.InputTooShort();
        }
        header.contractVersion = uint8(baseVerificationInput[0]);
        header.scope = uint256(bytes32(baseVerificationInput[32:64]));
        header.attestationId = bytes32(baseVerificationInput[64:96]);
        proofData = baseVerificationInput[96:];
    }

    /**
     * @notice Creates verification output based on attestation type.
     * @dev Routes to the appropriate output creation function based on the attestation ID.
     * @param attestationId The attestation identifier (passport or EU ID card).
     * @param vcAndDiscloseProof The VC and Disclose proof data.
     * @param indices The circuit-specific indices for extracting proof values.
     * @param userIdentifier The user identifier to include in the output.
     * @return The encoded verification output.
     */
    function createVerificationOutput(
        bytes32 attestationId,
        GenericProofStruct memory vcAndDiscloseProof,
        CircuitConstantsV2.DiscloseIndices memory indices,
        uint256 userIdentifier
    ) external pure returns (bytes memory) {
        if (attestationId == AttestationId.E_PASSPORT) {
            return _createPassportOutput(vcAndDiscloseProof, indices, attestationId, userIdentifier);
        } else if (attestationId == AttestationId.EU_ID_CARD) {
            return _createEuIdOutput(vcAndDiscloseProof, indices, attestationId, userIdentifier);
        } else if (attestationId == AttestationId.AADHAAR) {
            return _createAadhaarOutput(vcAndDiscloseProof, indices, attestationId, userIdentifier);
        } else {
            revert IdentityVerificationLibrary.InvalidAttestationId();
        }
    }

    /**
     * @notice Creates passport output struct.
     * @dev Constructs a PassportOutput struct from the proof data and encodes it.
     * @param vcAndDiscloseProof The VC and Disclose proof containing passport data.
     * @param indices The circuit-specific indices for extracting proof values.
     * @param attestationId The attestation identifier.
     * @param userIdentifier The user identifier.
     * @return The encoded PassportOutput struct.
     */
    function _createPassportOutput(
        GenericProofStruct memory vcAndDiscloseProof,
        CircuitConstantsV2.DiscloseIndices memory indices,
        bytes32 attestationId,
        uint256 userIdentifier
    ) internal pure returns (bytes memory) {
        SelfStructs.PassportOutput memory passportOutput;
        passportOutput.attestationId = uint256(attestationId);
        passportOutput.userIdentifier = userIdentifier;
        passportOutput.nullifier = vcAndDiscloseProof.pubSignals[indices.nullifierIndex];

        // Extract revealed data
        uint256[3] memory revealedDataPacked;
        for (uint256 i = 0; i < 3; i++) {
            revealedDataPacked[i] = vcAndDiscloseProof.pubSignals[indices.revealedDataPackedIndex + i];
        }
        passportOutput.revealedDataPacked = Formatter.fieldElementsToBytes(revealedDataPacked);

        // Extract forbidden countries list
        for (uint256 i = 0; i < 4; i++) {
            passportOutput.forbiddenCountriesListPacked[i] = vcAndDiscloseProof.pubSignals[
                indices.forbiddenCountriesListPackedIndex + i
            ];
        }

        return abi.encode(passportOutput);
    }

    /**
     * @notice Creates EU ID output struct.
     * @dev Constructs an EuIdOutput struct from the proof data and encodes it.
     * @param vcAndDiscloseProof The VC and Disclose proof containing EU ID card data.
     * @param indices The circuit-specific indices for extracting proof values.
     * @param attestationId The attestation identifier.
     * @param userIdentifier The user identifier.
     * @return The encoded EuIdOutput struct.
     */
    function _createEuIdOutput(
        GenericProofStruct memory vcAndDiscloseProof,
        CircuitConstantsV2.DiscloseIndices memory indices,
        bytes32 attestationId,
        uint256 userIdentifier
    ) internal pure returns (bytes memory) {
        SelfStructs.EuIdOutput memory euIdOutput;
        euIdOutput.attestationId = uint256(attestationId);
        euIdOutput.userIdentifier = userIdentifier;
        euIdOutput.nullifier = vcAndDiscloseProof.pubSignals[indices.nullifierIndex];

        // Extract revealed data
        uint256[4] memory revealedDataPacked;
        for (uint256 i = 0; i < 4; i++) {
            revealedDataPacked[i] = vcAndDiscloseProof.pubSignals[indices.revealedDataPackedIndex + i];
        }
        euIdOutput.revealedDataPacked = Formatter.fieldElementsToBytesIdCard(revealedDataPacked);

        // Extract forbidden countries list
        for (uint256 i = 0; i < 4; i++) {
            euIdOutput.forbiddenCountriesListPacked[i] = vcAndDiscloseProof.pubSignals[
                indices.forbiddenCountriesListPackedIndex + i
            ];
        }

        return abi.encode(euIdOutput);
    }

    function _createAadhaarOutput(
        GenericProofStruct memory vcAndDiscloseProof,
        CircuitConstantsV2.DiscloseIndices memory indices,
        bytes32 attestationId,
        uint256 userIdentifier
    ) internal pure returns (bytes memory) {
        SelfStructs.AadhaarOutput memory aadhaarOutput;
        aadhaarOutput.attestationId = uint256(attestationId);
        aadhaarOutput.userIdentifier = userIdentifier;
        aadhaarOutput.nullifier = vcAndDiscloseProof.pubSignals[indices.nullifierIndex];

        uint256[4] memory revealedDataPacked;
        for (uint256 i = 0; i < 4; i++) {
            revealedDataPacked[i] = vcAndDiscloseProof.pubSignals[indices.revealedDataPackedIndex + i];
        }
        aadhaarOutput.revealedDataPacked = Formatter.fieldElementsToBytesAadhaar(revealedDataPacked);

        for (uint256 i = 0; i < 4; i++) {
            aadhaarOutput.forbiddenCountriesListPacked[i] = vcAndDiscloseProof.pubSignals[
                indices.forbiddenCountriesListPackedIndex + i
            ];
        }

        return abi.encode(aadhaarOutput);
    }

    /**
     * @notice Decodes VC and Disclose proof from bytes data.
     * @dev Simple wrapper around abi.decode for type safety and clarity.
     * @param data The encoded proof data.
     * @return The decoded VcAndDiscloseProof struct.
     */
    function decodeVcAndDiscloseProof(bytes memory data) external pure returns (GenericProofStruct memory) {
        return abi.decode(data, (GenericProofStruct));
    }

    /**
     * @notice Performs user identifier validation.
     * @dev Validates that the user identifier in the proof matches the hash of the user context data.
     * Uses SHA256 followed by RIPEMD160 hashing for consistency with circuit implementation.
     * @param userContextData The user context data to hash and compare.
     * @param vcAndDiscloseProof The VC and Disclose proof containing the user identifier.
     * @param indices The circuit-specific indices for extracting the user identifier from proof.
     */
    function performUserIdentifierCheck(
        bytes calldata userContextData,
        GenericProofStruct memory vcAndDiscloseProof,
        CircuitConstantsV2.DiscloseIndices memory indices
    ) external pure {
        // Get the user identifier index for this attestation type
        uint256 proofUserIdentifier = vcAndDiscloseProof.pubSignals[indices.userIdentifierIndex];

        bytes memory userContextDataWithoutConfigId = userContextData[32:];
        bytes32 sha256Hash = sha256(userContextDataWithoutConfigId);
        bytes20 ripemdHash = ripemd160(abi.encodePacked(sha256Hash));
        uint256 hashedValue = uint256(uint160(ripemdHash));

        if (hashedValue != proofUserIdentifier) {
            revert IdentityVerificationLibrary.InvalidUserIdentifierInProof();
        }
    }


    /**
     * @notice Performs attestationId check
     */
    function performAttestationIdCheck(
        bytes32 attestationId,
        GenericProofStruct memory vcAndDiscloseProof,
        CircuitConstantsV2.DiscloseIndices memory indices
    ) external pure {
        if (vcAndDiscloseProof.pubSignals[indices.attestationIdIndex] != uint256(attestationId)) {
            revert IdentityVerificationLibrary.AttestationIdMismatch();
        }
    }

        /**
     * @notice Performs scope validation
     */
    function performScopeCheck(
        uint256 headerScope,
        GenericProofStruct memory vcAndDiscloseProof,
        CircuitConstantsV2.DiscloseIndices memory indices
    ) external pure {
        // Get scope from proof using the scope index from indices
        uint256 proofScope = vcAndDiscloseProof.pubSignals[indices.scopeIndex];

        if (headerScope != proofScope) {
            revert IdentityVerificationLibrary.ScopeMismatch();
        }
    }

}
