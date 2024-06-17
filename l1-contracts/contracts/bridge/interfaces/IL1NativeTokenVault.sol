// SPDX-License-Identifier: MIT

pragma solidity 0.8.24;

import {IL1SharedBridge} from "./IL1SharedBridge.sol";

/// @title L1 Native token vault contract interface
/// @author Matter Labs
/// @custom:security-contact security@matterlabs.dev
/// @notice The NTV is an Asset Handler for the L1SharedBridge to handle native tokens
interface IL1NativeTokenVault {
    /// @notice The L1SharedBridge contract
    function L1_SHARED_BRIDGE() external view returns (IL1SharedBridge);

    /// @notice The weth contract
    function L1_WETH_TOKEN() external view returns (address);

    /// @notice Used to register a token in the vault
    function registerToken(address _l1Token) external;

    /// @notice Used to get the assetId of a token
    function getAssetId(address l1TokenAddress) external view returns (bytes32);

    /// @notice Used to get the the ERC20 data for a token
    function getERC20Getters(address _token) external view returns (bytes memory);

    /// @notice Used to get the token address of an assetId
    function tokenAddress(bytes32 assetId) external view returns (address);
}
