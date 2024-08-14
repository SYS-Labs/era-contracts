// SPDX-License-Identifier: MIT

pragma solidity 0.8.24;

import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {IChainAdmin} from "./IChainAdmin.sol";
import {IRestriction} from "./IRestriction.sol";
import { Call } from "./Common.sol";

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";

/// @author Matter Labs
/// @custom:security-contact security@matterlabs.dev
/// @notice The contract is designed to hold the `admin` role in ZKSync Chain (State Transition) contracts.
/// The owner of the contract can perform any external calls and also save the information needed for
/// the blockchain node to accept the protocol upgrade.
contract ChainAdmin is IChainAdmin, Ownable2Step {
    using EnumerableSet for EnumerableSet.AddressSet;

    modifier onlySelf {
        require(msg.sender == address(this), "Only self");
        _;
    }

    constructor(address _initialOwner) {
        // solhint-disable-next-line gas-custom-errors, reason-string
        require(_initialOwner != address(0), "Initial owner should be non zero address");
        _transferOwnership(_initialOwner);
    }

    /// @notice Mapping of protocol versions to their expected upgrade timestamps.
    /// @dev Needed for the offchain node administration to know when to start building batches with the new protocol version.
    mapping(uint256 protocolVersion => uint256 upgradeTimestamp) public protocolVersionToUpgradeTimestamp;

    EnumerableSet.AddressSet internal activeRestrictions;    

    function getRestrictions() public view returns (address[] memory) {
        return activeRestrictions.values();
    }

    function isRestrictionActive(address restriction) external view returns (bool) {
        return activeRestrictions.contains(restriction);
    }

    function addRestriction(address restriction) external onlyOwner {
        activeRestrictions.add(restriction);
    }

    // Note that it is `onlySelf` because some restrictions may not allow to remove themselves
    function removeRestriction(address restriction) external onlySelf {
        activeRestrictions.remove(restriction);
    }

    /// @notice Set the expected upgrade timestamp for a specific protocol version.
    /// @param _protocolVersion The ZKsync chain protocol version.
    /// @param _upgradeTimestamp The timestamp at which the chain node should expect the upgrade to happen.
    function setUpgradeTimestamp(uint256 _protocolVersion, uint256 _upgradeTimestamp) external onlyOwner {
        protocolVersionToUpgradeTimestamp[_protocolVersion] = _upgradeTimestamp;
        emit UpdateUpgradeTimestamp(_protocolVersion, _upgradeTimestamp);
    }

    /// @notice Execute multiple calls as part of contract administration.
    /// @param _calls Array of Call structures defining target, value, and data for each call.
    /// @param _requireSuccess If true, reverts transaction on any call failure.
    /// @dev Intended for batch processing of contract interactions, managing gas efficiency and atomicity of operations.
    function multicall(Call[] calldata _calls, bool _requireSuccess) external payable onlyOwner {
        // solhint-disable-next-line gas-custom-errors
        require(_calls.length > 0, "No calls provided");
        // solhint-disable-next-line gas-length-in-loops
        for (uint256 i = 0; i < _calls.length; ++i) {
            require(_validateCall(_calls[i]), "Unallowed call");

            // slither-disable-next-line arbitrary-send-eth
            (bool success, bytes memory returnData) = _calls[i].target.call{value: _calls[i].value}(_calls[i].data);
            if (_requireSuccess && !success) {
                // Propagate an error if the call fails.
                assembly {
                    revert(add(returnData, 0x20), mload(returnData))
                }
            }
            emit CallExecuted(_calls[i], success, returnData);
        }
    }

    /// @dev Contract might receive/hold ETH as part of the maintenance process.
    receive() external payable {}
    
    /// @notice Function that returns the current admin can perform the call.
    /// @dev By default it always returns true, but can be overridden in derived contracts.
    function _validateCall(Call calldata _call) internal view returns (bool) {
        address[] memory restrictions = getRestrictions();

        unchecked {
            for (uint256 i = 0; i < restrictions.length; i++) {
                IRestriction(restrictions[i]).validateCall(_call);
            }
        } 
    }
}
