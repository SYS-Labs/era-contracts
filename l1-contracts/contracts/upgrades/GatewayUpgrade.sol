// SPDX-License-Identifier: MIT

pragma solidity 0.8.24;

import {Diamond} from "../state-transition/libraries/Diamond.sol";
import {BaseZkSyncUpgrade, ProposedUpgrade} from "./BaseZkSyncUpgrade.sol";

import {DataEncoding} from "../common/libraries/DataEncoding.sol";
import {ReentrancyGuard} from "../common/ReentrancyGuard.sol";

import {AdminFacet} from "../state-transition/chain-deps/facets/Admin.sol";

/// @author Matter Labs
/// @custom:security-contact security@matterlabs.dev
/// @notice This upgrade will be used to migrate Era to be part of the hyperchain ecosystem contracts.
contract GatewayUpgrade is BaseZkSyncUpgrade, AdminFacet, ReentrancyGuard {
    /// @notice The owner of the contract.
    address public owner;

    /// @notice chainID => l2LegacySharedBridge contract address.
    mapping(uint256 _chainId => address) public l2LegacySharedBridge;

    modifier onlyOwner() {
        // solhint-disable-next-line gas-custom-errors
        require(msg.sender == owner, "GW upgrade: only owner");
        _;
    }

    /// @notice to avoid parity hack
    constructor(address _owner) reentrancyGuardInitializer {
        _disableInitializers();
        owner = _owner;
    }

    /// @notice The main function that will be called by the upgrade proxy.
    /// @param _proposedUpgrade The upgrade to be executed.
    function upgrade(ProposedUpgrade calldata _proposedUpgrade) public override returns (bytes32) {
        (bytes memory l2TxDataStart, bytes memory l2TxDataFinish) = abi.decode(
            _proposedUpgrade.postUpgradeCalldata,
            (bytes, bytes)
        );

        s.baseTokenAssetId = DataEncoding.encodeNTVAssetId(block.chainid, s.baseToken);
        s.priorityTree.setup(s.priorityQueue.getTotalPriorityTxs());
        /// maybe set baseTokenAssetId in Bridgehub here

        ProposedUpgrade memory proposedUpgrade = _proposedUpgrade;
        address l2LegacyBridge = l2LegacySharedBridge[s.chainId];
        proposedUpgrade.l2ProtocolUpgradeTx.data = bytes.concat(l2TxDataStart, bytes32(l2LegacyBridge), l2TxDataFinish);
        this.upgradeExternal(proposedUpgrade);
        return Diamond.DIAMOND_INIT_SUCCESS_RETURN_VALUE;
    }

    function upgradeExternal(ProposedUpgrade calldata _proposedUpgrade) external {
        // solhint-disable-next-line gas-custom-errors
        require(msg.sender == address(this), "GatewayUpgrade: upgradeExternal");
        super.upgrade(_proposedUpgrade);
    }

    function setL2LegacySharedBridge(uint256 _chainId, address _l2LegacySharedBridge) external onlyOwner {
        l2LegacySharedBridge[_chainId] = _l2LegacySharedBridge;
    }
}
