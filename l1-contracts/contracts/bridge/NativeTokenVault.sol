// SPDX-License-Identifier: MIT

pragma solidity 0.8.24;

// solhint-disable reason-string, gas-custom-errors

import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import {BeaconProxy} from "@openzeppelin/contracts/proxy/beacon/BeaconProxy.sol";
import {UpgradeableBeacon} from "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";

import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

import {IStandardToken} from "./interfaces/IStandardToken.sol";
import {INativeTokenVault} from "./interfaces/INativeTokenVault.sol";
import {IAssetHandler} from "./interfaces/IAssetHandler.sol";
import {IAssetRouterBase} from "./interfaces/IAssetRouterBase.sol";
import {IL1Nullifier} from "./interfaces/IL1Nullifier.sol";

import {WrappedStandardERC20} from "../common/WrappedStandardERC20.sol";
import {ETH_TOKEN_ADDRESS} from "../common/Config.sol";
import {L2_NATIVE_TOKEN_VAULT_ADDRESS} from "../common/L2ContractAddresses.sol";

import {EmptyAddress, EmptyBytes32, AddressMismatch, AssetIdMismatch, DeployFailed, AmountMustBeGreaterThanZero, InvalidCaller} from "../common/L1ContractErrors.sol";

/// @author Matter Labs
/// @custom:security-contact security@matterlabs.dev
/// @dev Vault holding L1 native ETH and ERC20 tokens bridged into the ZK chains.
/// @dev Designed for use with a proxy for upgradability.
abstract contract NativeTokenVault is INativeTokenVault, IAssetHandler, Ownable2StepUpgradeable, PausableUpgradeable {
    using SafeERC20 for IERC20;

    /// @dev Contract that stores the implementation address for token.
    /// @dev For more details see https://docs.openzeppelin.com/contracts/3.x/api/proxy#UpgradeableBeacon.
    UpgradeableBeacon public wrappedTokenBeacon;

    /// @dev The address of the WETH token.
    address public immutable override WETH_TOKEN;

    /// @dev L1 Shared Bridge smart contract that handles communication with its counterparts on L2s
    IAssetRouterBase public immutable override ASSET_ROUTER;

    /// @dev Maps token balances for each chain to prevent unauthorized spending across ZK chains.
    /// This serves as a security measure until hyperbridging is implemented.
    /// NOTE: this function may be removed in the future, don't rely on it!
    mapping(uint256 chainId => mapping(address l1Token => uint256 balance)) public chainBalance;

    /// @dev A mapping assetId => tokenAddress
    mapping(bytes32 assetId => address tokenAddress) public tokenAddress;

    /// @dev A mapping assetId => isTokenWrapped
    mapping(bytes32 assetId => bool wrapped) public isTokenWrapped;

    /// @notice Checks that the message sender is the bridgehub.
    modifier onlyBridge() {
        require(msg.sender == address(ASSET_ROUTER), "NTV not AR");
        _;
    }

    /// @dev Contract is expected to be used as proxy implementation.
    /// @dev Disable the initialization to prevent Parity hack.
    /// @param _wethToken Address of WETH on deployed chain
    /// @param _assetRouter Address of Asset Router contract on deployed chain
    constructor(address _wethToken, IAssetRouterBase _assetRouter) {
        _disableInitializers();
        ASSET_ROUTER = _assetRouter;
        WETH_TOKEN = _wethToken;
    }

    /// @notice Sets token beacon used by wrapped ERC20 tokens deployed by NTV.
    /// @dev we don't call this in the constructor, as we need to provide factory deps
    function setWrappedTokenBeacon() external {
        if (address(wrappedTokenBeacon) != address(0)) {
            revert AddressMismatch(address(wrappedTokenBeacon), address(0));
        }
        address l2StandardToken = address(new WrappedStandardERC20{salt: bytes32(0)}());
        wrappedTokenBeacon = new UpgradeableBeacon{salt: bytes32(0)}(l2StandardToken);
        wrappedTokenBeacon.transferOwnership(owner());
    }

    /// @dev Initializes a contract for later use. Expected to be used in the proxy.
    /// @param _owner Address which can change pause / unpause the NTV.
    /// implementation. The owner is the Governor and separate from the ProxyAdmin from now on, so that the Governor can call the bridge.
    function initialize(address _owner) external initializer {
        require(_owner != address(0), "NTV owner 0");
        _transferOwnership(_owner);
    }

    /// @dev Accepts ether only from the Shared Bridge.
    receive() external payable {
        require(address(ASSET_ROUTER) == msg.sender, "NTV: ETH only accepted from Asset Router");
    }

    /// @notice Registers tokens within the NTV.
    /// @dev The goal was to allow bridging native tokens automatically, by registering them on the fly.
    /// @notice Allows the bridge to register a token address for the vault.
    /// @notice No access control is ok, since the bridging of tokens should be permissionless. This requires permissionless registration.
    function registerToken(address _nativeToken) external {
        require(_nativeToken != WETH_TOKEN, "NTV: WETH deposit not supported");
        require(_nativeToken == ETH_TOKEN_ADDRESS || _nativeToken.code.length > 0, "NTV: empty token");
        bytes32 assetId = getAssetId(_nativeToken);
        ASSET_ROUTER.setAssetHandlerAddress(bytes32(uint256(uint160(_nativeToken))), address(this));
        tokenAddress[assetId] = _nativeToken;
    }

    ///  @inheritdoc IAssetHandler
    function bridgeMint(
        uint256 _chainId,
        bytes32 _assetId,
        bytes calldata _transferData
    ) external payable override onlyBridge whenNotPaused returns (address receiver) {
        // Either it was locked before, therefore is not zero, or it is sent from remote chain and standard erc20 will be deployed
        address token = tokenAddress[_assetId];
        uint256 amount;

        if (chainBalance[_chainId][token] > 0) {
            (amount, receiver) = abi.decode(_transferData, (uint256, address));
            // Check that the chain has sufficient balance
            require(chainBalance[_chainId][token] >= amount, "NTV not enough funds 2"); // not enough funds
            chainBalance[_chainId][token] -= amount;

            if (token == ETH_TOKEN_ADDRESS) {
                bool callSuccess;
                // Low-level assembly call, to avoid any memory copying (save gas)
                assembly {
                    callSuccess := call(gas(), receiver, amount, 0, 0, 0, 0)
                }
                require(callSuccess, "NTV: withdrawal failed, no funds or cannot transfer to receiver");
            } else {
                // Withdraw funds
                IERC20(token).safeTransfer(receiver, amount);
            }
            // solhint-disable-next-line func-named-parameters
            emit BridgeMint(_chainId, _assetId, receiver, amount);
        } else {
            bytes memory erc20Data;
            address originToken;

            (, amount, receiver, erc20Data, originToken) = abi.decode(
                _transferData,
                (address, uint256, address, bytes, address)
            );
            address expectedToken = wrappedTokenAddress(originToken);
            if (token == address(0)) {
                bytes32 expectedAssetId = keccak256(
                    abi.encode(_chainId, L2_NATIVE_TOKEN_VAULT_ADDRESS, bytes32(uint256(uint160(originToken))))
                );
                if (_assetId != expectedAssetId) {
                    // Make sure that a NativeTokenVault sent the message
                    revert AssetIdMismatch(_assetId, expectedAssetId);
                }
                address deployedToken = _deployWrappedToken(originToken, erc20Data);
                if (deployedToken != expectedToken) {
                    revert AddressMismatch(expectedToken, deployedToken);
                }
                isTokenWrapped[_assetId] = true;
                tokenAddress[_assetId] = expectedToken;
            }

            IStandardToken(expectedToken).bridgeMint(receiver, amount);
        }
        emit BridgeMint(_chainId, _assetId, receiver, amount);
    }

    /// @inheritdoc IAssetHandler
    /// @notice Allows bridgehub to acquire mintValue for L1->L2 transactions.
    /// @dev In case of native token vault _transferData is the tuple of _depositAmount and _receiver.
    function bridgeBurn(
        uint256 _chainId,
        uint256,
        bytes32 _assetId,
        address _prevMsgSender,
        bytes calldata _transferData
    ) external payable override onlyBridge whenNotPaused returns (bytes memory bridgeMintData) {
        if (isTokenWrapped[_assetId]) {
            (uint256 _depositAmount, address _receiver) = abi.decode(_transferData, (uint256, address));

            uint256 amount;
            address nativeToken = tokenAddress[_assetId];
            if (nativeToken == ETH_TOKEN_ADDRESS) {
                amount = msg.value;

                // In the old SDK/contracts the user had to always provide `0` as the deposit amount for ETH token, while
                // ultimately the provided `msg.value` was used as the deposit amount. This check is needed for backwards compatibility.
                if (_depositAmount == 0) {
                    _depositAmount = amount;
                }

                require(_depositAmount == amount, "L1NTV: msg.value not equal to amount");
            } else {
                // The Bridgehub also checks this, but we want to be sure
                require(msg.value == 0, "NTV m.v > 0 b d.it");
                amount = _depositAmount;

                uint256 expectedDepositAmount = _depositFunds(_prevMsgSender, IERC20(nativeToken), _depositAmount); // note if _prevMsgSender is this contract, this will return 0. This does not happen.
                require(expectedDepositAmount == _depositAmount, "5T"); // The token has non-standard transfer logic
            }
            require(amount != 0, "6T"); // empty deposit amount

            chainBalance[_chainId][nativeToken] += amount;

            // solhint-disable-next-line func-named-parameters
            bridgeMintData = abi.encode(amount, _prevMsgSender, _receiver, getERC20Getters(nativeToken), nativeToken);
            // solhint-disable-next-line func-named-parameters
            emit BridgeBurn(_chainId, _assetId, _prevMsgSender, _receiver, amount);
        } else {
            (uint256 _amount, address _receiver) = abi.decode(_transferData, (uint256, address));
            if (_amount == 0) {
                // "Amount cannot be zero");
                revert AmountMustBeGreaterThanZero();
            }

            address wrappedToken = tokenAddress[_assetId];
            IStandardToken(wrappedToken).bridgeBurn(_prevMsgSender, _amount);

            // solhint-disable-next-line func-named-parameters
            emit BridgeBurn(_chainId, _assetId, _prevMsgSender, _receiver, _amount);
            bridgeMintData = _transferData;
        }
    }

    /// @notice Transfers tokens from the depositor address to the smart contract address.
    /// @param _from The address of the depositor.
    /// @param _token The ERC20 token to be transferred.
    /// @param _amount The amount to be transferred.
    /// @return The difference between the contract balance before and after the transferring of funds.
    function _depositFunds(address _from, IERC20 _token, uint256 _amount) internal returns (uint256) {
        uint256 balanceBefore = _token.balanceOf(address(this));
        address from = _from;
        // in the legacy scenario the SharedBridge was granting the allowance, we have to transfer from them instead of the user
        if (
            _token.allowance(address(ASSET_ROUTER), address(this)) >= _amount &&
            _token.allowance(_from, address(this)) < _amount
        ) {
            from = address(ASSET_ROUTER);
        }
        // slither-disable-next-line arbitrary-send-erc20
        _token.safeTransferFrom(from, address(this), _amount);
        uint256 balanceAfter = _token.balanceOf(address(this));

        return balanceAfter - balanceBefore;
    }

    /// @notice Receives and parses (name, symbol, decimals) from the token contract.
    /// @param _token The address of token of interest.
    /// @return Returns encoded name, symbol, and decimals for specific token.
    function getERC20Getters(address _token) public view returns (bytes memory) {
        if (_token == ETH_TOKEN_ADDRESS) {
            bytes memory name = bytes("Ether");
            bytes memory symbol = bytes("ETH");
            bytes memory decimals = abi.encode(uint8(18));
            return abi.encode(name, symbol, decimals); // when depositing eth to a non-eth based chain it is an ERC20
        }

        (, bytes memory data1) = _token.staticcall(abi.encodeCall(IERC20Metadata.name, ()));
        (, bytes memory data2) = _token.staticcall(abi.encodeCall(IERC20Metadata.symbol, ()));
        (, bytes memory data3) = _token.staticcall(abi.encodeCall(IERC20Metadata.decimals, ()));
        return abi.encode(data1, data2, data3);
    }

    /// @notice Returns the parsed assetId.
    /// @param _nativeToken The address of the token to be parsed.
    /// @return The asset ID.
    function getAssetId(address _nativeToken) public view override returns (bytes32) {
        return keccak256(abi.encode(block.chainid, L2_NATIVE_TOKEN_VAULT_ADDRESS, _nativeToken));
    }

    /// @notice Calculates the wrapped token address corresponding to native token counterpart.
    /// @param _nativeToken The address of native token.
    /// @return The address of wrapped token.
    function wrappedTokenAddress(address _nativeToken) public view virtual override returns (address);

    /// @notice Deploys and initializes the wrapped token for the native counterpart.
    /// @param _nativeToken The address of native token.
    /// @param _erc20Data The ERC20 metadata of the token deployed.
    /// @return The address of the beacon proxy (wrapped / bridged token).
    function _deployWrappedToken(address _nativeToken, bytes memory _erc20Data) internal returns (address) {
        bytes32 salt = _getCreate2Salt(_nativeToken);

        BeaconProxy l2Token = _deployBeaconProxy(salt);
        WrappedStandardERC20(address(l2Token)).bridgeInitialize(_nativeToken, _erc20Data);

        return address(l2Token);
    }

    /// @notice Converts the L1 token address to the create2 salt of deployed L2 token.
    /// @param _l1Token The address of token on L1.
    /// @return salt The salt used to compute address of wrapped token on L2 and for beacon proxy deployment.
    function _getCreate2Salt(address _l1Token) internal pure returns (bytes32 salt) {
        salt = bytes32(uint256(uint160(_l1Token)));
    }

    /// @notice Deploys the beacon proxy for the Wwrapped token.
    /// @dev This function uses raw call to ContractDeployer to make sure that exactly `l2TokenProxyBytecodeHash` is used
    /// for the code of the proxy.
    /// @param _salt The salt used for beacon proxy deployment of the wrapped token (we pass the native token address).
    /// @return proxy The beacon proxy, i.e. wrapped / bridged token.
    function _deployBeaconProxy(bytes32 _salt) internal virtual returns (BeaconProxy proxy);

    /*//////////////////////////////////////////////////////////////
                            PAUSE
    //////////////////////////////////////////////////////////////*/

    /// @notice Pauses all functions marked with the `whenNotPaused` modifier.
    function pause() external onlyOwner {
        _pause();
    }

    /// @notice Unpauses the contract, allowing all functions marked with the `whenNotPaused` modifier to be called again.
    function unpause() external onlyOwner {
        _unpause();
    }
}
