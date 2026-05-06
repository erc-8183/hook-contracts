// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./UnderwritingTypes.sol";

interface IUnderwritingHookView {
    function getCommit(uint256 jobId) external view returns (UnderwritingTypes.UnderwriteCommit memory);
    function jobUnderwriter(uint256 jobId) external view returns (address);
    function jobSidecarState(uint256 jobId) external view returns (UnderwritingTypes.SidecarState);
}
