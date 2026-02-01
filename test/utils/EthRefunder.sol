// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title EthRefunder
 * @dev A contract that accepts ETH and immediately refunds it back to sender.
 * Useful for testing accounting system flaws.
 */
contract EthRefunder {
    event Received(address indexed from, uint256 amount);
    event Refunded(address indexed to, uint256 amount);

    receive() external payable {
        emit Received(msg.sender, msg.value);

        (bool success,) = payable(msg.sender).call{value: msg.value}("");

        if (success) {
            emit Refunded(msg.sender, msg.value);
        }
    }
}
