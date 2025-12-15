// SPDX-License-Identifier: MIT
pragma solidity =0.8.30;

contract Create2Factory {
    event Deployed(
        address indexed sender,
        bytes32 indexed salt,
        address indexed deployed
    );

    function deploy(
        bytes32 salt,
        bytes memory code
    ) external payable returns (address deployed) {
        assembly {
            mstore(0x00, salt)
            mstore(0x20, caller())
            deployed := create2(
                callvalue(),
                add(code, 0x20),
                mload(code),
                keccak256(0x00, 0x40)
            )
            if iszero(deployed) {
                revert(0, 0)
            }
            log4(
                0,
                0,
                0xfa86dcef4390d6a0f7edde563410fc44e4c2d382b4c6699cce5ebc4071abcc95,
                caller(),
                salt,
                deployed
            )
        }
    }

    function compute(
        bytes32 salt,
        bytes memory code,
        address eoa
    ) external view returns (address computed) {
        assembly {
            let ptr := mload(0x40)
            mstore(0x00, salt)
            mstore(0x20, eoa)
            salt := keccak256(0x00, 0x40)
            mstore(0x00, address())
            mstore(0x20, salt)
            mstore(0x40, keccak256(add(code, 0x20), mload(code)))
            mstore8(0x0b, 0xff)
            computed := keccak256(0x0b, 0x55)
            mstore(0x40, ptr)
        }
    }
}
