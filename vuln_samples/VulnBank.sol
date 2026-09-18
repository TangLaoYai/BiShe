// SPDX-License-Identifier: MIT
// 漏洞样本：权限越权 + selfdestruct 后门 + 硬编码 owner
// 用于测试 privilege_check 与 dynamic_penetrate 模块
pragma solidity ^0.8.0;

contract VulnBank {
    // 硬编码管理员地址（规则 4：硬编码管理员）
    address public owner = 0xAb8483F64d9C6d1EcF9b849Ae677dD3315835cb2;

    mapping(address => uint256) public balances;

    // 规则 2：setOwner 无权限保护 -> 任意地址可接管
    function setOwner(address _newOwner) public {
        owner = _newOwner;
    }

    // 规则 3：selfdestruct 后门
    function kill() public {
        selfdestruct(payable(msg.sender));
    }

    // 规则 1：状态变更函数缺少权限控制
    function withdraw(uint256 amount) public {
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // 规则 5：tx.origin 鉴权
    function transferOwner(address _to) public {
        require(tx.origin == owner, "not owner");
        owner = _to;
    }
}
