// SPDX-License-Identifier: MIT
// 漏洞样本：整数溢出（Solidity 0.7 无溢出检查）+ 重入风险
// 用于测试 slither 静态分析
pragma solidity ^0.7.6;

contract OverflowToken {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    function transfer(address to, uint256 amount) public returns (bool) {
        // 整数溢出：balances[to] + amount 可能溢出
        balances[msg.sender] -= amount;
        balances[to] += amount;
        return true;
    }

    function mint(uint256 amount) public {
        // 缺少权限控制 + 溢出
        balances[msg.sender] += amount;
        totalSupply += amount;
    }

    // 重入漏洞：先转账后更新余额
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] -= amount;
    }
}
