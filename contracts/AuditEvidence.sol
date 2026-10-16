// SPDX-License-Identifier: MIT
/**
 * AuditEvidence 审计结果存证合约
 * ------------------------------------------------------------------
 * 部署平台：FISCO BCOS 单节点（Ubuntu 20.04 虚拟机）
 * 编译版本：solc 0.4.24（FISCO BCOS 2.x 默认兼容版本）
 *
 * 功能：
 *   1. saveEvidence  审计系统将「审计编号 + 合约源码SHA256 + 审计记录SHA256」上链
 *   2. getEvidence   校验端按审计编号取回链上哈希，与本地重算哈希比对
 *
 * 设计说明：
 *   - 同一审计编号仅允许存证一次（链层幂等，配合业务层防重复存证）
 *   - 仅保存哈希值（64位十六进制字符串），不上传源码与报告原文，保护业务隐私
 *   - timestamp 取区块时间，作为上链时间凭证
 *
 * 已部署地址（见 config.FISCO_CONTRACT_ADDRESS）：
 *   0xc6d09d57e9fd74f155fd5a77455945ed73028914
 */
pragma solidity ^0.4.24;

contract AuditEvidence {

    // 单条存证结构
    struct Evidence {
        string auditId;          // 审计编号（业务主键，如 AUD202609171038336FF8A051）
        string contractHash;     // 合约源码 SHA256
        string auditRecordHash;  // 审计记录规范化 JSON 全文 SHA256
        uint256 timestamp;       // 上链区块时间
        bool exists;             // 是否已存证（mapping 默认值无法区分零值，用显式标志）
    }

    // 审计编号 => 存证内容
    mapping(string => Evidence) private evidences;

    // 存证成功事件，便于链下监听与检索
    event EvidenceSaved(
        string indexed auditId,
        string contractHash,
        string auditRecordHash,
        uint256 timestamp
    );

    /**
     * 上链存证
     * @param auditId         审计编号
     * @param contractHash    合约源码 SHA256
     * @param auditRecordHash 审计记录全文 SHA256
     */
    function saveEvidence(
        string auditId,
        string contractHash,
        string auditRecordHash
    ) public {
        // 同一审计不可重复存证
        require(!evidences[auditId].exists, "evidence already exists");
        // 哈希与编号不允许为空
        require(bytes(auditId).length > 0, "empty auditId");
        require(bytes(contractHash).length > 0, "empty contractHash");
        require(bytes(auditRecordHash).length > 0, "empty auditRecordHash");

        evidences[auditId] = Evidence({
            auditId: auditId,
            contractHash: contractHash,
            auditRecordHash: auditRecordHash,
            timestamp: block.timestamp,
            exists: true
        });

        emit EvidenceSaved(auditId, contractHash, auditRecordHash, block.timestamp);
    }

    /**
     * 读取链上存证（校验时调用）
     * @param auditId 审计编号
     * @return 审计编号 / 合约哈希 / 审计记录哈希 / 上链时间
     */
    function getEvidence(string auditId)
        public
        view
        returns (string, string, string, uint256)
    {
        require(evidences[auditId].exists, "evidence not found");
        Evidence memory e = evidences[auditId];
        return (e.auditId, e.contractHash, e.auditRecordHash, e.timestamp);
    }
}
