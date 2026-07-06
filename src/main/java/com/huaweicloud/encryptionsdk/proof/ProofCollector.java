package com.huaweicloud.encryptionsdk.proof;

/**
 * 证明文档收集器接口
 */
public interface ProofCollector {

    /**
     * 收集证明文档
     *
     * @param proofInfo 证明文档所需信息
     * @return 证明文档
     */
    AttestationDocument collect(ProofInfo proofInfo);
}