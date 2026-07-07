package com.huaweicloud.encryptionsdk.kms;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.huaweicloud.encryptionsdk.proof.AttestationDocument;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 临时实现：解密密钥胶囊请求体
 * TODO: 待 KMS SDK 发布包含密钥胶囊 API 的版本后，替换为官方类
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DecryptKeyCapsuleRequest {

    /**
     * 主密钥ID
     */
    @JsonProperty("key_id")
    private String keyId;

    /**
     * 密文数据密钥
     */
    @JsonProperty("datakey_capsule")
    private String datakeyCapsule;

    /**
     * 证明文档
     */
    @JsonProperty("attestation_document")
    private AttestationDocument attestationDocument;
}