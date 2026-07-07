package com.huaweicloud.encryptionsdk.kms;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 临时实现：创建密钥胶囊请求体
 * TODO: 待 KMS SDK 发布包含密钥胶囊 API 的版本后，替换为官方类
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CreateKeyCapsuleRequest {

    /**
     * 主密钥ID
     */
    @JsonProperty("key_id")
    private String keyId;

    /**
     * 数据密钥长度
     */
    @JsonProperty("datakey_length")
    private int datakeyLength;

    /**
     * 公钥，用于保护返回的数据密钥（可选）
     */
    @JsonProperty("public_key")
    private String publicKey;

    /**
     * 密钥策略ID
     */
    @JsonProperty("policy_id")
    private String policyId;

    /**
     * 内联密钥策略
     */
    @JsonProperty("key_policy")
    private String keyPolicy;
}