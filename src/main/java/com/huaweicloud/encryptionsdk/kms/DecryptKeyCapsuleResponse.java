package com.huaweicloud.encryptionsdk.kms;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 临时实现：解密密钥胶囊响应
 * TODO: 待 KMS SDK 发布包含密钥胶囊 API 的版本后，替换为官方类
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DecryptKeyCapsuleResponse {

    @JsonProperty("key_id")
    private String keyId;

    @JsonProperty("datakey")
    private String datakey;

    @JsonProperty("datakey_cipher")
    private String datakeyCipher;

    @JsonProperty("instance_id")
    private String instanceId;
}