package com.huaweicloud.encryptionsdk.kms;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 创建密钥胶囊响应
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CreateKeyCapsuleResponse {

    @JsonProperty("key_id")
    private String keyId;

    @JsonProperty("datakey_cipher")
    private String datakeyCipher;

    @JsonProperty("datakey")
    private String datakey;

    @JsonProperty("datakey_capsule")
    private String datakeyCapsule;
}