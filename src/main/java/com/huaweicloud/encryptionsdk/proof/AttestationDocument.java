package com.huaweicloud.encryptionsdk.proof;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 证明文档
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AttestationDocument {
    @JsonProperty("ecs_signature")
    private String ecsSignature;

    @JsonProperty("custom_signature")
    private String customSignature;

    @JsonProperty("custom_public_key")
    private String customPublicKey;

    @JsonProperty("expire_time")
    private String expireTime;

    @JsonProperty("service_token")
    private String serviceToken;

    @Override
    public String toString() {
        return "AttestationDocument(ecsSignature=" + ecsSignature
                + ", customSignature=" + customSignature
                + ", customPublicKey=" + customPublicKey
                + ", expireTime=" + expireTime
                + ", serviceToken=****)";
    }
}