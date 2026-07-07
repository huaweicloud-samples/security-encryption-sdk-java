package com.huaweicloud.encryptionsdk.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 密钥胶囊
 * 每个密钥胶囊只对应一个接入点
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class KeyCapsule {

    /**
     * 主密钥ID
     */
    private String keyId;

    /**
     * 密钥胶囊
     */
    private String datakeyCapsule;

    /**
     * 接入点类型: 1:ECS, 2:Custom
     */
    private int accessPointType;

    /**
     * 实例ID（解密时由KMS返回）
     */
    private String instanceId;
}