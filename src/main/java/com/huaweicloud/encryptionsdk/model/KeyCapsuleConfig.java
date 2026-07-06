package com.huaweicloud.encryptionsdk.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 密钥胶囊配置
 * 用于加密时构建密钥胶囊请求参数
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class KeyCapsuleConfig {

    /**
     * 区域
     */
    private String region;

    /**
     * 默认策略ID（当EncryptRequest中未指定策略时使用）
     */
    private String defaultPolicyId;

    /**
     * 默认内联策略（当EncryptRequest中未指定策略且defaultPolicyId未设置时使用）
     */
    private String defaultKeyPolicy;

    /**
     * 接入点类型
     */
    private AccessPointConfig accessPointConfig;
}