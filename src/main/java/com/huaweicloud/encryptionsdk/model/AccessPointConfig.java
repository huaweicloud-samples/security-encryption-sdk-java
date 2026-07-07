package com.huaweicloud.encryptionsdk.model;

import com.huaweicloud.encryptionsdk.proof.PrivateKeyDecryptCallback;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 接入点配置
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AccessPointConfig {

    /**
     * 接入点类型: 1:ECS, 2:Custom
     */
    private int type;

    /**
     * 加密的私钥字节数组
     */
    private String encryptedPrivateKey;

    /**
     * 私钥解密回调（由用户实现）
     */
    private PrivateKeyDecryptCallback privateKeyDecryptCallback;

    /**
     * CCE场景的ServiceAccount名称，默认default
     */
    private String serviceAccount;
}