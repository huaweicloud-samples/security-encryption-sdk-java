package com.huaweicloud.encryptionsdk.proof;

/**
 * 私钥解密回调接口
 */
@FunctionalInterface
public interface PrivateKeyDecryptCallback {

    /**
     * 解密私钥
     *
     * @param encryptedPrivateKey 加密的私钥
     * @return 解密后的明文私钥（Base64格式）
     */
    String decrypt(String encryptedPrivateKey);
}