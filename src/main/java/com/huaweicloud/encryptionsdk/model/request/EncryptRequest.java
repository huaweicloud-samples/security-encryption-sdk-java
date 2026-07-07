package com.huaweicloud.encryptionsdk.model.request;

import java.util.HashMap;
import java.util.Map;

public class EncryptRequest {
    private Map<String, String> encryptionContext;

    private byte[] plainText;

    /**
     * 策略ID（与 keyPolicy 二选一，keyPolicy 未设置时使用）
     */
    private String policyId;

    /**
     * 内联策略（与 policyId 二选一，优先使用）
     */
    private String keyPolicy;

    public EncryptRequest(Map<String, String> encryptionContext, byte[] plainText) {
        this.encryptionContext = encryptionContext == null ? new HashMap<>() : encryptionContext;
        this.plainText = plainText;
    }

    public EncryptRequest() {
        this.encryptionContext = new HashMap<>();
    }

    public Map<String, String> getEncryptionContext() {
        return encryptionContext;
    }

    public void setEncryptionContext(Map<String, String> encryptionContext) {
        this.encryptionContext = encryptionContext;
    }

    public byte[] getPlainText() {
        return plainText;
    }

    public void setPlainText(byte[] plainText) {
        this.plainText = plainText;
    }

    public String getPolicyId() {
        return policyId;
    }

    public void setPolicyId(String policyId) {
        this.policyId = policyId;
    }

    public String getKeyPolicy() {
        return keyPolicy;
    }

    public void setKeyPolicy(String keyPolicy) {
        this.keyPolicy = keyPolicy;
    }
}
