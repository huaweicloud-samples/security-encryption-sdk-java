package com.huaweicloud.encryptionsdk.model;

import com.huaweicloud.encryptionsdk.model.enums.CryptoAlgorithm;

import javax.crypto.SecretKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class DataKeyMaterials {

    private SecretKey plaintextDataKey;

    private List<CiphertextDataKey> ciphertextDataKeys = new ArrayList<>();

    private Map<String, String> encryptionContexts = new HashMap<>();

    private CryptoAlgorithm cryptoAlgorithm;

    /**
     * 密钥胶囊（密钥胶囊模式时使用）
     */
    private KeyCapsule keyCapsule;

    /**
     * 策略ID（与 keyPolicy 二选一，优先使用）
     */
    private String policyId;

    /**
     * 内联策略（与 policyId 二选一，policyId 未设置时使用）
     */
    private String keyPolicy;

    public SecretKey getPlaintextDataKey() {
        return plaintextDataKey;
    }

    public void setPlaintextDataKey(SecretKey plaintextDataKey) {
        this.plaintextDataKey = plaintextDataKey;
    }

    public List<CiphertextDataKey> getCiphertextDataKeys() {
        return ciphertextDataKeys;
    }

    public void setCiphertextDataKeys(List<CiphertextDataKey> ciphertextDataKeys) {
        this.ciphertextDataKeys = ciphertextDataKeys;
    }

    public Map<String, String> getEncryptionContexts() {
        return encryptionContexts;
    }

    public void setEncryptionContexts(Map<String, String> encryptionContexts) {
        this.encryptionContexts = encryptionContexts;
    }

    public CryptoAlgorithm getCryptoAlgorithm() {
        return cryptoAlgorithm;
    }

    public void setCryptoAlgorithm(CryptoAlgorithm cryptoAlgorithm) {
        this.cryptoAlgorithm = cryptoAlgorithm;
    }

    public KeyCapsule getKeyCapsule() {
        return keyCapsule;
    }

    public void setKeyCapsule(KeyCapsule keyCapsule) {
        this.keyCapsule = keyCapsule;
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
