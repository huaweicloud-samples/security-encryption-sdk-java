package com.huaweicloud.encryptionsdk.model.enums;

/**
 * @description: 密钥环类型
 */
public enum KeyringTypeEnum {
    RAW_AES("AES"),
    RAW_SM2("SM2"),
    RAW_RSA("RSA"),
    RAW_SM4_CBC("SM4_CBC"),
    RAW_SM4_GCN("SM4_GCM"),
    KMS_MULTI_REGION("multi"),
    KMS_DISCOVERY("discovery"),
    KMS_KEY_CAPSULE("key_capsule");

    private String type;

    KeyringTypeEnum(String type) {
        this.type = type;
    }

    public String getType() {
        return type;
    }

    public static KeyringTypeEnum getRawKeyringType(String type) {
        for (KeyringTypeEnum keyringTypeEnum : KeyringTypeEnum.values()) {
            if (keyringTypeEnum.getType().equalsIgnoreCase(type)) {
                return keyringTypeEnum;
            }
        }
        return null;
    }
}
