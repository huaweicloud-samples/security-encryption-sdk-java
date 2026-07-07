package com.huaweicloud.encryptionsdk.model.enums;

/**
 * @description: 数据密钥生成方式
 */
public enum DataKeyGenerateType {
    LOCAL_GENERATE("create data key from local", 1),
    KMS_GENERATE("create data key from KMS", 2),
    KEY_CAPSULE_GENERATE("create data key from key capsule", 3);

    private String desc;

    private int code;

    DataKeyGenerateType(String desc, int code) {
        this.desc = desc;
        this.code = code;

    }

    public int getCode() {
        return code;
    }
}
