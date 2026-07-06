package com.huaweicloud.encryptionsdk.meterialmanager;

import com.huaweicloud.encryptionsdk.exception.ErrorMessage;
import com.huaweicloud.encryptionsdk.exception.HuaweicloudException;
import com.huaweicloud.encryptionsdk.model.enums.DataKeyGenerateType;

/**
 * @description: 数据密钥生成器工厂
 */
public class DataKeyGenerateFactory {

    public static DataKeyGenerate getDataKeyGenerate(DataKeyGenerateType dataKeyGenerateType) {

        switch (dataKeyGenerateType) {
            case KMS_GENERATE:
                return new KmsDataKeyGenerate();
            case LOCAL_GENERATE:
                return new LocalDataKeyGenerate();
            case KEY_CAPSULE_GENERATE:
                return new KeyCapsuleDataKeyGenerate();
            default:
                throw new HuaweicloudException(ErrorMessage.DATA_KEY_GENERATE_EXCEPTION.getMessage());
        }
    }
}
