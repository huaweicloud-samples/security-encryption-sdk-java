package com.huaweicloud.encryptionsdk.keyrings;

import com.huaweicloud.encryptionsdk.exception.ErrorMessage;
import com.huaweicloud.encryptionsdk.exception.KeyringNotFoundException;
import com.huaweicloud.encryptionsdk.keyrings.kmskeyring.KMSDiscoveryKeyring;
import com.huaweicloud.encryptionsdk.keyrings.kmskeyring.KMSKeyCapsuleKeyring;
import com.huaweicloud.encryptionsdk.keyrings.kmskeyring.KMSKeyring;
import com.huaweicloud.encryptionsdk.keyrings.kmskeyring.KMSMultiRegionKeyring;
import com.huaweicloud.encryptionsdk.model.enums.KeyringTypeEnum;

/**
 * @description: kmsKeyring工厂
 */
public class KmsKeyringFactory implements KeyringFactory {
    @Override
    public KMSKeyring getKeyring(String type) {
        KeyringTypeEnum keyringTypeEnum = KeyringTypeEnum.getRawKeyringType(type);
        if (keyringTypeEnum == null) {
            throw new KeyringNotFoundException(ErrorMessage.KEYRING_NOT_FOUND_EXCEPTION.getMessage());
        }
        switch (keyringTypeEnum) {
            case KMS_DISCOVERY:
                return new KMSDiscoveryKeyring();
            case KMS_MULTI_REGION:
                return new KMSMultiRegionKeyring();
            case KMS_KEY_CAPSULE:
                return new KMSKeyCapsuleKeyring();
            default:
                return null;
        }
    }
}
