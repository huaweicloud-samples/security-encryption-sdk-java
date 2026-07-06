package com.huaweicloud.encryptionsdk.meterialmanager;

import com.huaweicloud.encryptionsdk.HuaweiConfig;
import com.huaweicloud.encryptionsdk.common.Constants;
import com.huaweicloud.encryptionsdk.common.CryptoFactory;
import com.huaweicloud.encryptionsdk.exception.EncryptException;
import com.huaweicloud.encryptionsdk.exception.ErrorMessage;
import com.huaweicloud.encryptionsdk.model.DataKeyMaterials;
import com.huaweicloud.encryptionsdk.model.enums.CryptoAlgorithm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class LocalDataKeyGenerate implements DataKeyGenerate {
    
    private static final Logger LOGGER = LoggerFactory.getLogger(LocalDataKeyGenerate.class);

    private static final String KEY_ALGORITHM_SM4 = "SM4";

    private static final String KEY_ALGORITHM_AES = "AES";

    @Override
    public void dataKeyGenerate(HuaweiConfig huaweiConfig, DataKeyMaterials dataKeyMaterials)
        throws NoSuchAlgorithmException {
        CryptoAlgorithm algorithm = huaweiConfig.getCryptoAlgorithm();
        String[] keySpecArr = algorithm.getKeySpec().split(Constants.KEY_SPEC_DELIMITER);
        String keSpec = keySpecArr[0];
        if (KEY_ALGORITHM_SM4.equalsIgnoreCase(keSpec)) {
            keSpec = KEY_ALGORITHM_AES;
        }
        KeyGenerator keyGenerator;
        try {
            keyGenerator = CryptoFactory.getKeyGenerator(keSpec);
        } catch (Exception e) {
            throw new EncryptException(ErrorMessage.ENCRYPT_EXCEPTION.getMessage(), e);
        }
        SecureRandom random;
        try {
            random = SecureRandom.getInstance("DRBG");
        } catch (NoSuchAlgorithmException e) {
            LOGGER.error("DRBG not available, using default SecureRandom");
            random = new SecureRandom();
        }
        keyGenerator.init(algorithm.getKeyLen() * 8, random);
        SecretKey secretKey = keyGenerator.generateKey();
        dataKeyMaterials.setPlaintextDataKey(secretKey);
    }
}
