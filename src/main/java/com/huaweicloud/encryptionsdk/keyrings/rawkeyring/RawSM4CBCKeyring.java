package com.huaweicloud.encryptionsdk.keyrings.rawkeyring;

import com.huaweicloud.encryptionsdk.common.Constants;
import com.huaweicloud.encryptionsdk.common.Utils;
import com.huaweicloud.encryptionsdk.exception.EncryptException;
import com.huaweicloud.encryptionsdk.exception.ErrorMessage;
import com.huaweicloud.encryptionsdk.handler.CipherHandler;
import com.huaweicloud.encryptionsdk.model.CiphertextDataKey;
import com.huaweicloud.encryptionsdk.model.DataKeyMaterials;
import com.huaweicloud.encryptionsdk.model.enums.CryptoAlgorithm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.List;

/**
 * @description: 本地sm4算法实现keiring
 */
public class RawSM4CBCKeyring extends RawKeyring {
    private static final Logger LOGGER = LoggerFactory.getLogger(RawSM4CBCKeyring.class);

    private static final String KEY_ALGORITHM = "SM4";

    @Override
    public void realEncrypt(byte[] bytes, List<CiphertextDataKey> ciphertextDataKeys,
        DataKeyMaterials dataKeyMaterials) {
        try {
            CryptoAlgorithm algorithm = CryptoAlgorithm.SM4_128_CBC_PADDING;
            SecretKey secretKey = new SecretKeySpec(bytes, KEY_ALGORITHM);
            CipherHandler cipherHandler = new CipherHandler(algorithm, secretKey, Cipher.ENCRYPT_MODE);
            byte[] originalDataKey = dataKeyMaterials.getPlaintextDataKey().getEncoded();
            byte[] encryptDataKey = cipherHandler.cipherData(originalDataKey, dataKeyMaterials.getEncryptionContexts(),
                Constants.NUM_0, originalDataKey.length);
            int ivLength = cipherHandler.getIv().length;
            byte[] message = new byte[ivLength + encryptDataKey.length];
            System.arraycopy(cipherHandler.getIv(), Constants.NUM_0, message, Constants.NUM_0, ivLength);
            System.arraycopy(encryptDataKey, Constants.NUM_0, message, ivLength, encryptDataKey.length);
            ciphertextDataKeys.add(new CiphertextDataKey(message));
        } catch (Exception e) {
            throw new EncryptException(ErrorMessage.ENCRYPT_EXCEPTION.getMessage(), e);
        }
    }

    @Override
    public boolean realDecrypt(byte[] bytes, CiphertextDataKey ciphertextDataKey, DataKeyMaterials dataKeyMaterials) {
        try {
            CryptoAlgorithm algorithm = CryptoAlgorithm.SM4_128_CBC_PADDING;
            byte[] dataKey = ciphertextDataKey.getDataKey();
            SecretKey secretKey = new SecretKeySpec(bytes, KEY_ALGORITHM);
            CipherHandler cipherHandler = new CipherHandler(algorithm, secretKey, Cipher.DECRYPT_MODE);
            if (dataKey.length
                < dataKeyMaterials.getCryptoAlgorithm().getIvLen() + dataKeyMaterials.getCryptoAlgorithm()
                .getTagLen()) {
                throw new IllegalArgumentException();
            }
            int ivLen = algorithm.getIvLen();
            byte[] iv = new byte[ivLen];
            System.arraycopy(dataKey, Constants.NUM_0, iv, Constants.NUM_0, ivLen);
            cipherHandler.setIv(iv);
            byte[] decryptDataKey = cipherHandler.cipherData(dataKey, dataKeyMaterials.getEncryptionContexts(), ivLen,
                dataKey.length - ivLen);
            SecretKey secretKey1 = Utils.byteToSecretKey(decryptDataKey,
                dataKeyMaterials.getCryptoAlgorithm().getAlgorithmName());
            dataKeyMaterials.setPlaintextDataKey(secretKey1);
            return true;
        } catch (Exception e) {
            LOGGER.warn("one master key may be not match when decrypt data key in RawSM4Keyring.class");
        }
        return false;
    }

    @Override
    public List<byte[]> getEncryptSecretKey() {
        return getSymmetricKey();
    }

    @Override
    public List<byte[]> getDecryptSecretKey() {
        return getSymmetricKey();
    }

}
