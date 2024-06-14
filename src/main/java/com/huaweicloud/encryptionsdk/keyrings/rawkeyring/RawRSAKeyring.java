package com.huaweicloud.encryptionsdk.keyrings.rawkeyring;

import com.huaweicloud.encryptionsdk.common.Utils;
import com.huaweicloud.encryptionsdk.exception.EncryptException;
import com.huaweicloud.encryptionsdk.exception.ErrorMessage;
import com.huaweicloud.encryptionsdk.keyrings.kmskeyring.KMSKeyring;
import com.huaweicloud.encryptionsdk.model.CiphertextDataKey;
import com.huaweicloud.encryptionsdk.model.DataKeyMaterials;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import java.io.FileNotFoundException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;

/**
 * @description: 本地RSA算法实现keyring
 */
public class RawRSAKeyring extends RawKeyring {
    private static final Logger LOGGER = LoggerFactory.getLogger(KMSKeyring.class);

    public static final String RSA_ALGORITHM = "RSA";

    private static final String DEFAULT_CIPHER_ALGORITHM = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

    @Override
    public List<byte[]> getEncryptSecretKey() throws FileNotFoundException {
        return getPublicKey();
    }

    @Override
    public void realEncrypt(byte[] bytes, List<CiphertextDataKey> ciphertextDataKeys,
        DataKeyMaterials dataKeyMaterials) {
        try {
            byte[] encodeDatakey = dataKeyMaterials.getPlaintextDataKey().getEncoded();
            RSAPublicKey publicKey = (RSAPublicKey) Utils.getPublicKey(bytes, RSA_ALGORITHM);
            Cipher cipher = Cipher.getInstance(DEFAULT_CIPHER_ALGORITHM, BouncyCastleProvider.PROVIDER_NAME);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            ciphertextDataKeys.add(new CiphertextDataKey(cipher.doFinal(encodeDatakey)));
        } catch (Exception e) {
            throw new EncryptException(ErrorMessage.ENCRYPT_EXCEPTION.getMessage(), e);
        }
    }

    @Override
    public boolean realDecrypt(byte[] bytes, CiphertextDataKey ciphertextDataKey, DataKeyMaterials dataKeyMaterials) {
        try {
            PrivateKey privateKey = Utils.getPrivateKey(bytes, RSA_ALGORITHM);
            Cipher cipher = Cipher.getInstance(DEFAULT_CIPHER_ALGORITHM, BouncyCastleProvider.PROVIDER_NAME);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] dataKey = cipher.doFinal(ciphertextDataKey.getDataKey());
            dataKeyMaterials.setPlaintextDataKey(
                Utils.byteToSecretKey(dataKey, dataKeyMaterials.getCryptoAlgorithm().getAlgorithmName()));
            return true;
        } catch (Exception e) {
            LOGGER.warn("one master key may be not match when decrypt data key in RawRSAKeyring.class");

        }
        return false;
    }

    @Override
    public List<byte[]> getDecryptSecretKey() {
        return getPrivateKey();
    }
}
