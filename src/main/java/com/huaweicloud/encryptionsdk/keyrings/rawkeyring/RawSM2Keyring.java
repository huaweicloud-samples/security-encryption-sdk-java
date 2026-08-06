package com.huaweicloud.encryptionsdk.keyrings.rawkeyring;

import com.huaweicloud.encryptionsdk.common.ProviderManager;
import com.huaweicloud.encryptionsdk.common.Utils;
import com.huaweicloud.encryptionsdk.exception.EncryptException;
import com.huaweicloud.encryptionsdk.exception.ErrorMessage;
import com.huaweicloud.encryptionsdk.keyrings.kmskeyring.KMSKeyring;
import com.huaweicloud.encryptionsdk.model.CiphertextDataKey;
import com.huaweicloud.encryptionsdk.model.DataKeyMaterials;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;

/**
 * @description: 本地sm2算法实现keiring
 */
public class RawSM2Keyring extends RawKeyring {
    private static final Logger LOGGER = LoggerFactory.getLogger(KMSKeyring.class);

    private static final String KEY_ALGORITHM = "EC";

    @Override
    public void realEncrypt(byte[] bytes, List<CiphertextDataKey> ciphertextDataKeys,
        DataKeyMaterials dataKeyMaterials) {
        try {
            SecretKey plaintextDataKey = dataKeyMaterials.getPlaintextDataKey();
            byte[] encodeDatakey = plaintextDataKey.getEncoded();
            ECPublicKeyParameters publicKeyParam = getPublicKeyParam(bytes);
            SM2Engine sm2Engine = new SM2Engine();
            sm2Engine.init(true, new ParametersWithRandom(publicKeyParam));
            byte[] result = sm2Engine.processBlock(encodeDatakey, 0, encodeDatakey.length);
            ciphertextDataKeys.add(new CiphertextDataKey(result));
        } catch (Exception e) {
            throw new EncryptException(ErrorMessage.ENCRYPT_EXCEPTION.getMessage(), e);
        }
    }

    @Override
    public boolean realDecrypt(byte[] bytes, CiphertextDataKey ciphertextDataKey, DataKeyMaterials dataKeyMaterials) {
        try {
            ECPrivateKeyParameters privateKeyParameters = getPrivateKeyParameters(
                (ECPrivateKey) parsePrivateKeyWithBc(bytes));
            SM2Engine sm2Engine = new SM2Engine();
            sm2Engine.init(false, privateKeyParameters);
            byte[] dataKey = sm2Engine.processBlock(ciphertextDataKey.getDataKey(), 0,
                ciphertextDataKey.getDataKey().length);
            dataKeyMaterials.setPlaintextDataKey(
                Utils.byteToSecretKey(dataKey, dataKeyMaterials.getCryptoAlgorithm().getAlgorithmName()));
            return true;
        } catch (Exception e) {
            LOGGER.warn("one master key may be not match when decrypt data key in RawSM2Keyring.class");
        }
        return false;
    }

    private ECPublicKeyParameters getPublicKeyParam(byte[] bytes) {
        ECPublicKey publicKey = (ECPublicKey) parsePublicKeyWithBc(bytes);
        ECParameterSpec parameterSpec = publicKey.getParameters();
        ECDomainParameters domainParams = new ECDomainParameters(parameterSpec.getCurve(), parameterSpec.getG(),
            parameterSpec.getN(), parameterSpec.getH());
        return new ECPublicKeyParameters(publicKey.getQ(), domainParams);
    }

    private ECPrivateKeyParameters getPrivateKeyParameters(ECPrivateKey privateKey) {
        ECParameterSpec parameterSpec = privateKey.getParameters();
        ECCurve curve = parameterSpec.getCurve();
        ECPoint g = parameterSpec.getG();
        BigInteger n = parameterSpec.getN();
        BigInteger h = parameterSpec.getH();
        ECDomainParameters domainParams = new ECDomainParameters(curve, g, n, h);
        return new ECPrivateKeyParameters(privateKey.getD(), domainParams);
    }

    /**
     * 使用 BC provider 解析公钥, 确保返回 BC 的 ECPublicKey 实现
     */
    private static PublicKey parsePublicKeyWithBc(byte[] keyBytes) {
        try {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM, ProviderManager.getBcProvider());
            return keyFactory.generatePublic(keySpec);
        } catch (Exception e) {
            throw new EncryptException(ErrorMessage.PUBLIC_KEY_PARSE_EXCEPTION.getMessage(), e);
        }
    }

    /**
     * 使用 BC provider 解析私钥, 确保返回 BC 的 ECPrivateKey 实现
     */
    private static PrivateKey parsePrivateKeyWithBc(byte[] keyBytes) {
        try {
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM, ProviderManager.getBcProvider());
            return keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            throw new EncryptException(ErrorMessage.PRIVATE_KEY_PARSE_EXCEPTION.getMessage(), e);
        }
    }

    @Override
    public List<byte[]> getEncryptSecretKey() {
        return getPublicKey();
    }

    @Override
    public List<byte[]> getDecryptSecretKey() {
        return getPrivateKey();
    }

}
