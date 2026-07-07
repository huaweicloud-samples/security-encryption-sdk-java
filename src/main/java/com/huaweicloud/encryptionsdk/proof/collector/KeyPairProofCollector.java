package com.huaweicloud.encryptionsdk.proof.collector;

import com.huaweicloud.encryptionsdk.common.ECPrivateKeyLoader;
import com.huaweicloud.encryptionsdk.common.ProviderManager;
import com.huaweicloud.encryptionsdk.exception.ErrorMessage;
import com.huaweicloud.encryptionsdk.exception.HuaweicloudException;
import com.huaweicloud.encryptionsdk.proof.AttestationDocument;
import com.huaweicloud.encryptionsdk.proof.ProofCollector;
import com.huaweicloud.encryptionsdk.proof.ProofInfo;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;

/**
 * 密钥对证明文档收集器
 */
public class KeyPairProofCollector implements ProofCollector {

    private static final Logger LOGGER = LoggerFactory.getLogger(KeyPairProofCollector.class);

    @Override
    public AttestationDocument collect(ProofInfo proofInfo) {
        String privateKeyStr = proofInfo.getPrivateKeyDecryptCallback().decrypt(proofInfo.getEncryptedPrivateKey());
        PrivateKey privateKey = ECPrivateKeyLoader.load(privateKeyStr);
        String expireTime = getExpireTime();
        String originText = proofInfo.getKeyCapsule() + expireTime;
        String signature = getSignature(privateKey, originText);

        return AttestationDocument.builder()
                .customPublicKey(getPublicKeyFromPrivateKey(privateKey))
                .customSignature(signature)
                .expireTime(expireTime)
                .build();
    }

    private String getPublicKeyFromPrivateKey(PrivateKey privateKey) {
        try {
            if (!(privateKey instanceof BCECPrivateKey bcecPrivateKey)) {
                throw new HuaweicloudException(ErrorMessage.GET_PUB_KEY_EXCEPTION.getMessage());
            }
            KeyFactory keyFactory = KeyFactory.getInstance("EC", ProviderManager.getBcProvider());
            ECParameterSpec ecSpec = bcecPrivateKey.getParameters();
            ECPoint q = ecSpec.getG().multiply((bcecPrivateKey).getD());
            ECPublicKeySpec pubSpec = new ECPublicKeySpec(q, ecSpec);
            return Base64.getEncoder().encodeToString(keyFactory.generatePublic(pubSpec).getEncoded());
        } catch (Exception e) {
            LOGGER.error("get ecc public key from private key error, msg is {}", e.getMessage());
            throw new HuaweicloudException(ErrorMessage.GET_PUB_KEY_EXCEPTION.getMessage(), e);
        }
    }

    private String getSignature(PrivateKey privateKey, String originText) {
        try {
            Signature signature = Signature.getInstance("SHA256withECDSA", ProviderManager.getBcProvider());
            signature.initSign(privateKey);
            signature.update(originText.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(signature.sign());
        } catch (Exception e) {
            throw new HuaweicloudException(ErrorMessage.COLLECT_PROOF_EXCEPTION.getMessage(), e);
        }
    }

    private String getExpireTime() {
        return Instant.now()
                .plus(30, ChronoUnit.MINUTES)
                .truncatedTo(ChronoUnit.SECONDS)
                .toString();
    }
}