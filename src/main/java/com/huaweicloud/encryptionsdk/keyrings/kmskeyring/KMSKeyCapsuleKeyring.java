package com.huaweicloud.encryptionsdk.keyrings.kmskeyring;

import com.huaweicloud.encryptionsdk.HuaweiConfig;
import com.huaweicloud.encryptionsdk.common.Utils;
import com.huaweicloud.encryptionsdk.exception.ErrorMessage;
import com.huaweicloud.encryptionsdk.exception.HuaweicloudException;
import com.huaweicloud.encryptionsdk.kms.DecryptKeyCapsuleRequest;
import com.huaweicloud.encryptionsdk.kms.DecryptKeyCapsuleResponse;
import com.huaweicloud.encryptionsdk.kms.KmsHttpClient;
import com.huaweicloud.encryptionsdk.model.AccessPointConfig;
import com.huaweicloud.encryptionsdk.model.CiphertextDataKey;
import com.huaweicloud.encryptionsdk.model.DataKeyMaterials;
import com.huaweicloud.encryptionsdk.model.KeyCapsule;
import com.huaweicloud.encryptionsdk.model.KMSConfig;
import com.huaweicloud.encryptionsdk.model.KeyCapsuleConfig;
import com.huaweicloud.encryptionsdk.proof.AttestationDocument;
import com.huaweicloud.encryptionsdk.proof.ProofCollectorFactory;
import com.huaweicloud.encryptionsdk.proof.ProofInfo;
import com.huaweicloud.sdk.core.auth.BasicCredentials;
import com.huaweicloud.sdk.core.auth.ICredential;
import com.huaweicloud.sdk.core.region.Region;
import com.huaweicloud.sdk.kms.v2.KmsClient;
import com.huaweicloud.sdk.kms.v2.model.ListKeyDetailRequest;
import com.huaweicloud.sdk.kms.v2.model.OperateKeyRequestBody;
import com.huaweicloud.sdk.kms.v2.region.KmsRegion;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.spec.SecretKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * 密钥胶囊模式KMS密钥环
 * 继承KMSKeyring，复用KMS客户端缓存等基础设施
 */
public class KMSKeyCapsuleKeyring extends KMSKeyring {

    private static final Logger LOGGER = LoggerFactory.getLogger(KMSKeyCapsuleKeyring.class);

    @Override
    public void doDecrypt(DataKeyMaterials dataKeyMaterials) {
        KeyCapsule keyCapsule = dataKeyMaterials.getKeyCapsule();
        if (keyCapsule == null) {
            throw new HuaweicloudException("Key capsule is null");
        }

        List<CiphertextDataKey> ciphertextDataKeys = dataKeyMaterials.getCiphertextDataKeys();
        if (ciphertextDataKeys == null || ciphertextDataKeys.isEmpty()) {
            throw new HuaweicloudException(ErrorMessage.CIPHER_TEXT_DATA_KEY_NOT_NULL.getMessage());
        }
        CiphertextDataKey ciphertextDataKey = ciphertextDataKeys.get(0);
        KMSConfig kmsConfig = getKMSConfig(ciphertextDataKey);
        keyCapsule.setDatakeyCapsule(Utils.bytesToHex(ciphertextDataKey.getDataKey()));

        HuaweiConfig huaweiConfig = getHuaweiConfig();
        BasicCredentials auth = new BasicCredentials()
            .withAk(huaweiConfig.getAk())
            .withSk(huaweiConfig.getSk())
            .withProjectId(kmsConfig.getProjectId());
        if (StringUtils.isNotEmpty(huaweiConfig.getSecurityToken())) {
            auth = auth.withSecurityToken(huaweiConfig.getSecurityToken());
        }

        // 从密钥胶囊获取或使用本地接入点配置
        AccessPointConfig accessPointConfig = huaweiConfig.getKeyCapsuleConfig().getAccessPointConfig();
        ProofInfo proofInfo = new ProofInfo();
        proofInfo.setType(keyCapsule.getAccessPointType());
        proofInfo.setKeyCapsule(keyCapsule.getDatakeyCapsule());
        proofInfo.setEncryptedPrivateKey(accessPointConfig.getEncryptedPrivateKey());
        proofInfo.setPrivateKeyDecryptCallback(accessPointConfig.getPrivateKeyDecryptCallback());
        proofInfo.setServiceAccount(accessPointConfig.getServiceAccount());

        // 收集证明文档
        AttestationDocument attestationDocument = ProofCollectorFactory.collect(proofInfo);

        // 调用KMS解密密钥胶囊
        byte[] plaintextDataKey = decryptKeyCapsuleByKms(keyCapsule, attestationDocument, kmsConfig, auth);

        dataKeyMaterials.setPlaintextDataKey(
            new SecretKeySpec(plaintextDataKey, dataKeyMaterials.getCryptoAlgorithm().getSecKeyAlgorithm()));
    }

    private KMSConfig getKMSConfig(CiphertextDataKey ciphertextDataKey) {
        return new KMSConfig(ciphertextDataKey.getRegion(), ciphertextDataKey.getKeyId(),
                ciphertextDataKey.getProjectId(), ciphertextDataKey.getEndPoint());
    }

    @Override
    public DataKeyMaterials encryptDataKey(DataKeyMaterials dataKeyMaterials) {
        // 密钥胶囊模式下，CiphertextDataKey的dataKey就是胶囊
        KeyCapsuleConfig keyCapsuleConfig = getHuaweiConfig().getKeyCapsuleConfig();
        KMSConfig kmsConfig = Utils.getCapsuleKMSConfig(getHuaweiConfig().getKmsConfigList(), keyCapsuleConfig);
        String region = keyCapsuleConfig.getRegion();
        String keyId = kmsConfig.getKeyId();
        String projectId = kmsConfig.getProjectId();
        String endpoint = kmsConfig.getEndPoint();
        if (StringUtils.isEmpty(endpoint)) {
            try {
                Region kmsRegion = KmsRegion.valueOf(keyCapsuleConfig.getRegion());
                endpoint = kmsRegion.getEndpoints().get(0);
            } catch (IllegalArgumentException e) {
                throw new HuaweicloudException("Invalid KMS region: " + keyCapsuleConfig.getRegion(), e);
            }
        }
        if (StringUtils.isEmpty(endpoint)) {
            throw new HuaweicloudException(ErrorMessage.END_POINT_NOT_NULL.getMessage());
        }
        List<CiphertextDataKey> ciphertextDataKeys = new ArrayList<>();
        byte[] cipherDataKeyBytes = null;
        try {
            cipherDataKeyBytes = Utils.hexToBytes(dataKeyMaterials.getKeyCapsule().getDatakeyCapsule());
        } catch (DecoderException e) {
            throw new HuaweicloudException(ErrorMessage.KMS_CREATE_KEY_CAPSULE_EXCEPTION.getMessage(), e);
        }
        ciphertextDataKeys.add(new CiphertextDataKey(cipherDataKeyBytes, new KMSConfig(region, keyId, projectId, endpoint)));
        dataKeyMaterials.setCiphertextDataKeys(ciphertextDataKeys);
        return dataKeyMaterials;
    }

    /**
     * 调用KMS解密密钥胶囊
     */
    private byte[] decryptKeyCapsuleByKms(KeyCapsule keyCapsule, AttestationDocument attestationDocument, KMSConfig kmsConfig, ICredential auth) {
        try {
            KmsHttpClient client = new KmsHttpClient(getHuaweiConfig().getAk(), getHuaweiConfig().getSk(), getHuaweiConfig().getSecurityToken(), kmsConfig);
            DecryptKeyCapsuleRequest requestBody = new DecryptKeyCapsuleRequest();
            requestBody.setKeyId(keyCapsule.getKeyId());
            requestBody.setDatakeyCapsule(keyCapsule.getDatakeyCapsule());
            requestBody.setAttestationDocument(attestationDocument);
            DecryptKeyCapsuleResponse response = client.post("/kms/datakey-capsule/decrypt", requestBody, DecryptKeyCapsuleResponse.class);
            keyCapsule.setInstanceId(response.getInstanceId());
            return Utils.hexToBytes(response.getDatakey());
        } catch (DecoderException e) {
            throw new HuaweicloudException("Failed to decrypt key capsule", e);
        }
    }

    /**
     * 获取主密钥规格
     */
    private String getKeySpec(KmsClient kmsClient, String keyId) {
        ListKeyDetailRequest request = new ListKeyDetailRequest()
            .withBody(new OperateKeyRequestBody().withKeyId(keyId));
        com.huaweicloud.sdk.kms.v2.model.ListKeyDetailResponse response =
            kmsClient.listKeyDetail(request);
        return response.getKeyInfo().getKeySpec().getValue();
    }

    /**
     * 获取KMS客户端（使用父类静态缓存）
     */
    private KmsClient getKmsClient(KMSConfig kmsConfig, ICredential auth) {
        String cacheKey = getHuaweiConfig().getAk() + getHuaweiConfig().getSk() + kmsConfig.getRegion();
        return kmsClientHashMap.computeIfAbsent(cacheKey, k -> {
            Region region;
            if (Utils.isEmpty(kmsConfig.getEndPoint())) {
                region = KmsRegion.valueOf(kmsConfig.getRegion());
            } else {
                region = new Region(kmsConfig.getRegion(), kmsConfig.getEndPoint());
            }
            return KmsClient.newBuilder()
                .withCredential(auth)
                .withRegion(region)
                .withEndpoints(Collections.singletonList(kmsConfig.getEndPoint()))
                .build();
        });
    }

}