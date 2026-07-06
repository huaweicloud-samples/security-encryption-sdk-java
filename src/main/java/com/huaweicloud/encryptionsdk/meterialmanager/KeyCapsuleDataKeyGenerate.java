package com.huaweicloud.encryptionsdk.meterialmanager;

import com.huaweicloud.encryptionsdk.HuaweiConfig;
import com.huaweicloud.encryptionsdk.common.Utils;
import com.huaweicloud.encryptionsdk.exception.ErrorMessage;
import com.huaweicloud.encryptionsdk.exception.HuaweicloudException;
import com.huaweicloud.encryptionsdk.kms.CreateKeyCapsuleRequest;
import com.huaweicloud.encryptionsdk.kms.CreateKeyCapsuleResponse;
import com.huaweicloud.encryptionsdk.kms.KmsHttpClient;
import com.huaweicloud.encryptionsdk.model.DataKeyMaterials;
import com.huaweicloud.encryptionsdk.model.KMSConfig;
import com.huaweicloud.encryptionsdk.model.KeyCapsule;
import com.huaweicloud.encryptionsdk.model.KeyCapsuleConfig;
import com.huaweicloud.encryptionsdk.model.enums.CryptoAlgorithm;
import com.huaweicloud.sdk.core.auth.BasicCredentials;
import com.huaweicloud.sdk.core.auth.ICredential;
import com.huaweicloud.sdk.kms.v2.KmsClient;
import com.huaweicloud.sdk.kms.v2.model.ListKeyDetailRequest;
import com.huaweicloud.sdk.kms.v2.model.OperateKeyRequestBody;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.spec.SecretKeySpec;

/**
 * 密钥胶囊模式数据密钥生成器
 * 调用KMS create-datakey-capsule API，同时返回密钥胶囊和数据密钥明文
 */
public class KeyCapsuleDataKeyGenerate implements DataKeyGenerate {

    private static final Logger LOGGER = LoggerFactory.getLogger(KeyCapsuleDataKeyGenerate.class);

    @Override
    public void dataKeyGenerate(HuaweiConfig huaweiConfig, DataKeyMaterials dataKeyMaterials) {
        KMSConfig kmsConfig = Utils.getCapsuleKMSConfig(huaweiConfig.getKmsConfigList(), huaweiConfig.getKeyCapsuleConfig());

        ICredential auth = new BasicCredentials()
            .withAk(huaweiConfig.getAk())
            .withSk(huaweiConfig.getSk())
            .withProjectId(kmsConfig.getProjectId());

        CreateKeyCapsuleResponse response = createKeyCapsuleByKms(dataKeyMaterials, huaweiConfig.getKeyCapsuleConfig(), huaweiConfig, kmsConfig, auth);
        KeyCapsule keyCapsule = parseKeyCapsule(response, huaweiConfig.getKeyCapsuleConfig());
        byte[] plaintextDataKey = parsePlaintextDataKey(response);

        dataKeyMaterials.setKeyCapsule(keyCapsule);
        dataKeyMaterials.setPlaintextDataKey(
            new SecretKeySpec(plaintextDataKey, huaweiConfig.getCryptoAlgorithm().getSecKeyAlgorithm()));
    }

    /**
     * 调用KMS创建密钥胶囊
     */
    private CreateKeyCapsuleResponse createKeyCapsuleByKms(
            DataKeyMaterials dataKeyMaterials, KeyCapsuleConfig config, HuaweiConfig huaweiConfig, KMSConfig kmsConfig, ICredential auth) {
        try {
            KmsHttpClient client = new KmsHttpClient(huaweiConfig.getAk(), huaweiConfig.getSk(), kmsConfig);
            CreateKeyCapsuleRequest request = buildRequestBody(dataKeyMaterials, config, huaweiConfig, kmsConfig);
            return client.post("/kms/datakey-capsule/create", request, CreateKeyCapsuleResponse.class);
        } catch (Exception e) {
            throw new HuaweicloudException(ErrorMessage.KMS_CREATE_KEY_EXCEPTION.getMessage(), e);
        }
    }

    /**
     * 构建请求体
     */
    private CreateKeyCapsuleRequest buildRequestBody(
            DataKeyMaterials dataKeyMaterials, KeyCapsuleConfig config, HuaweiConfig huaweiConfig, KMSConfig kmsConfig) {
        CryptoAlgorithm cryptoAlgorithm = huaweiConfig.getCryptoAlgorithm();
        CreateKeyCapsuleRequest body = CreateKeyCapsuleRequest.builder()
            .keyId(kmsConfig.getKeyId())
            .datakeyLength(cryptoAlgorithm.getDatakeyLength())
            .build();

        // 优先使用动态策略
        String policyId = dataKeyMaterials.getPolicyId();
        String keyPolicy = dataKeyMaterials.getKeyPolicy();

        // 回退到默认策略
        if (StringUtils.isEmpty(policyId) && StringUtils.isEmpty(keyPolicy)) {
            policyId = config.getDefaultPolicyId();
            keyPolicy = config.getDefaultKeyPolicy();
        }

        // 设置密钥策略（内联或引用）
        if (StringUtils.isNotEmpty(keyPolicy)) {
            body.setKeyPolicy(keyPolicy);
        } else if (StringUtils.isNotEmpty(policyId)) {
            body.setPolicyId(policyId);
        }

        return body;
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
     * 解析密钥胶囊响应
     */
    private KeyCapsule parseKeyCapsule(CreateKeyCapsuleResponse response, KeyCapsuleConfig config) {
        return KeyCapsule.builder()
            .keyId(response.getKeyId())
            .datakeyCapsule(response.getDatakeyCapsule())
            .accessPointType(config.getAccessPointConfig().getType())
            .build();
    }

    /**
     * 解析数据密钥明文
     */
    private byte[] parsePlaintextDataKey(CreateKeyCapsuleResponse response) {
        try {
            return Utils.hexToBytes(response.getDatakey());
        } catch (DecoderException e) {
            throw new HuaweicloudException("Failed to parse plaintext data key", e);
        }
    }

}