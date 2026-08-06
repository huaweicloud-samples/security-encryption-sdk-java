package com.huaweicloud.encryptionsdk.keyrings.kmskeyring;

import com.huaweicloud.encryptionsdk.HuaweiConfig;
import com.huaweicloud.encryptionsdk.common.Utils;
import com.huaweicloud.encryptionsdk.exception.EncryptException;
import com.huaweicloud.encryptionsdk.exception.ErrorMessage;
import com.huaweicloud.encryptionsdk.keyrings.Keyring;
import com.huaweicloud.encryptionsdk.model.CiphertextDataKey;
import com.huaweicloud.encryptionsdk.model.DataKeyMaterials;
import com.huaweicloud.encryptionsdk.model.KMSConfig;
import com.huaweicloud.sdk.core.auth.BasicCredentials;
import com.huaweicloud.sdk.core.auth.ICredential;
import com.huaweicloud.sdk.core.region.Region;
import com.huaweicloud.sdk.kms.v2.KmsClient;
import com.huaweicloud.sdk.kms.v2.model.CreateDatakeyRequestBody;
import com.huaweicloud.sdk.kms.v2.model.DecryptDatakeyRequest;
import com.huaweicloud.sdk.kms.v2.model.DecryptDatakeyRequestBody;
import com.huaweicloud.sdk.kms.v2.model.DecryptDatakeyResponse;
import com.huaweicloud.sdk.kms.v2.model.EncryptDatakeyRequest;
import com.huaweicloud.sdk.kms.v2.model.EncryptDatakeyRequestBody;
import com.huaweicloud.sdk.kms.v2.model.EncryptDatakeyResponse;
import com.huaweicloud.sdk.kms.v2.model.ListKeyDetailRequest;
import com.huaweicloud.sdk.kms.v2.model.ListKeyDetailResponse;
import com.huaweicloud.sdk.kms.v2.model.OperateKeyRequestBody;
import com.huaweicloud.sdk.kms.v2.region.KmsRegion;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

/**
 * @description: kms实现keyring基类
 */
public abstract class KMSKeyring implements Keyring {

    private static final Logger LOGGER = LoggerFactory.getLogger(KMSKeyring.class);

    /**
     * kms服务版本号
     */
    private static final String KMS_INTERFACE_VERSION = "v2.0";

    /**
     * kms加密前，根据数据密钥计算hash值
     */
    public static final String SHA256 = "SHA256";

    public static final String SM3 = "SM3";

    private HuaweiConfig huaweiConfig;

    public static final Map<String, KmsClient> kmsClientHashMap = new HashMap<>();

    public HuaweiConfig getHuaweiConfig() {
        return huaweiConfig;
    }

    public void setHuaweiConfig(HuaweiConfig huaweiConfig) {
        this.huaweiConfig = huaweiConfig;
    }

    /**
     * @return void
     * @Description ：解密数据密钥，实际实现由子类定义
     * @Param [dataKeyMaterials]
     **/
    public abstract void doDecrypt(DataKeyMaterials dataKeyMaterials);

    @Override
    public DataKeyMaterials encryptDataKey(DataKeyMaterials dataKeyMaterials)
        throws ExecutionException, InterruptedException, DecoderException {
        doEncrypt(dataKeyMaterials);
        return dataKeyMaterials;
    }

    @Override
    public DataKeyMaterials decryptDataKey(DataKeyMaterials dataKeyMaterials) {
        doDecrypt(dataKeyMaterials);
        return dataKeyMaterials;
    }

    /**
     * @return void
     * @Description ；加密数据密钥
     * @Param [dataKeyMaterials]
     **/
    private void doEncrypt(DataKeyMaterials dataKeyMaterials)
        throws ExecutionException, InterruptedException, DecoderException {
        List<KMSConfig> kmsConfigList = huaweiConfig.getKmsConfigList();
        ArrayList<CiphertextDataKey> ciphertextDataKeys = new ArrayList<>();
        List<CompletableFuture> futureList = new ArrayList<>();
        for (KMSConfig kmsConfig : kmsConfigList) {
            CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
                BasicCredentials auth = new BasicCredentials().withAk(huaweiConfig.getAk())
                    .withSk(huaweiConfig.getSk())
                    .withProjectId(kmsConfig.getProjectId());
                if (StringUtils.isNotEmpty(huaweiConfig.getSecurityToken())) {
                    auth = auth.withSecurityToken(huaweiConfig.getSecurityToken());
                }
                EncryptDatakeyResponse response = null;
                try {
                    response = kmsEncryptDataKey(kmsConfig.getRegion(), kmsConfig.getEndPoint(), kmsConfig.getKeyId(),
                        auth, dataKeyMaterials);
                    byte[] cipherDataKeyBytes = Utils.hexToBytes(response.getCipherText());
                    CiphertextDataKey ciphertextDataKey = null;
                    if (huaweiConfig.isDiscovery()) {
                        ciphertextDataKey = new CiphertextDataKey(cipherDataKeyBytes, kmsConfig);
                    } else {
                        ciphertextDataKey = new CiphertextDataKey(cipherDataKeyBytes, null);
                    }
                    ciphertextDataKeys.add(ciphertextDataKey);
                } catch (DecoderException e) {
                    LOGGER.warn(
                        "encrypt data key error by kms server,please check the server information is right,region is :{},keyId is:{}",
                        kmsConfig.getRegion(), kmsConfig.getKeyId());
                }
            });
            futureList.add(future);
        }
        CompletableFuture<Void> completableFuture = CompletableFuture.allOf(
            futureList.toArray(new CompletableFuture[0]));
        completableFuture.get();
        if (ciphertextDataKeys.size() <= 0) {
            throw new EncryptException(ErrorMessage.ENCRYPT_DATA_KEY_EXCEPTION.getMessage());
        }
        dataKeyMaterials.setCiphertextDataKeys(ciphertextDataKeys);

    }

    private EncryptDatakeyResponse kmsEncryptDataKey(String regionStr, String endPoint, String keyId, ICredential auth,
        DataKeyMaterials dataKeyMaterials) throws DecoderException {
        KmsClient kmsClient = getKmsClient(regionStr, endPoint, auth);
        SecretKey plaintextDataKey = dataKeyMaterials.getPlaintextDataKey();
        String dataKey = Utils.bytesToHex(plaintextDataKey.getEncoded());
        int length = dataKey.length();
        String keySqpec = getKeySqpec(kmsClient, keyId);
        String digestAl;
        if (CreateDatakeyRequestBody.KeySpecEnum.AES_256.getValue().equals(keySqpec)) {
            digestAl = SHA256;
        } else {
            digestAl = SM3;
        }
        byte[] tmpDigest = Utils.commonHash(plaintextDataKey.getEncoded(), digestAl);
        dataKey += new String(Hex.encodeHex(tmpDigest));
        EncryptDatakeyRequest encryptDataRequest = new EncryptDatakeyRequest().withBody(
            new EncryptDatakeyRequestBody().withKeyId(keyId)
                .withPlainText(dataKey)
                .withDatakeyPlainLength(String.valueOf(length / 2)));
        return kmsClient.encryptDatakey(encryptDataRequest);
    }

    private String getKeySqpec(KmsClient kmsClient, String keyId) {
        ListKeyDetailRequest request = new ListKeyDetailRequest().withBody(
            new OperateKeyRequestBody().withKeyId(keyId));
        ListKeyDetailResponse response = kmsClient.listKeyDetail(request);
        return response.getKeyInfo().getKeySpec().getValue();
    }

    private KmsClient getKmsClient(String regionStr, String endPoint, ICredential auth) {
        KmsClient kmsClient;
        if (kmsClientHashMap.containsKey(huaweiConfig.getAk() + huaweiConfig.getSk() + regionStr)) {
            kmsClient = kmsClientHashMap.get(huaweiConfig.getAk() + huaweiConfig.getSk() + regionStr);
        } else {
            Region region;
            if (Utils.isEmpty(endPoint)) {
                region = KmsRegion.valueOf(regionStr);
            } else {
                region = new Region(regionStr, endPoint);
            }
            kmsClient = KmsClient.newBuilder()
                .withCredential(auth)
                .withRegion(region)
                .withEndpoints(Collections.singletonList(endPoint))
                .build();
            kmsClientHashMap.put(huaweiConfig.getAk() + huaweiConfig.getSk() + regionStr, kmsClient);
        }
        return kmsClient;
    }

    /**
     * @return void
     * @Description ：解密数据密钥具体流程
     * @Param [dataKeyMaterials]
     **/
    public void realDecrypt(DataKeyMaterials dataKeyMaterials) {
        List<KMSConfig> kmsConfigList = huaweiConfig.getKmsConfigList();
        List<CiphertextDataKey> ciphertextDataKeys = dataKeyMaterials.getCiphertextDataKeys();
        for (KMSConfig kmsConfig : kmsConfigList) {
            BasicCredentials auth = new BasicCredentials().withAk(huaweiConfig.getAk())
                .withSk(huaweiConfig.getSk())
                .withProjectId(kmsConfig.getProjectId());
            if (StringUtils.isNotEmpty(huaweiConfig.getSecurityToken())) {
                auth = auth.withSecurityToken(huaweiConfig.getSecurityToken());
            }
            for (CiphertextDataKey ciphertextDataKey : ciphertextDataKeys) {
                try {
                    String regionStr = kmsConfig.getRegion();
                    String endPoint = kmsConfig.getEndPoint();
                    String keyId = kmsConfig.getKeyId();
                    KmsClient kmsClient = getKmsClient(regionStr, endPoint, auth);
                    String encodeDataKey = Utils.bytesToHex(ciphertextDataKey.getDataKey());
                    DecryptDatakeyRequest decryptDataRequest = new DecryptDatakeyRequest().withBody(
                        new DecryptDatakeyRequestBody().withKeyId(keyId)
                            .withCipherText(encodeDataKey)
                            .withDatakeyCipherLength("32"));
                    DecryptDatakeyResponse decryptDataResponse = kmsClient.decryptDatakey(decryptDataRequest);
                    byte[] plaintBytes = Hex.decodeHex(decryptDataResponse.getDataKey().toCharArray());
                    String algorithmName = dataKeyMaterials.getCryptoAlgorithm().getSecKeyAlgorithm();
                    dataKeyMaterials.setPlaintextDataKey(
                        new SecretKeySpec(plaintBytes, 0, plaintBytes.length, algorithmName));
                    return;
                } catch (Exception e) {
                    LOGGER.warn("one master key may be not match when decrypt data key in KMSKeyring.class");
                }

            }
        }
    }

}
