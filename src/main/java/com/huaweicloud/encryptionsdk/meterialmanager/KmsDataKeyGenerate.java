package com.huaweicloud.encryptionsdk.meterialmanager;

import com.huaweicloud.encryptionsdk.HuaweiConfig;
import com.huaweicloud.encryptionsdk.common.Utils;
import com.huaweicloud.encryptionsdk.exception.ErrorMessage;
import com.huaweicloud.encryptionsdk.exception.HuaweicloudException;
import com.huaweicloud.encryptionsdk.model.DataKeyMaterials;
import com.huaweicloud.encryptionsdk.model.KMSConfig;
import com.huaweicloud.encryptionsdk.model.enums.CryptoAlgorithm;
import com.huaweicloud.sdk.core.auth.BasicCredentials;
import com.huaweicloud.sdk.core.auth.ICredential;
import com.huaweicloud.sdk.core.region.Region;
import com.huaweicloud.sdk.kms.v2.KmsClient;
import com.huaweicloud.sdk.kms.v2.model.CreateDatakeyRequest;
import com.huaweicloud.sdk.kms.v2.model.CreateDatakeyRequestBody;
import com.huaweicloud.sdk.kms.v2.model.CreateDatakeyResponse;
import com.huaweicloud.sdk.kms.v2.region.KmsRegion;
import org.apache.commons.codec.DecoderException;

import javax.crypto.spec.SecretKeySpec;
import java.util.Collections;
import java.util.List;

/**
 * @description: 通过kms生成数据密钥
 */
public class KmsDataKeyGenerate implements DataKeyGenerate {

    @Override
    public void dataKeyGenerate(HuaweiConfig huaweiConfig, DataKeyMaterials dataKeyMaterials) {
        List<KMSConfig> kmsConfigList = huaweiConfig.getKmsConfigList();
        if (Utils.isEmpty(kmsConfigList)) {
            throw new HuaweicloudException(ErrorMessage.CONFIG_NULL_ERROR.getMessage());
        }
        for (KMSConfig kmsConfig : kmsConfigList) {
            // 只需要创建一个数据密钥即可
            ICredential auth = new BasicCredentials().withAk(huaweiConfig.getAk())
                .withSk(huaweiConfig.getSk())
                .withProjectId(kmsConfig.getProjectId());
            CreateDatakeyResponse response = createDataKeyByKms(kmsConfig.getRegion(), kmsConfig.getKeyId(),
                kmsConfig.getEndPoint(), auth, huaweiConfig.getCryptoAlgorithm());
            byte[] plaintBytes;
            try {
                plaintBytes = Utils.hexToBytes(response.getPlainText());
            } catch (DecoderException e) {
                throw new HuaweicloudException(e);
            }
            dataKeyMaterials.setPlaintextDataKey(
                new SecretKeySpec(plaintBytes, huaweiConfig.getCryptoAlgorithm().getSecKeyAlgorithm()));
            return;
        }
    }

    private CreateDatakeyResponse createDataKeyByKms(String regionStr, String keyId, String endPoint, ICredential auth,
        CryptoAlgorithm algorithm) {
        try {
            Region region;
            if (Utils.isEmpty(endPoint)) {
                region = KmsRegion.valueOf(regionStr);
            } else {
                region = new Region(regionStr, endPoint);
            }
            KmsClient client = KmsClient.newBuilder()
                .withCredential(auth)
                .withRegion(region)
                .withEndpoints(Collections.singletonList(endPoint))
                .build();
            CreateDatakeyRequest request = new CreateDatakeyRequest();
            String keySpec = algorithm.getKeySpec();
            if (CryptoAlgorithm.SM4_128_GCM_NOPADDING.getKeySpec().equalsIgnoreCase(keySpec)) {
                keySpec = CryptoAlgorithm.AES_128_GCM_NOPADDING.getKeySpec();
            }
            CreateDatakeyRequestBody body = new CreateDatakeyRequestBody().withDatakeyLength(
                    String.valueOf(algorithm.getKeyLen() * 8))
                .withKeyId(keyId)
                .withKeySpec(CreateDatakeyRequestBody.KeySpecEnum.fromValue(keySpec));
            request.withBody(body);
            return client.createDatakey(request);
        } catch (Exception e) {
            throw new HuaweicloudException(ErrorMessage.KMS_CREATE_KEY_EXCEPTION.getMessage(), e);
        }
    }
}
