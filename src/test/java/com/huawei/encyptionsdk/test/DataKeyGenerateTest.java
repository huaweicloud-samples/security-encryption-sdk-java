package com.huawei.encyptionsdk.test;

import com.huaweicloud.encryptionsdk.HuaweiConfig;
import com.huaweicloud.encryptionsdk.exception.HuaweicloudException;
import com.huaweicloud.encryptionsdk.meterialmanager.DataKeyGenerate;
import com.huaweicloud.encryptionsdk.meterialmanager.DataKeyGenerateFactory;
import com.huaweicloud.encryptionsdk.meterialmanager.KeyCapsuleDataKeyGenerate;
import com.huaweicloud.encryptionsdk.model.DataKeyMaterials;
import com.huaweicloud.encryptionsdk.model.KMSConfig;
import com.huaweicloud.encryptionsdk.model.enums.CryptoAlgorithm;
import com.huaweicloud.encryptionsdk.model.enums.DataKeyGenerateType;
import com.huaweicloud.sdk.kms.v2.KmsClient;
import com.huaweicloud.sdk.kms.v2.model.CreateDatakeyResponse;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.MockedConstruction;
import org.mockito.Mockito;

import java.security.NoSuchAlgorithmException;
import java.util.Collections;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

public class DataKeyGenerateTest {

    private static final String PROJECT_ID = "7c55d8e5238d42e49fd9ce11b24b035b";

    private static final String REGION = "cn-north-7";

    private static final String KEYID = "c1f52e49-8e5c-4772-8713-ead33ed9faa2";

    private static final String ENDPOINT = "https://kms.cn-north-7.myhuaweicloud.com";

    private static final String MOCK_PLAINTEXT_HEX = "6130616461636433643263396464346437333263386265346236373238643962";

    @Test
    public void Should_ok_When_LocalGenerate() throws NoSuchAlgorithmException {
        DataKeyGenerate dataKeyGenerate = DataKeyGenerateFactory.getDataKeyGenerate(DataKeyGenerateType.LOCAL_GENERATE);
        HuaweiConfig huaweiConfig = HuaweiConfig.builder()
                .cryptoAlgorithm(CryptoAlgorithm.AES_256_GCM_NOPADDING)
                .build();
        DataKeyMaterials dataKeyMaterials = new DataKeyMaterials();
        dataKeyGenerate.dataKeyGenerate(huaweiConfig, dataKeyMaterials);
        Assert.assertNotNull(dataKeyMaterials.getPlaintextDataKey().getEncoded());
    }

    @Test
    public void Should_ok_When_KMSGenerate() throws NoSuchAlgorithmException {
        CreateDatakeyResponse mockResponse = new CreateDatakeyResponse();
        mockResponse.setPlainText(MOCK_PLAINTEXT_HEX);
        mockResponse.setCipherText("mockCipherText");

        try (MockedConstruction<KmsClient> mocked = Mockito.mockConstruction(KmsClient.class,
                (mock, context) -> when(mock.createDatakey(any())).thenReturn(mockResponse))) {

            DataKeyGenerate dataKeyGenerate = DataKeyGenerateFactory.getDataKeyGenerate(DataKeyGenerateType.KMS_GENERATE);
            HuaweiConfig huaweiConfig = HuaweiConfig.builder()
                    .sk("mockSk")
                    .ak("mockAk")
                    .kmsConfigList(Collections.singletonList(new KMSConfig(REGION, KEYID, PROJECT_ID, ENDPOINT)))
                    .cryptoAlgorithm(CryptoAlgorithm.AES_256_GCM_NOPADDING)
                    .build();
            DataKeyMaterials dataKeyMaterials = new DataKeyMaterials();
            dataKeyGenerate.dataKeyGenerate(huaweiConfig, dataKeyMaterials);

            Assert.assertNotNull(dataKeyMaterials.getPlaintextDataKey());
            Assert.assertEquals(32, dataKeyMaterials.getPlaintextDataKey().getEncoded().length);
        }
    }

    @Test
    public void Should_ok_When_KeyCapsuleGenerate() {
        DataKeyGenerate dataKeyGenerate = DataKeyGenerateFactory.getDataKeyGenerate(DataKeyGenerateType.KEY_CAPSULE_GENERATE);
        Assert.assertTrue(dataKeyGenerate instanceof KeyCapsuleDataKeyGenerate);
    }

    @Test(expected = NullPointerException.class)
    public void Should_throw_When_NullGenerateType() {
        DataKeyGenerateFactory.getDataKeyGenerate(null);
    }

    @Test(expected = HuaweicloudException.class)
    public void Should_throw_When_KMSGenerateEmptyConfig() throws Exception {
        DataKeyGenerate dataKeyGenerate = DataKeyGenerateFactory.getDataKeyGenerate(DataKeyGenerateType.KMS_GENERATE);
        HuaweiConfig huaweiConfig = HuaweiConfig.builder()
                .cryptoAlgorithm(CryptoAlgorithm.AES_256_GCM_NOPADDING)
                .build();
        DataKeyMaterials dataKeyMaterials = new DataKeyMaterials();
        dataKeyGenerate.dataKeyGenerate(huaweiConfig, dataKeyMaterials);
    }

    @Test
    public void Should_ok_When_KMSGenerateSM4() throws Exception {
        CreateDatakeyResponse mockResponse = new CreateDatakeyResponse();
        mockResponse.setPlainText("61306164616364336130616461636433");
        mockResponse.setCipherText("mockCipherText");

        try (MockedConstruction<KmsClient> mocked = Mockito.mockConstruction(KmsClient.class,
                (mock, context) -> when(mock.createDatakey(any())).thenReturn(mockResponse))) {

            DataKeyGenerate dataKeyGenerate = DataKeyGenerateFactory.getDataKeyGenerate(DataKeyGenerateType.KMS_GENERATE);
            HuaweiConfig huaweiConfig = HuaweiConfig.builder()
                    .sk("mockSk")
                    .ak("mockAk")
                    .kmsConfigList(Collections.singletonList(new KMSConfig(REGION, KEYID, PROJECT_ID, ENDPOINT)))
                    .cryptoAlgorithm(CryptoAlgorithm.SM4_128_GCM_NOPADDING)
                    .build();
            DataKeyMaterials dataKeyMaterials = new DataKeyMaterials();
            dataKeyGenerate.dataKeyGenerate(huaweiConfig, dataKeyMaterials);

            Assert.assertNotNull(dataKeyMaterials.getPlaintextDataKey());
            Assert.assertEquals(16, dataKeyMaterials.getPlaintextDataKey().getEncoded().length);
        }
    }
}
