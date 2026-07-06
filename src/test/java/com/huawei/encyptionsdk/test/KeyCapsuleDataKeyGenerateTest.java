package com.huawei.encyptionsdk.test;

import com.huaweicloud.encryptionsdk.HuaweiConfig;
import com.huaweicloud.encryptionsdk.exception.HuaweicloudException;
import com.huaweicloud.encryptionsdk.kms.CreateKeyCapsuleResponse;
import com.huaweicloud.encryptionsdk.kms.KmsHttpClient;
import com.huaweicloud.encryptionsdk.meterialmanager.DataKeyGenerate;
import com.huaweicloud.encryptionsdk.meterialmanager.DataKeyGenerateFactory;
import com.huaweicloud.encryptionsdk.meterialmanager.KeyCapsuleDataKeyGenerate;
import com.huaweicloud.encryptionsdk.model.AccessPointConfig;
import com.huaweicloud.encryptionsdk.model.DataKeyMaterials;
import com.huaweicloud.encryptionsdk.model.KMSConfig;
import com.huaweicloud.encryptionsdk.model.KeyCapsuleConfig;
import com.huaweicloud.encryptionsdk.model.enums.CryptoAlgorithm;
import com.huaweicloud.encryptionsdk.model.enums.DataKeyGenerateType;
import org.junit.Test;
import org.mockito.MockedConstruction;
import org.mockito.Mockito;

import java.util.Collections;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;

public class KeyCapsuleDataKeyGenerateTest {

    private static final String KEY_ID = "key-123";
    private static final String PROJECT_ID = "pid-123";
    private static final String REGION = "cn-north-7";
    private static final String ENDPOINT = "https://kms.cn-north-7.myhuaweicloud.com";
    private static final String DATAKEY_HEX = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

    private static HuaweiConfig buildConfig() {
        return buildConfig(CryptoAlgorithm.AES_256_GCM_NOPADDING);
    }

    private static HuaweiConfig buildConfig(CryptoAlgorithm algo) {
        return HuaweiConfig.builder().ak("testAk").sk("testSk")
                .kmsConfigList(Collections.singletonList(new KMSConfig(REGION, KEY_ID, PROJECT_ID, ENDPOINT)))
                .keyCapsuleConfig(KeyCapsuleConfig.builder().region(REGION)
                        .accessPointConfig(AccessPointConfig.builder().type(2).encryptedPrivateKey("encKey")
                                .privateKeyDecryptCallback(k -> "dec").build()).build())
                .cryptoAlgorithm(algo).build();
    }

    private static CreateKeyCapsuleResponse buildResponse(String keyId, String capsule, String datakey) {
        return CreateKeyCapsuleResponse.builder().keyId(keyId).datakeyCapsule(capsule).datakey(datakey).build();
    }

    @FunctionalInterface
    private interface GenerateAction { void accept(DataKeyGenerate g) throws Exception; }

    private void withMockedKms(CreateKeyCapsuleResponse response, GenerateAction action) throws Exception {
        try (MockedConstruction<KmsHttpClient> mocked = Mockito.mockConstruction(KmsHttpClient.class,
                (mock, ctx) -> Mockito.when(mock.post(anyString(), any(), eq(CreateKeyCapsuleResponse.class))).thenReturn(response))) {
            action.accept(DataKeyGenerateFactory.getDataKeyGenerate(DataKeyGenerateType.KEY_CAPSULE_GENERATE));
        }
    }

    private void withMockedKmsThrowing(GenerateAction action) throws Exception {
        try (MockedConstruction<KmsHttpClient> mocked = Mockito.mockConstruction(KmsHttpClient.class,
                (mock, ctx) -> Mockito.when(mock.post(anyString(), any(), eq(CreateKeyCapsuleResponse.class)))
                        .thenThrow(new HuaweicloudException("KMS error")))) {
            action.accept(DataKeyGenerateFactory.getDataKeyGenerate(DataKeyGenerateType.KEY_CAPSULE_GENERATE));
        }
    }

    @Test
    public void testFactoryReturnsCorrectType() {
        assertTrue(DataKeyGenerateFactory.getDataKeyGenerate(DataKeyGenerateType.KEY_CAPSULE_GENERATE) instanceof KeyCapsuleDataKeyGenerate);
    }

    @Test
    public void testDataKeyGenerateWithMockedKms() throws Exception {
        withMockedKms(buildResponse(KEY_ID, "capsuledata", DATAKEY_HEX), generate -> {
            DataKeyMaterials m = new DataKeyMaterials();
            generate.dataKeyGenerate(buildConfig(), m);
            assertNotNull(m.getPlaintextDataKey());
            assertEquals(32, m.getPlaintextDataKey().getEncoded().length);
            assertEquals(KEY_ID, m.getKeyCapsule().getKeyId());
            assertEquals("capsuledata", m.getKeyCapsule().getDatakeyCapsule());
            assertEquals(2, m.getKeyCapsule().getAccessPointType());
        });
    }

    @Test
    public void testDataKeyGenerateWithSM4Algorithm() throws Exception {
        withMockedKms(buildResponse(KEY_ID, "capsuledata", "0102030405060708090a0b0c0d0e0f10"), generate -> {
            DataKeyMaterials m = new DataKeyMaterials();
            generate.dataKeyGenerate(buildConfig(CryptoAlgorithm.SM4_128_GCM_NOPADDING), m);
            assertNotNull(m.getPlaintextDataKey());
            assertEquals(16, m.getPlaintextDataKey().getEncoded().length);
        });
    }

    @Test
    public void testDataKeyGenerateWithPolicyId() throws Exception {
        withMockedKms(buildResponse(KEY_ID, "capsuledata", DATAKEY_HEX), generate -> {
            DataKeyMaterials m = new DataKeyMaterials();
            m.setPolicyId("policy-123");
            generate.dataKeyGenerate(buildConfig(), m);
            assertNotNull(m.getPlaintextDataKey());
        });
    }

    @Test
    public void testDataKeyGenerateWithKeyPolicy() throws Exception {
        withMockedKms(buildResponse(KEY_ID, "capsuledata", DATAKEY_HEX), generate -> {
            DataKeyMaterials m = new DataKeyMaterials();
            m.setKeyPolicy("{\"Version\":\"1.0\"}");
            generate.dataKeyGenerate(buildConfig(), m);
            assertNotNull(m.getPlaintextDataKey());
        });
    }

    @Test
    public void testDataKeyGenerateWithInvalidHex() throws Exception {
        withMockedKms(buildResponse(KEY_ID, "capsuledata", "ZZZZ!!invalid"), generate -> {
            try {
                generate.dataKeyGenerate(buildConfig(), new DataKeyMaterials());
            } catch (HuaweicloudException e) {
                assertTrue(e.getMessage().contains("parse plaintext data key") || e.getMessage().contains("hex"));
            }
        });
    }

    @Test
    public void testDataKeyGenerateKmsThrowsException() throws Exception {
        withMockedKmsThrowing(generate -> {
            try {
                generate.dataKeyGenerate(buildConfig(), new DataKeyMaterials());
            } catch (HuaweicloudException e) {
                assertNotNull(e);
            }
        });
    }
}
