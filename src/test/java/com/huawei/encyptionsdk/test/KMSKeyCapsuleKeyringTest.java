package com.huawei.encyptionsdk.test;

import com.huaweicloud.encryptionsdk.HuaweiConfig;
import com.huaweicloud.encryptionsdk.exception.HuaweicloudException;
import com.huaweicloud.encryptionsdk.kms.DecryptKeyCapsuleResponse;
import com.huaweicloud.encryptionsdk.kms.KmsHttpClient;
import com.huaweicloud.encryptionsdk.keyrings.kmskeyring.KMSKeyCapsuleKeyring;
import com.huaweicloud.encryptionsdk.keyrings.kmskeyring.KMSKeyring;
import com.huaweicloud.encryptionsdk.model.AccessPointConfig;
import com.huaweicloud.encryptionsdk.model.CiphertextDataKey;
import com.huaweicloud.encryptionsdk.model.DataKeyMaterials;
import com.huaweicloud.encryptionsdk.model.KeyCapsule;
import com.huaweicloud.encryptionsdk.model.KeyCapsuleConfig;
import com.huaweicloud.encryptionsdk.model.KMSConfig;
import com.huaweicloud.encryptionsdk.model.enums.CryptoAlgorithm;
import com.huaweicloud.encryptionsdk.proof.AttestationDocument;
import com.huaweicloud.encryptionsdk.proof.ProofCollectorFactory;
import com.huaweicloud.encryptionsdk.proof.ProofInfo;
import com.huaweicloud.sdk.core.auth.BasicCredentials;
import com.huaweicloud.sdk.core.auth.ICredential;
import com.huaweicloud.sdk.kms.v2.KmsClient;
import com.huaweicloud.sdk.kms.v2.model.KeyDetails;
import com.huaweicloud.sdk.kms.v2.model.ListKeyDetailRequest;
import com.huaweicloud.sdk.kms.v2.model.ListKeyDetailResponse;
import org.junit.Test;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;

public class KMSKeyCapsuleKeyringTest {

    private static final String REGION = "cn-north-7";
    private static final String KEY_ID = "key-123";
    private static final String PROJECT_ID = "pid-123";
    private static final String ENDPOINT = "https://kms.cn-north-7.myhuaweicloud.com";

    private static KeyCapsule defaultKeyCapsule() {
        return KeyCapsule.builder().keyId(KEY_ID).datakeyCapsule("aabbccdd").accessPointType(2).build();
    }

    private static KMSConfig defaultKMSConfig() {
        return new KMSConfig(REGION, KEY_ID, PROJECT_ID, ENDPOINT);
    }

    private static DataKeyMaterials defaultDecryptMaterials() {
        DataKeyMaterials materials = new DataKeyMaterials();
        materials.setCryptoAlgorithm(CryptoAlgorithm.AES_256_GCM_NOPADDING);
        materials.setKeyCapsule(defaultKeyCapsule());
        List<CiphertextDataKey> cdkList = new ArrayList<>();
        cdkList.add(new CiphertextDataKey(new byte[]{1, 2, 3}, defaultKMSConfig()));
        materials.setCiphertextDataKeys(cdkList);
        return materials;
    }

    private static DataKeyMaterials defaultEncryptMaterials(String datakeyCapsule) {
        DataKeyMaterials materials = new DataKeyMaterials();
        materials.setCryptoAlgorithm(CryptoAlgorithm.AES_256_GCM_NOPADDING);
        materials.setKeyCapsule(KeyCapsule.builder().keyId(KEY_ID).datakeyCapsule(datakeyCapsule).accessPointType(2).build());
        return materials;
    }

    private static HuaweiConfig buildHuaweiConfig() {
        return HuaweiConfig.builder()
                .ak("testAk").sk("testSk")
                .kmsConfigList(Collections.singletonList(defaultKMSConfig()))
                .keyCapsuleConfig(KeyCapsuleConfig.builder()
                        .region(REGION)
                        .accessPointConfig(AccessPointConfig.builder()
                                .type(2).encryptedPrivateKey("encKey")
                                .privateKeyDecryptCallback(key -> "decrypted").build())
                        .build())
                .build();
    }

    private static HuaweiConfig buildHuaweiConfig(String region, String endpoint) {
        return HuaweiConfig.builder()
                .ak("testAk").sk("testSk")
                .kmsConfigList(Collections.singletonList(new KMSConfig(region, KEY_ID, PROJECT_ID, endpoint)))
                .keyCapsuleConfig(KeyCapsuleConfig.builder()
                        .region(region)
                        .accessPointConfig(AccessPointConfig.builder()
                                .type(2).encryptedPrivateKey("encKey")
                                .privateKeyDecryptCallback(k -> "dec").build())
                        .build())
                .build();
    }

    private static KMSKeyCapsuleKeyring configuredKeyring() {
        KMSKeyCapsuleKeyring keyring = new KMSKeyCapsuleKeyring();
        keyring.setHuaweiConfig(buildHuaweiConfig());
        return keyring;
    }

    private static KMSKeyCapsuleKeyring configuredKeyring(String region, String endpoint) {
        KMSKeyCapsuleKeyring keyring = new KMSKeyCapsuleKeyring();
        keyring.setHuaweiConfig(buildHuaweiConfig(region, endpoint));
        return keyring;
    }

    private static MockedConstruction<KmsHttpClient> mockKmsConstruction(DecryptKeyCapsuleResponse response) {
        return Mockito.mockConstruction(KmsHttpClient.class,
                (mock, context) -> Mockito.when(mock.post(anyString(), any(), eq(DecryptKeyCapsuleResponse.class)))
                        .thenReturn(response));
    }

    private static MockedConstruction<KmsHttpClient> mockKmsConstructionThrowing() {
        return Mockito.mockConstruction(KmsHttpClient.class,
                (mock, context) -> Mockito.when(mock.post(anyString(), any(), eq(DecryptKeyCapsuleResponse.class)))
                        .thenThrow(new HuaweicloudException("KMS error")));
    }

    private static Method getDeclaredMethod(String name, Class<?>... paramTypes) throws Exception {
        Method method = KMSKeyCapsuleKeyring.class.getDeclaredMethod(name, paramTypes);
        method.setAccessible(true);
        return method;
    }

    @Test
    public void testInstanceCreation() {
        assertNotNull(new KMSKeyCapsuleKeyring());
    }

    @Test(expected = HuaweicloudException.class)
    public void testDoDecryptNullKeyCapsule() {
        DataKeyMaterials materials = new DataKeyMaterials();
        materials.setKeyCapsule(null);
        new KMSKeyCapsuleKeyring().doDecrypt(materials);
    }

    @Test(expected = HuaweicloudException.class)
    public void testDoDecryptEmptyCiphertextDataKeys() {
        DataKeyMaterials materials = new DataKeyMaterials();
        materials.setKeyCapsule(KeyCapsule.builder().keyId("kid").datakeyCapsule("dc").accessPointType(2).build());
        materials.setCiphertextDataKeys(new ArrayList<>());
        new KMSKeyCapsuleKeyring().doDecrypt(materials);
    }

    @Test(expected = HuaweicloudException.class)
    public void testDoDecryptNullCiphertextDataKeys() {
        DataKeyMaterials materials = new DataKeyMaterials();
        materials.setKeyCapsule(KeyCapsule.builder().keyId("kid").datakeyCapsule("dc").accessPointType(2).build());
        materials.setCiphertextDataKeys(null);
        new KMSKeyCapsuleKeyring().doDecrypt(materials);
    }

    @Test
    public void testEncryptDataKeyWithConfig() {
        DataKeyMaterials result = configuredKeyring().encryptDataKey(defaultEncryptMaterials("aabbccdd"));
        assertNotNull(result.getCiphertextDataKeys());
        assertEquals(1, result.getCiphertextDataKeys().size());
    }

    @Test(expected = HuaweicloudException.class)
    public void testEncryptDataKeyWithEmptyEndpoint() {
        configuredKeyring("cn-north-7", "").encryptDataKey(defaultEncryptMaterials("aabbccdd"));
    }

    @Test
    public void testEncryptDataKeyWithInvalidHex() {
        try {
            configuredKeyring().encryptDataKey(defaultEncryptMaterials("ZZZZ"));
        } catch (HuaweicloudException e) {
            assertTrue(e.getMessage().contains("key capsule"));
        }
    }

    @Test
    public void testEncryptDataKeyWithRegionEndpoint() {
        DataKeyMaterials result = configuredKeyring("cn-north-4", null)
                .encryptDataKey(defaultEncryptMaterials("aabbccdd"));
        assertNotNull(result.getCiphertextDataKeys());
        assertEquals(1, result.getCiphertextDataKeys().size());
    }

    @Test
    public void testDoDecryptWithMockedProofAndKms() {
        KMSKeyCapsuleKeyring keyring = configuredKeyring();
        DecryptKeyCapsuleResponse mockResponse = DecryptKeyCapsuleResponse.builder()
                .keyId(KEY_ID).datakey("aabbccdd").instanceId("inst-1").build();
        AttestationDocument mockDoc = AttestationDocument.builder().serviceToken("mock-token").build();

        try (MockedStatic<ProofCollectorFactory> proofMock = Mockito.mockStatic(ProofCollectorFactory.class);
             MockedConstruction<KmsHttpClient> constructionMock = mockKmsConstruction(mockResponse)) {
            proofMock.when(() -> ProofCollectorFactory.collect(any(ProofInfo.class))).thenReturn(mockDoc);
            DataKeyMaterials materials = defaultDecryptMaterials();
            keyring.doDecrypt(materials);
            assertNotNull(materials.getPlaintextDataKey());
            assertEquals(1, constructionMock.constructed().size());
        }
    }

    @Test
    public void testDoDecryptKmsThrowsException() {
        KMSKeyCapsuleKeyring keyring = configuredKeyring();
        AttestationDocument mockDoc = AttestationDocument.builder().serviceToken("mock-token").build();

        try (MockedStatic<ProofCollectorFactory> proofMock = Mockito.mockStatic(ProofCollectorFactory.class);
             MockedConstruction<KmsHttpClient> ignored = mockKmsConstructionThrowing()) {
            proofMock.when(() -> ProofCollectorFactory.collect(any(ProofInfo.class))).thenReturn(mockDoc);
            try {
                keyring.doDecrypt(defaultDecryptMaterials());
            } catch (HuaweicloudException e) {
                assertNotNull(e);
            }
        }
    }

    @Test
    public void testDoDecryptWithDecoderException() {
        KMSKeyCapsuleKeyring keyring = configuredKeyring();
        DecryptKeyCapsuleResponse mockResponse = DecryptKeyCapsuleResponse.builder()
                .keyId(KEY_ID).datakey("ZZZZ").instanceId("inst-1").build();
        AttestationDocument mockDoc = AttestationDocument.builder().serviceToken("mock-token").build();

        try (MockedStatic<ProofCollectorFactory> proofMock = Mockito.mockStatic(ProofCollectorFactory.class);
             MockedConstruction<KmsHttpClient> ignored = mockKmsConstruction(mockResponse)) {
            proofMock.when(() -> ProofCollectorFactory.collect(any(ProofInfo.class))).thenReturn(mockDoc);
            try {
                keyring.doDecrypt(defaultDecryptMaterials());
            } catch (HuaweicloudException e) {
                assertTrue(e.getMessage().contains("Failed to decrypt key capsule"));
            }
        }
    }

    @Test
    public void testDoDecryptProofCollectorThrows() {
        KMSKeyCapsuleKeyring keyring = configuredKeyring();

        try (MockedStatic<ProofCollectorFactory> proofMock = Mockito.mockStatic(ProofCollectorFactory.class)) {
            proofMock.when(() -> ProofCollectorFactory.collect(any(ProofInfo.class)))
                    .thenThrow(new HuaweicloudException("Proof collection failed"));
            try {
                keyring.doDecrypt(defaultDecryptMaterials());
            } catch (HuaweicloudException e) {
                assertTrue(e.getMessage().contains("Proof collection failed"));
            }
        }
    }

    @Test
    public void testDoDecryptSetsDatakeyCapsule() {
        KMSKeyCapsuleKeyring keyring = configuredKeyring();
        DecryptKeyCapsuleResponse mockResponse = DecryptKeyCapsuleResponse.builder()
                .keyId(KEY_ID).datakey("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
                .instanceId("inst-1").build();
        AttestationDocument mockDoc = AttestationDocument.builder().serviceToken("mock-token").build();

        try (MockedStatic<ProofCollectorFactory> proofMock = Mockito.mockStatic(ProofCollectorFactory.class);
             MockedConstruction<KmsHttpClient> ignored = mockKmsConstruction(mockResponse)) {
            proofMock.when(() -> ProofCollectorFactory.collect(any(ProofInfo.class))).thenReturn(mockDoc);
            DataKeyMaterials materials = defaultDecryptMaterials();
            keyring.doDecrypt(materials);
            assertNotNull(materials.getPlaintextDataKey());
            assertEquals("010203", materials.getKeyCapsule().getDatakeyCapsule());
        }
    }

    @Test
    public void testGetKMSConfig() throws Exception {
        Method method = getDeclaredMethod("getKMSConfig", CiphertextDataKey.class);
        CiphertextDataKey cdk = new CiphertextDataKey(new byte[]{1, 2, 3},
                new KMSConfig(REGION, KEY_ID, PROJECT_ID, "https://kms.example.com"));
        KMSConfig result = (KMSConfig) method.invoke(new KMSKeyCapsuleKeyring(), cdk);
        assertEquals(REGION, result.getRegion());
        assertEquals(KEY_ID, result.getKeyId());
        assertEquals(PROJECT_ID, result.getProjectId());
        assertEquals("https://kms.example.com", result.getEndPoint());
    }

    @Test
    public void testDecryptKeyCapsuleByKms() throws Exception {
        KMSKeyCapsuleKeyring keyring = configuredKeyring();
        DecryptKeyCapsuleResponse mockResponse = DecryptKeyCapsuleResponse.builder()
                .keyId(KEY_ID).datakey("aabbccdd").instanceId("inst-1").build();

        try (MockedConstruction<KmsHttpClient> ignored = mockKmsConstruction(mockResponse)) {
            Method method = getDeclaredMethod("decryptKeyCapsuleByKms", KeyCapsule.class,
                    AttestationDocument.class, KMSConfig.class, ICredential.class);
            KeyCapsule capsule = defaultKeyCapsule();
            byte[] result = (byte[]) method.invoke(keyring, capsule,
                    AttestationDocument.builder().serviceToken("token").build(),
                    new KMSConfig(REGION, KEY_ID, PROJECT_ID, "https://kms.example.com"),
                    new BasicCredentials().withAk("testAk").withSk("testSk").withProjectId(PROJECT_ID));
            assertNotNull(result);
            assertEquals(4, result.length);
            assertEquals("inst-1", capsule.getInstanceId());
        }
    }

    @Test
    public void testDecryptKeyCapsuleByKmsWithDecoderException() throws Exception {
        KMSKeyCapsuleKeyring keyring = configuredKeyring();
        DecryptKeyCapsuleResponse mockResponse = DecryptKeyCapsuleResponse.builder()
                .keyId(KEY_ID).datakey("ZZZZ!!invalid").instanceId("inst-1").build();

        try (MockedConstruction<KmsHttpClient> ignored = mockKmsConstruction(mockResponse)) {
            Method method = getDeclaredMethod("decryptKeyCapsuleByKms", KeyCapsule.class,
                    AttestationDocument.class, KMSConfig.class, ICredential.class);
            try {
                method.invoke(keyring, defaultKeyCapsule(),
                        AttestationDocument.builder().serviceToken("token").build(),
                        new KMSConfig(REGION, KEY_ID, PROJECT_ID, "https://kms.example.com"),
                        new BasicCredentials().withAk("testAk").withSk("testSk").withProjectId(PROJECT_ID));
            } catch (java.lang.reflect.InvocationTargetException e) {
                assertTrue(e.getCause() instanceof HuaweicloudException);
                assertTrue(e.getCause().getMessage().contains("Failed to decrypt key capsule"));
            }
        }
    }

    @Test
    public void testGetKmsClientWithEndpoint() throws Exception {
        KMSKeyCapsuleKeyring keyring = configuredKeyring();
        Map<String, KmsClient> cache = KMSKeyring.kmsClientHashMap;
        String cacheKey = "testAktestSkcn-north-7";
        cache.remove(cacheKey);
        try {
            Method method = getDeclaredMethod("getKmsClient", KMSConfig.class, ICredential.class);
            KmsClient result = (KmsClient) method.invoke(keyring, defaultKMSConfig(),
                    new BasicCredentials().withAk("testAk").withSk("testSk").withProjectId(PROJECT_ID));
            assertNotNull(result);
            assertTrue(cache.containsKey(cacheKey));
        } finally {
            cache.remove(cacheKey);
        }
    }

    @Test
    public void testGetKmsClientWithEmptyEndpoint() throws Exception {
        KMSKeyCapsuleKeyring keyring = configuredKeyring("cn-north-4", null);
        Map<String, KmsClient> cache = KMSKeyring.kmsClientHashMap;
        String cacheKey = "testAktestSkcn-north-4";
        cache.remove(cacheKey);
        try {
            Method method = getDeclaredMethod("getKmsClient", KMSConfig.class, ICredential.class);
            KmsClient result = (KmsClient) method.invoke(keyring,
                    new KMSConfig("cn-north-4", KEY_ID, PROJECT_ID, null),
                    new BasicCredentials().withAk("testAk").withSk("testSk").withProjectId(PROJECT_ID));
            assertNotNull(result);
            assertTrue(cache.containsKey(cacheKey));
        } finally {
            cache.remove(cacheKey);
        }
    }

    @Test
    public void testGetKmsClientCached() throws Exception {
        KMSKeyCapsuleKeyring keyring = configuredKeyring();
        Map<String, KmsClient> cache = KMSKeyring.kmsClientHashMap;
        String cacheKey = "testAktestSkcn-north-7";
        KmsClient mockClient = Mockito.mock(KmsClient.class);
        cache.put(cacheKey, mockClient);
        try {
            Method method = getDeclaredMethod("getKmsClient", KMSConfig.class, ICredential.class);
            KmsClient result = (KmsClient) method.invoke(keyring, defaultKMSConfig(),
                    new BasicCredentials().withAk("testAk").withSk("testSk").withProjectId(PROJECT_ID));
            assertEquals(mockClient, result);
        } finally {
            cache.remove(cacheKey);
        }
    }

    @Test
    public void testGetKeySpec() throws Exception {
        KMSKeyCapsuleKeyring keyring = configuredKeyring();
        KmsClient mockClient = Mockito.mock(KmsClient.class);
        ListKeyDetailResponse mockResponse = Mockito.mock(ListKeyDetailResponse.class);
        KeyDetails mockKeyDetails = Mockito.mock(KeyDetails.class);
        Mockito.when(mockClient.listKeyDetail(any(ListKeyDetailRequest.class))).thenReturn(mockResponse);
        Mockito.when(mockResponse.getKeyInfo()).thenReturn(mockKeyDetails);
        Mockito.when(mockKeyDetails.getKeySpec()).thenReturn(KeyDetails.KeySpecEnum.AES_256);

        Method method = getDeclaredMethod("getKeySpec", KmsClient.class, String.class);
        String result = (String) method.invoke(keyring, mockClient, KEY_ID);
        assertEquals(KeyDetails.KeySpecEnum.AES_256.getValue(), result);
    }
}
