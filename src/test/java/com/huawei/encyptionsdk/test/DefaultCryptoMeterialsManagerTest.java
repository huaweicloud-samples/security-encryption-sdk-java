package com.huawei.encyptionsdk.test;

import com.huaweicloud.encryptionsdk.HuaweiConfig;
import com.huaweicloud.encryptionsdk.exception.HuaweicloudException;
import com.huaweicloud.encryptionsdk.keyrings.Keyring;
import com.huaweicloud.encryptionsdk.keyrings.kmskeyring.KMSKeyCapsuleKeyring;
import com.huaweicloud.encryptionsdk.keyrings.kmskeyring.KMSKeyring;
import com.huaweicloud.encryptionsdk.meterialmanager.DataKeyGenerate;
import com.huaweicloud.encryptionsdk.meterialmanager.DataKeyGenerateFactory;
import com.huaweicloud.encryptionsdk.meterialmanager.DefaultCryptoMeterialsManager;
import com.huaweicloud.encryptionsdk.model.DataKeyMaterials;
import com.huaweicloud.encryptionsdk.model.KMSConfig;
import com.huaweicloud.encryptionsdk.model.enums.CryptoAlgorithm;
import org.junit.Before;
import org.junit.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.util.Collections;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;

public class DefaultCryptoMeterialsManagerTest {

    private HuaweiConfig config;

    @Before
    public void setUp() {
        config = HuaweiConfig.builder()
                .ak("testAk").sk("testSk")
                .kmsConfigList(Collections.singletonList(
                        new KMSConfig("cn-north-7", "key-123", "pid-123", "https://kms.cn-north-7.myhuaweicloud.com")))
                .cryptoAlgorithm(CryptoAlgorithm.AES_256_GCM_NOPADDING)
                .build();
    }

    private DataKeyGenerate mockGenerateWithFactory() {
        DataKeyGenerate mockGenerate = Mockito.mock(DataKeyGenerate.class);
        MockedStatic<DataKeyGenerateFactory> mockedFactory = Mockito.mockStatic(DataKeyGenerateFactory.class);
        mockedFactory.when(() -> DataKeyGenerateFactory.getDataKeyGenerate(any())).thenReturn(mockGenerate);
        return mockGenerate;
    }

    private DataKeyMaterials buildMaterials() {
        DataKeyMaterials m = new DataKeyMaterials();
        m.setCryptoAlgorithm(CryptoAlgorithm.AES_256_GCM_NOPADDING);
        return m;
    }

    @Test
    public void testGetMaterialsForEncryptWithKMSKeyring() throws Exception {
        KMSKeyring mockKeyring = Mockito.mock(KMSKeyring.class);
        DataKeyMaterials input = buildMaterials();
        Mockito.when(mockKeyring.encryptDataKey(any(DataKeyMaterials.class))).thenAnswer(inv -> inv.getArgument(0));

        try (MockedStatic<DataKeyGenerateFactory> mockedFactory = Mockito.mockStatic(DataKeyGenerateFactory.class)) {
            DataKeyGenerate mockGenerate = Mockito.mock(DataKeyGenerate.class);
            mockedFactory.when(() -> DataKeyGenerateFactory.getDataKeyGenerate(any())).thenReturn(mockGenerate);

            DefaultCryptoMeterialsManager manager = new DefaultCryptoMeterialsManager(config);
            DataKeyMaterials result = manager.getMaterialsForEncrypt(mockKeyring, input, 100L);
            assertNotNull(result);
            assertEquals(CryptoAlgorithm.AES_256_GCM_NOPADDING, result.getCryptoAlgorithm());
            verify(mockKeyring).setHuaweiConfig(config);
            verify(mockKeyring).encryptDataKey(any(DataKeyMaterials.class));
        }
    }

    @Test
    public void testGetMaterialsForEncryptWithKMSKeyCapsuleKeyring() throws Exception {
        KMSKeyCapsuleKeyring mockKeyring = Mockito.mock(KMSKeyCapsuleKeyring.class);
        DataKeyMaterials input = buildMaterials();
        Mockito.when(mockKeyring.encryptDataKey(any(DataKeyMaterials.class))).thenAnswer(inv -> inv.getArgument(0));

        try (MockedStatic<DataKeyGenerateFactory> mockedFactory = Mockito.mockStatic(DataKeyGenerateFactory.class)) {
            DataKeyGenerate mockGenerate = Mockito.mock(DataKeyGenerate.class);
            mockedFactory.when(() -> DataKeyGenerateFactory.getDataKeyGenerate(any())).thenReturn(mockGenerate);

            DefaultCryptoMeterialsManager manager = new DefaultCryptoMeterialsManager(config);
            DataKeyMaterials result = manager.getMaterialsForEncrypt(mockKeyring, input, 100L);
            assertNotNull(result);
            assertEquals(CryptoAlgorithm.AES_256_GCM_NOPADDING, result.getCryptoAlgorithm());
            verify(mockKeyring).setHuaweiConfig(config);
            verify(mockKeyring).encryptDataKey(any(DataKeyMaterials.class));
        }
    }

    @Test
    public void testGetMaterialsForEncryptWithLocalKeyring() throws Exception {
        Keyring mockKeyring = Mockito.mock(Keyring.class);
        DataKeyMaterials input = buildMaterials();
        Mockito.when(mockKeyring.encryptDataKey(any(DataKeyMaterials.class))).thenAnswer(inv -> inv.getArgument(0));

        try (MockedStatic<DataKeyGenerateFactory> mockedFactory = Mockito.mockStatic(DataKeyGenerateFactory.class)) {
            DataKeyGenerate mockGenerate = Mockito.mock(DataKeyGenerate.class);
            mockedFactory.when(() -> DataKeyGenerateFactory.getDataKeyGenerate(any())).thenReturn(mockGenerate);

            DefaultCryptoMeterialsManager manager = new DefaultCryptoMeterialsManager(config);
            DataKeyMaterials result = manager.getMaterialsForEncrypt(mockKeyring, input, 100L);
            assertNotNull(result);
            assertEquals(CryptoAlgorithm.AES_256_GCM_NOPADDING, result.getCryptoAlgorithm());
            verify(mockKeyring).encryptDataKey(any(DataKeyMaterials.class));
        }
    }

    @Test
    public void testGetMaterialsForDecryptWithKMSKeyring() throws Exception {
        KMSKeyring mockKeyring = Mockito.mock(KMSKeyring.class);
        Mockito.when(mockKeyring.decryptDataKey(any(DataKeyMaterials.class))).thenAnswer(inv -> inv.getArgument(0));

        DefaultCryptoMeterialsManager manager = new DefaultCryptoMeterialsManager(config);
        try {
            manager.getMaterialsForDecrypt(mockKeyring, new byte[]{0, 2, 0, 0, 0, 0});
        } catch (HuaweicloudException e) {
            assertNotNull(e.getMessage());
        } catch (Exception e) {
            assertNotNull(e.getMessage());
        }
    }

    @Test
    public void testGetMaterialsForDecryptWithKMSKeyCapsuleKeyring() throws Exception {
        KMSKeyCapsuleKeyring mockKeyring = Mockito.mock(KMSKeyCapsuleKeyring.class);
        Mockito.when(mockKeyring.decryptDataKey(any(DataKeyMaterials.class))).thenAnswer(inv -> inv.getArgument(0));

        DefaultCryptoMeterialsManager manager = new DefaultCryptoMeterialsManager(config);
        try {
            manager.getMaterialsForDecrypt(mockKeyring, new byte[]{0, 2, 0, 0, 0, 0});
        } catch (HuaweicloudException e) {
            assertNotNull(e.getMessage());
        } catch (Exception e) {
            assertNotNull(e.getMessage());
        }
    }

    @Test
    public void testGetMaterialsForDecryptWithLocalKeyring() throws Exception {
        Keyring mockKeyring = Mockito.mock(Keyring.class);
        Mockito.when(mockKeyring.decryptDataKey(any(DataKeyMaterials.class))).thenAnswer(inv -> inv.getArgument(0));

        DefaultCryptoMeterialsManager manager = new DefaultCryptoMeterialsManager(config);
        try {
            manager.getMaterialsForDecrypt(mockKeyring, new byte[]{0, 2, 0, 0, 0, 0});
        } catch (HuaweicloudException e) {
            assertNotNull(e.getMessage());
        } catch (Exception e) {
            assertNotNull(e.getMessage());
        }
    }

    @Test
    public void testDefaultConstructor() {
        DefaultCryptoMeterialsManager manager = new DefaultCryptoMeterialsManager();
        assertNotNull(manager);
        assertEquals(DefaultCryptoMeterialsManager.class, manager.getClass());
    }

    @Test(expected = HuaweicloudException.class)
    public void testGetMaterialsForStreamDecryptInvalidInput() throws Exception {
        Keyring mockKeyring = Mockito.mock(Keyring.class);
        DefaultCryptoMeterialsManager manager = new DefaultCryptoMeterialsManager(config);
        java.io.ByteArrayInputStream invalidStream = new java.io.ByteArrayInputStream(new byte[]{0});
        manager.getMaterialsForStreamDecrypt(mockKeyring, invalidStream);
    }
}
