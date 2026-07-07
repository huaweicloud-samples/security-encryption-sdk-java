package com.huawei.encyptionsdk.test;

import com.huaweicloud.encryptionsdk.HuaweiConfig;
import com.huaweicloud.encryptionsdk.cache.DataKeyCache;
import com.huaweicloud.encryptionsdk.exception.HuaweicloudException;
import com.huaweicloud.encryptionsdk.meterialmanager.CacheCryptoMeterialManager;
import com.huaweicloud.encryptionsdk.model.AccessPointConfig;
import com.huaweicloud.encryptionsdk.model.DataKeyMaterials;
import com.huaweicloud.encryptionsdk.model.KMSConfig;
import com.huaweicloud.encryptionsdk.model.KeyCapsuleConfig;
import com.huaweicloud.encryptionsdk.model.enums.CryptoAlgorithm;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

public class CacheCryptoMeterialManagerTest {

    private DataKeyCache mockCache;
    private HuaweiConfig config;

    @Before
    public void setUp() {
        mockCache = Mockito.mock(DataKeyCache.class);
        config = HuaweiConfig.builder()
                .ak("testAk").sk("testSk")
                .kmsConfigList(Collections.singletonList(
                        new KMSConfig("cn-north-7", "key-123", "pid-123", "https://kms.cn-north-7.myhuaweicloud.com")))
                .cryptoAlgorithm(CryptoAlgorithm.AES_256_GCM_NOPADDING)
                .build();
    }

    @Test
    public void testSetSurvivalTimePositive() {
        CacheCryptoMeterialManager manager = new CacheCryptoMeterialManager(mockCache, config);
        CacheCryptoMeterialManager result = manager.setSurvivalTime(1000L);
        assertTrue(result instanceof CacheCryptoMeterialManager);
        verify(mockCache).setSurvivalTime(1000L);
    }

    @Test(expected = HuaweicloudException.class)
    public void testSetSurvivalTimeZero() {
        CacheCryptoMeterialManager manager = new CacheCryptoMeterialManager(mockCache, config);
        manager.setSurvivalTime(0L);
    }

    @Test(expected = HuaweicloudException.class)
    public void testSetSurvivalTimeNegative() {
        CacheCryptoMeterialManager manager = new CacheCryptoMeterialManager(mockCache, config);
        manager.setSurvivalTime(-1L);
    }

    @Test
    public void testSetMaxMessageLimitPositive() {
        CacheCryptoMeterialManager manager = new CacheCryptoMeterialManager(mockCache, config);
        CacheCryptoMeterialManager result = manager.setMaxMessageLimit(100L);
        assertTrue(result instanceof CacheCryptoMeterialManager);
    }

    @Test(expected = HuaweicloudException.class)
    public void testSetMaxMessageLimitZero() {
        CacheCryptoMeterialManager manager = new CacheCryptoMeterialManager(mockCache, config);
        manager.setMaxMessageLimit(0L);
    }

    @Test
    public void testSetMaxByteLimitPositive() {
        CacheCryptoMeterialManager manager = new CacheCryptoMeterialManager(mockCache, config);
        CacheCryptoMeterialManager result = manager.setMaxByteLimit(1024L);
        assertNotNull(result);
        assertEquals(1024L, result.getMaxByteLimit());
    }

    @Test(expected = HuaweicloudException.class)
    public void testSetMaxByteLimitZero() {
        CacheCryptoMeterialManager manager = new CacheCryptoMeterialManager(mockCache, config);
        manager.setMaxByteLimit(0L);
    }

    @Test
    public void testGetMaxByteLimitDefault() {
        CacheCryptoMeterialManager manager = new CacheCryptoMeterialManager(mockCache, config);
        assertEquals(Long.MAX_VALUE, manager.getMaxByteLimit());
    }

    @Test
    public void testGetMaterialsForEncryptCacheHit() throws Exception {
        DataKeyMaterials cachedMaterials = new DataKeyMaterials();
        cachedMaterials.setCryptoAlgorithm(CryptoAlgorithm.AES_256_GCM_NOPADDING);
        DataKeyCache.EncryptCacheEntry mockEntry = Mockito.mock(DataKeyCache.EncryptCacheEntry.class);
        DataKeyCache.UsageStatus usageStatus = new DataKeyCache.UsageStatus(100L, 1L);
        Mockito.when(mockEntry.getUsageStatus()).thenReturn(usageStatus);
        Mockito.when(mockEntry.getDataKeyMaterials()).thenReturn(cachedMaterials);
        Mockito.when(mockCache.getEntryForEncrypt(anyString(), any(DataKeyCache.UsageStatus.class)))
                .thenReturn(mockEntry);

        CacheCryptoMeterialManager manager = new CacheCryptoMeterialManager(mockCache, config);
        DataKeyMaterials input = new DataKeyMaterials();
        input.setCryptoAlgorithm(CryptoAlgorithm.AES_256_GCM_NOPADDING);
        DataKeyMaterials result = manager.getMaterialsForEncrypt(Mockito.mock(com.huaweicloud.encryptionsdk.keyrings.Keyring.class), input, 100L);
        assertEquals(cachedMaterials, result);
    }

    @Test
    public void testGetMaterialsForEncryptCacheMiss() throws Exception {
        Mockito.when(mockCache.getEntryForEncrypt(anyString(), any(DataKeyCache.UsageStatus.class)))
                .thenReturn(null);

        CacheCryptoMeterialManager manager = new CacheCryptoMeterialManager(mockCache, config);
        DataKeyMaterials input = new DataKeyMaterials();
        input.setCryptoAlgorithm(CryptoAlgorithm.AES_256_GCM_NOPADDING);
        try {
            manager.getMaterialsForEncrypt(Mockito.mock(com.huaweicloud.encryptionsdk.keyrings.Keyring.class), input, 100L);
        } catch (Exception e) {
            assertNotNull(e.getMessage());
        }
        verify(mockCache).putEntryForEncrypt(anyString(), any(DataKeyMaterials.class), any(DataKeyCache.UsageStatus.class));
    }

    @Test
    public void testGetMaterialsForEncryptWithSm4Algorithm() throws Exception {
        HuaweiConfig sm4Config = HuaweiConfig.builder()
                .ak("testAk").sk("testSk")
                .kmsConfigList(Collections.singletonList(
                        new KMSConfig("cn-north-7", "key-123", "pid-123", "https://kms.cn-north-7.myhuaweicloud.com")))
                .cryptoAlgorithm(CryptoAlgorithm.SM4_128_GCM_NOPADDING)
                .build();
        Mockito.when(mockCache.getEntryForEncrypt(anyString(), any(DataKeyCache.UsageStatus.class)))
                .thenReturn(null);

        CacheCryptoMeterialManager manager = new CacheCryptoMeterialManager(mockCache, sm4Config);
        DataKeyMaterials input = new DataKeyMaterials();
        input.setCryptoAlgorithm(CryptoAlgorithm.SM4_128_GCM_NOPADDING);
        try {
            manager.getMaterialsForEncrypt(Mockito.mock(com.huaweicloud.encryptionsdk.keyrings.Keyring.class), input, 100L);
        } catch (Exception e) {
            assertNotNull(e.getMessage());
        }
        verify(mockCache).putEntryForEncrypt(anyString(), any(DataKeyMaterials.class), any(DataKeyCache.UsageStatus.class));
    }

    @Test
    public void testGetMaterialsForEncryptWithEncryptionContext() throws Exception {
        DataKeyMaterials cachedMaterials = new DataKeyMaterials();
        cachedMaterials.setCryptoAlgorithm(CryptoAlgorithm.AES_256_GCM_NOPADDING);
        DataKeyCache.EncryptCacheEntry mockEntry = Mockito.mock(DataKeyCache.EncryptCacheEntry.class);
        DataKeyCache.UsageStatus usageStatus = new DataKeyCache.UsageStatus(100L, 1L);
        Mockito.when(mockEntry.getUsageStatus()).thenReturn(usageStatus);
        Mockito.when(mockEntry.getDataKeyMaterials()).thenReturn(cachedMaterials);
        Mockito.when(mockCache.getEntryForEncrypt(anyString(), any(DataKeyCache.UsageStatus.class)))
                .thenReturn(mockEntry);

        CacheCryptoMeterialManager manager = new CacheCryptoMeterialManager(mockCache, config);
        DataKeyMaterials input = new DataKeyMaterials();
        input.setCryptoAlgorithm(CryptoAlgorithm.AES_256_GCM_NOPADDING);
        Map<String, String> context = new HashMap<>();
        context.put("key1", "value1");
        input.setEncryptionContexts(context);
        DataKeyMaterials result = manager.getMaterialsForEncrypt(Mockito.mock(com.huaweicloud.encryptionsdk.keyrings.Keyring.class), input, 100L);
        assertNotNull(result);
        assertEquals(CryptoAlgorithm.AES_256_GCM_NOPADDING, result.getCryptoAlgorithm());
        assertSame(cachedMaterials, result);
    }

    @Test
    public void testGetMaterialsForEncryptWithKeyCapsuleConfig() throws Exception {
        HuaweiConfig capsuleConfig = HuaweiConfig.builder()
                .ak("testAk").sk("testSk")
                .kmsConfigList(Collections.singletonList(
                        new KMSConfig("cn-north-7", "key-123", "pid-123", "https://kms.cn-north-7.myhuaweicloud.com")))
                .cryptoAlgorithm(CryptoAlgorithm.AES_256_GCM_NOPADDING)
                .keyCapsuleConfig(KeyCapsuleConfig.builder()
                        .region("cn-north-7")
                        .defaultPolicyId("policy-123")
                        .accessPointConfig(AccessPointConfig.builder()
                                .type(2).encryptedPrivateKey("encKey")
                                .privateKeyDecryptCallback(k -> "dec").build())
                        .build())
                .build();
        Mockito.when(mockCache.getEntryForEncrypt(anyString(), any(DataKeyCache.UsageStatus.class)))
                .thenReturn(null);

        CacheCryptoMeterialManager manager = new CacheCryptoMeterialManager(mockCache, capsuleConfig);
        DataKeyMaterials input = new DataKeyMaterials();
        input.setCryptoAlgorithm(CryptoAlgorithm.AES_256_GCM_NOPADDING);
        try {
            manager.getMaterialsForEncrypt(Mockito.mock(com.huaweicloud.encryptionsdk.keyrings.Keyring.class), input, 100L);
        } catch (Exception e) {
            assertNotNull(e.getMessage());
        }
        verify(mockCache).putEntryForEncrypt(anyString(), any(DataKeyMaterials.class), any(DataKeyCache.UsageStatus.class));
    }

    @Test
    public void testGetMaterialsForEncryptWithKeyPolicy() throws Exception {
        HuaweiConfig capsuleConfig = HuaweiConfig.builder()
                .ak("testAk").sk("testSk")
                .kmsConfigList(Collections.singletonList(
                        new KMSConfig("cn-north-7", "key-123", "pid-123", "https://kms.cn-north-7.myhuaweicloud.com")))
                .cryptoAlgorithm(CryptoAlgorithm.AES_256_GCM_NOPADDING)
                .keyCapsuleConfig(KeyCapsuleConfig.builder()
                        .region("cn-north-7")
                        .defaultKeyPolicy("{\"Version\":\"1.0\"}")
                        .accessPointConfig(AccessPointConfig.builder()
                                .type(2).encryptedPrivateKey("encKey")
                                .privateKeyDecryptCallback(k -> "dec").build())
                        .build())
                .build();
        Mockito.when(mockCache.getEntryForEncrypt(anyString(), any(DataKeyCache.UsageStatus.class)))
                .thenReturn(null);

        CacheCryptoMeterialManager manager = new CacheCryptoMeterialManager(mockCache, capsuleConfig);
        DataKeyMaterials input = new DataKeyMaterials();
        input.setCryptoAlgorithm(CryptoAlgorithm.AES_256_GCM_NOPADDING);
        input.setKeyPolicy("{\"Version\":\"1.0\"}");
        try {
            manager.getMaterialsForEncrypt(Mockito.mock(com.huaweicloud.encryptionsdk.keyrings.Keyring.class), input, 100L);
        } catch (Exception e) {
            assertNotNull(e.getMessage());
        }
        verify(mockCache).putEntryForEncrypt(anyString(), any(DataKeyMaterials.class), any(DataKeyCache.UsageStatus.class));
    }

    @Test
    public void testGetMaterialsForDecryptCacheHit() throws Exception {
        DataKeyMaterials cachedMaterials = new DataKeyMaterials();
        DataKeyCache.DecryptCacheEntry mockEntry = Mockito.mock(DataKeyCache.DecryptCacheEntry.class);
        Mockito.when(mockEntry.getDataKeyMaterials()).thenReturn(cachedMaterials);
        Mockito.when(mockCache.getEntryForDecrypt(anyString())).thenReturn(mockEntry);

        CacheCryptoMeterialManager manager = new CacheCryptoMeterialManager(mockCache, config);
        com.huaweicloud.encryptionsdk.keyrings.Keyring mockKeyring = Mockito.mock(com.huaweicloud.encryptionsdk.keyrings.Keyring.class);
        try {
            DataKeyMaterials result = manager.getMaterialsForDecrypt(mockKeyring, new byte[]{0, 2, 0, 0, 0, 0});
        } catch (Exception e) {
            assertNotNull(e.getMessage());
        }
        verify(mockKeyring, never()).decryptDataKey(any(DataKeyMaterials.class));
    }

    @Test
    public void testGetMaterialsForDecryptWithNullAlgorithm() throws Exception {
        DataKeyCache.DecryptCacheEntry mockEntry = Mockito.mock(DataKeyCache.DecryptCacheEntry.class);
        Mockito.when(mockCache.getEntryForDecrypt(anyString())).thenReturn(mockEntry);
        Mockito.when(mockEntry.getDataKeyMaterials()).thenReturn(new DataKeyMaterials());

        CacheCryptoMeterialManager manager = new CacheCryptoMeterialManager(mockCache, config);
        com.huaweicloud.encryptionsdk.keyrings.Keyring mockKeyring = Mockito.mock(com.huaweicloud.encryptionsdk.keyrings.Keyring.class);
        try {
            manager.getMaterialsForDecrypt(mockKeyring, new byte[]{0, 2, 0, 0, 0, 0});
        } catch (Exception e) {
            assertNotNull(e.getMessage());
        }
    }

    @Test
    public void testGetMaterialsForEncryptExceedLimit() throws Exception {
        DataKeyCache.EncryptCacheEntry mockEntry = Mockito.mock(DataKeyCache.EncryptCacheEntry.class);
        DataKeyCache.UsageStatus exceededStatus = new DataKeyCache.UsageStatus(Long.MAX_VALUE, Long.MAX_VALUE);
        Mockito.when(mockEntry.getUsageStatus()).thenReturn(exceededStatus);
        Mockito.when(mockEntry.getDataKeyMaterials()).thenReturn(new DataKeyMaterials());
        Mockito.when(mockCache.getEntryForEncrypt(anyString(), any(DataKeyCache.UsageStatus.class)))
                .thenReturn(mockEntry);

        CacheCryptoMeterialManager manager = new CacheCryptoMeterialManager(mockCache, config);
        DataKeyMaterials input = new DataKeyMaterials();
        input.setCryptoAlgorithm(CryptoAlgorithm.AES_256_GCM_NOPADDING);
        try {
            manager.getMaterialsForEncrypt(Mockito.mock(com.huaweicloud.encryptionsdk.keyrings.Keyring.class), input, 100L);
        } catch (Exception e) {
            assertNotNull(e.getMessage());
        }
        verify(mockEntry).invalidate();
    }

    @Test
    public void testGetMaterialsForEncryptWithNullAlgorithm() throws Exception {
        DataKeyCache.EncryptCacheEntry mockEntry = Mockito.mock(DataKeyCache.EncryptCacheEntry.class);
        DataKeyCache.UsageStatus usageStatus = new DataKeyCache.UsageStatus(100L, 1L);
        Mockito.when(mockEntry.getUsageStatus()).thenReturn(usageStatus);
        Mockito.when(mockEntry.getDataKeyMaterials()).thenReturn(new DataKeyMaterials());
        Mockito.when(mockCache.getEntryForEncrypt(anyString(), any(DataKeyCache.UsageStatus.class)))
                .thenReturn(mockEntry);

        CacheCryptoMeterialManager manager = new CacheCryptoMeterialManager(mockCache, config);
        DataKeyMaterials input = new DataKeyMaterials();
        DataKeyMaterials result = manager.getMaterialsForEncrypt(Mockito.mock(com.huaweicloud.encryptionsdk.keyrings.Keyring.class), input, 100L);
        assertSame(mockEntry.getDataKeyMaterials(), result);
    }

    @Test
    public void testGetMaterialsForEncryptWithPolicyId() throws Exception {
        HuaweiConfig capsuleConfig = HuaweiConfig.builder()
                .ak("testAk").sk("testSk")
                .kmsConfigList(Collections.singletonList(
                        new KMSConfig("cn-north-7", "key-123", "pid-123", "https://kms.cn-north-7.myhuaweicloud.com")))
                .cryptoAlgorithm(CryptoAlgorithm.AES_256_GCM_NOPADDING)
                .keyCapsuleConfig(KeyCapsuleConfig.builder()
                        .region("cn-north-7")
                        .accessPointConfig(AccessPointConfig.builder()
                                .type(2).encryptedPrivateKey("encKey")
                                .privateKeyDecryptCallback(k -> "dec").build())
                        .build())
                .build();
        Mockito.when(mockCache.getEntryForEncrypt(anyString(), any(DataKeyCache.UsageStatus.class)))
                .thenReturn(null);

        CacheCryptoMeterialManager manager = new CacheCryptoMeterialManager(mockCache, capsuleConfig);
        DataKeyMaterials input = new DataKeyMaterials();
        input.setCryptoAlgorithm(CryptoAlgorithm.AES_256_GCM_NOPADDING);
        input.setPolicyId("policy-456");
        try {
            manager.getMaterialsForEncrypt(Mockito.mock(com.huaweicloud.encryptionsdk.keyrings.Keyring.class), input, 100L);
        } catch (Exception e) {
            assertNotNull(e.getMessage());
        }
        verify(mockCache).putEntryForEncrypt(anyString(), any(DataKeyMaterials.class), any(DataKeyCache.UsageStatus.class));
    }
}
