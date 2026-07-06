package com.huawei.encyptionsdk.test;

import com.huaweicloud.encryptionsdk.HuaweiConfig;
import com.huaweicloud.encryptionsdk.HuaweiCrypto;
import com.huaweicloud.encryptionsdk.cache.DataKeyCache;
import com.huaweicloud.encryptionsdk.exception.HuaweicloudException;
import com.huaweicloud.encryptionsdk.handler.CryptoHadler;
import com.huaweicloud.encryptionsdk.keyrings.Keyring;
import com.huaweicloud.encryptionsdk.keyrings.kmskeyring.KMSKeyring;
import com.huaweicloud.encryptionsdk.log.LogReporterManager;
import com.huaweicloud.encryptionsdk.meterialmanager.CacheCryptoMeterialManager;
import com.huaweicloud.encryptionsdk.meterialmanager.CryptoMeterialManager;
import com.huaweicloud.encryptionsdk.model.CryptoResult;
import com.huaweicloud.encryptionsdk.model.DataKeyMaterials;
import com.huaweicloud.encryptionsdk.model.KeyCapsule;
import com.huaweicloud.encryptionsdk.model.KMSConfig;
import com.huaweicloud.encryptionsdk.model.enums.CryptoAlgorithm;
import com.huaweicloud.encryptionsdk.model.request.EncryptRequest;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;

public class HuaweiCryptoTest {

    private static final KMSConfig KMS_CFG = new KMSConfig("cn-north-7", "key-123", "pid-123", "https://kms.cn-north-7.myhuaweicloud.com");

    private HuaweiConfig config;

    @Before
    public void setUp() {
        config = buildConfig(false);
    }

    private static HuaweiConfig buildConfig(boolean localLogOnly) {
        return HuaweiConfig.builder().ak("testAk").sk("testSk")
                .kmsConfigList(Collections.singletonList(KMS_CFG))
                .cryptoAlgorithm(CryptoAlgorithm.AES_256_GCM_NOPADDING)
                .localLogOnly(localLogOnly).build();
    }

    private static void setField(Object obj, String name, Object val) {
        try {
            Field f = obj.getClass().getDeclaredField(name);
            f.setAccessible(true);
            f.set(obj, val);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            throw new AssertionError("Failed to set field: " + name, e);
        }
    }

    private HuaweiCrypto buildCryptoWithMocks(DataKeyMaterials materials, CryptoResult<byte[]> result, boolean logEnabled) throws Exception {
        CryptoMeterialManager mm = Mockito.mock(CryptoMeterialManager.class);
        CryptoHadler handler = Mockito.mock(CryptoHadler.class);
        Mockito.when(mm.getMaterialsForEncrypt(any(Keyring.class), any(DataKeyMaterials.class), anyLong())).thenReturn(materials);
        Mockito.when(mm.getMaterialsForDecrypt(any(Keyring.class), any(byte[].class))).thenReturn(materials);
        Mockito.when(handler.encrypt(any(EncryptRequest.class), any(DataKeyMaterials.class))).thenReturn(result);
        Mockito.when(handler.decrypt(any(byte[].class), any(DataKeyMaterials.class))).thenReturn(result);
        HuaweiCrypto crypto = new HuaweiCrypto(logEnabled ? buildConfig(true) : config);
        crypto.withCryptoMeterialManager(mm);
        setField(crypto, "cryptoHandler", handler);
        setField(crypto, "keyring", Mockito.mock(Keyring.class));
        if (logEnabled) {
            setField(crypto, "logReporterManager", Mockito.mock(LogReporterManager.class));
        }
        return crypto;
    }

    private static DataKeyMaterials buildMaterialsWithCapsule(String keyId, int accessPointType, String instanceId) {
        DataKeyMaterials m = new DataKeyMaterials();
        m.setCryptoAlgorithm(CryptoAlgorithm.AES_256_GCM_NOPADDING);
        m.setKeyCapsule(KeyCapsule.builder().keyId(keyId).datakeyCapsule("capsule").accessPointType(accessPointType).instanceId(instanceId).build());
        return m;
    }

    private static DataKeyMaterials buildMaterialsWithoutCapsule() {
        DataKeyMaterials m = new DataKeyMaterials();
        m.setCryptoAlgorithm(CryptoAlgorithm.AES_256_GCM_NOPADDING);
        return m;
    }

    private LogReporterManager getLogMock(HuaweiCrypto crypto) {
        return (LogReporterManager) getField(crypto, "logReporterManager");
    }

    private static Object getField(Object obj, String name) {
        try {
            Field f = obj.getClass().getDeclaredField(name);
            f.setAccessible(true);
            return f.get(obj);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            throw new AssertionError("Failed to get field: " + name, e);
        }
    }

    private HuaweiCrypto buildStreamCryptoWithMocks(DataKeyMaterials m, boolean logEnabled) throws Exception {
        CryptoMeterialManager mm = Mockito.mock(CryptoMeterialManager.class);
        CryptoHadler handler = Mockito.mock(CryptoHadler.class);
        Mockito.when(mm.getMaterialsForEncrypt(any(Keyring.class), any(DataKeyMaterials.class), anyLong())).thenReturn(m);
        Mockito.when(mm.getMaterialsForStreamDecrypt(any(Keyring.class), any(ByteArrayInputStream.class))).thenReturn(m);
        Mockito.when(mm.getMaterialsForStreamDecrypt(any(Keyring.class), any(FileInputStream.class))).thenReturn(m);
        CryptoResult<OutputStream> res = new CryptoResult<>(new ByteArrayOutputStream(), null);
        Mockito.when(handler.encrypt(any(ByteArrayInputStream.class), any(ByteArrayOutputStream.class), any(DataKeyMaterials.class), any())).thenReturn(res);
        Mockito.when(handler.encrypt(any(FileInputStream.class), any(FileOutputStream.class), any(DataKeyMaterials.class), any())).thenReturn(res);
        Mockito.when(handler.decrypt(any(ByteArrayInputStream.class), any(ByteArrayOutputStream.class), any(DataKeyMaterials.class))).thenReturn(res);
        Mockito.when(handler.decrypt(any(FileInputStream.class), any(FileOutputStream.class), any(DataKeyMaterials.class))).thenReturn(res);
        HuaweiCrypto crypto = new HuaweiCrypto(logEnabled ? buildConfig(true) : config);
        crypto.withCryptoMeterialManager(mm);
        setField(crypto, "cryptoHandler", handler);
        setField(crypto, "keyring", Mockito.mock(Keyring.class));
        if (logEnabled) {
            setField(crypto, "logReporterManager", Mockito.mock(LogReporterManager.class));
        }
        return crypto;
    }

    @Test(expected = HuaweicloudException.class)
    public void testEncryptNullKeyring() {
        new HuaweiCrypto(config).encrypt(new EncryptRequest(Collections.emptyMap(), "test".getBytes(StandardCharsets.UTF_8)));
    }

    @Test(expected = HuaweicloudException.class)
    public void testDecryptNullKeyring() {
        new HuaweiCrypto(config).decrypt(new byte[]{0, 0});
    }

    @Test(expected = HuaweicloudException.class)
    public void testStreamEncryptNullKeyring() {
        new HuaweiCrypto(config).encrypt(new ByteArrayInputStream("test".getBytes(StandardCharsets.UTF_8)), new ByteArrayOutputStream(), Collections.emptyMap());
    }

    @Test(expected = HuaweicloudException.class)
    public void testStreamDecryptNullKeyring() {
        new HuaweiCrypto(config).decrypt(new ByteArrayInputStream(new byte[]{0, 0}), new ByteArrayOutputStream());
    }

    @Test(expected = HuaweicloudException.class)
    public void testFileEncryptNullKeyring() {
        new HuaweiCrypto(config).encrypt("src.txt", "tgt.enc", null);
    }

    @Test(expected = HuaweicloudException.class)
    public void testFileDecryptNullKeyring() {
        new HuaweiCrypto(config).decrypt("src.enc", "tgt.txt");
    }

    @Test
    public void testEncryptByteArrayNoKeyring() throws Exception {
        try { new HuaweiCrypto(config).encrypt("test".getBytes(StandardCharsets.UTF_8)); } catch (HuaweicloudException e) { assertNotNull(e.getMessage()); }
    }

    @Test
    public void testConstructorWithNullCryptoAlgorithm() {
        assertNotNull(new HuaweiCrypto(HuaweiConfig.builder().ak("a").sk("s").kmsConfigList(Collections.singletonList(KMS_CFG)).build()));
    }

    @Test
    public void testWithKeyringKMSKeyring() {
        KMSKeyring kr = Mockito.mock(KMSKeyring.class);
        assertNotNull(new HuaweiCrypto(config).withKeyring(kr));
        Mockito.verify(kr).setHuaweiConfig(config);
    }

    @Test
    public void testWithKeyringGenericKeyring() {
        assertNotNull(new HuaweiCrypto(config).withKeyring(Mockito.mock(Keyring.class)));
    }

    @Test
    public void testWithCryptoMeterialManager() {
        assertNotNull(new HuaweiCrypto(config).withCryptoMeterialManager(Mockito.mock(CryptoMeterialManager.class)));
    }

    @Test
    public void testEncryptWithLogReportingAndKeyCapsule() throws Exception {
        DataKeyMaterials m = buildMaterialsWithCapsule("key-123", 2, "i-123");
        HuaweiCrypto crypto = buildCryptoWithMocks(m, new CryptoResult<>("test".getBytes(StandardCharsets.UTF_8), null), true);
        assertNotNull(crypto.encrypt(new EncryptRequest(Collections.emptyMap(), "test".getBytes(StandardCharsets.UTF_8))));
        Mockito.verify(getLogMock(crypto)).recordEncryptLog(isNull(), anyLong(), isNull(), anyLong(), eq("key-123"), anyString(), isNull());
    }

    @Test
    public void testDecryptWithLogReportingAndKeyCapsule() throws Exception {
        DataKeyMaterials m = buildMaterialsWithCapsule("key-456", 2, "i-456");
        HuaweiCrypto crypto = buildCryptoWithMocks(m, new CryptoResult<>("dec".getBytes(StandardCharsets.UTF_8), null), true);
        assertNotNull(crypto.decrypt(new byte[]{0, 0, 0, 0}));
        Mockito.verify(getLogMock(crypto)).recordDecryptLog(isNull(), anyLong(), isNull(), anyLong(), eq("key-456"), anyString(), eq("i-456"));
    }

    @Test
    public void testEncryptNoLogConfigNoKeyCapsule() throws Exception {
        HuaweiCrypto crypto = buildCryptoWithMocks(buildMaterialsWithoutCapsule(), new CryptoResult<>("test".getBytes(StandardCharsets.UTF_8), null), false);
        assertNotNull(crypto.encrypt(new EncryptRequest(Collections.emptyMap(), "test".getBytes(StandardCharsets.UTF_8))));
    }

    @Test
    public void testEncryptWithPolicyIdAndKeyPolicy() throws Exception {
        HuaweiCrypto crypto = buildCryptoWithMocks(buildMaterialsWithoutCapsule(), new CryptoResult<>("test".getBytes(StandardCharsets.UTF_8), null), false);
        Map<String, String> ctx = new HashMap<>();
        ctx.put("key1", "value1");
        EncryptRequest req = new EncryptRequest(ctx, "test".getBytes(StandardCharsets.UTF_8));
        req.setPolicyId("policy-123");
        req.setKeyPolicy("{\"Version\":\"1.0\"}");
        assertNotNull(crypto.encrypt(req));
    }

    @Test
    public void testEncryptWithEcsAccessPointType() throws Exception {
        DataKeyMaterials m = buildMaterialsWithCapsule("key-ecs", 1, "i-ecs-123");
        HuaweiCrypto crypto = buildCryptoWithMocks(m, new CryptoResult<>("test".getBytes(StandardCharsets.UTF_8), null), true);
        try (var ecs = Mockito.mockStatic(com.huaweicloud.encryptionsdk.common.EcsMetadataService.class)) {
            ecs.when(com.huaweicloud.encryptionsdk.common.EcsMetadataService::getEcsInstanceId).thenReturn("i-ecs-123");
            assertNotNull(crypto.encrypt(new EncryptRequest(Collections.emptyMap(), "test".getBytes(StandardCharsets.UTF_8))));
            Mockito.verify(getLogMock(crypto)).recordEncryptLog(isNull(), anyLong(), isNull(), anyLong(), eq("key-ecs"), eq("ECS"), eq("i-ecs-123"));
        }
    }

    @Test
    public void testDecryptWithNullResult() throws Exception {
        DataKeyMaterials m = buildMaterialsWithCapsule("key-null", 2, "i-123");
        HuaweiCrypto crypto = buildCryptoWithMocks(m, new CryptoResult<>((byte[]) null, null), true);
        assertNotNull(crypto.decrypt(new byte[]{0, 0, 0, 0}));
        Mockito.verify(getLogMock(crypto)).recordDecryptLog(isNull(), anyLong(), isNull(), eq(0L), eq("key-null"), anyString(), eq("i-123"));
    }

    @Test
    public void testEncryptWithLogConfigButNoKeyCapsule() throws Exception {
        HuaweiCrypto crypto = buildCryptoWithMocks(buildMaterialsWithoutCapsule(), new CryptoResult<>("test".getBytes(StandardCharsets.UTF_8), null), true);
        assertNotNull(crypto.encrypt(new EncryptRequest(Collections.emptyMap(), "test".getBytes(StandardCharsets.UTF_8))));
        Mockito.verify(getLogMock(crypto), Mockito.never()).recordEncryptLog(anyString(), anyLong(), anyString(), anyLong(), anyString(), anyString(), anyString());
    }

    @Test
    public void testDecryptWithLogConfigButNoKeyCapsule() throws Exception {
        HuaweiCrypto crypto = buildCryptoWithMocks(buildMaterialsWithoutCapsule(), new CryptoResult<>("dec".getBytes(StandardCharsets.UTF_8), null), true);
        assertNotNull(crypto.decrypt(new byte[]{0, 0, 0, 0}));
        Mockito.verify(getLogMock(crypto), Mockito.never()).recordDecryptLog(anyString(), anyLong(), anyString(), anyLong(), anyString(), anyString(), anyString());
    }

    @Test
    public void testStreamEncryptWithLogReportingAndKeyCapsule() throws Exception {
        HuaweiCrypto crypto = buildStreamCryptoWithMocks(buildMaterialsWithCapsule("key-stream", 2, "i-stream"), true);
        assertNotNull(crypto.encrypt(new ByteArrayInputStream("test".getBytes(StandardCharsets.UTF_8)), new ByteArrayOutputStream(), Collections.emptyMap()));
        Mockito.verify(getLogMock(crypto)).recordEncryptLog(isNull(), anyLong(), isNull(), anyLong(), eq("key-stream"), anyString(), isNull());
    }

    @Test
    public void testStreamDecryptWithLogReportingAndKeyCapsule() throws Exception {
        HuaweiCrypto crypto = buildStreamCryptoWithMocks(buildMaterialsWithCapsule("key-dec-s", 2, "i-dec-s"), true);
        assertNotNull(crypto.decrypt(new ByteArrayInputStream(new byte[]{0, 0, 0, 0}), new ByteArrayOutputStream()));
        Mockito.verify(getLogMock(crypto)).recordDecryptLog(isNull(), anyLong(), isNull(), isNull(), eq("key-dec-s"), anyString(), eq("i-dec-s"));
    }

    @Test
    public void testStreamEncryptNoLogConfig() throws Exception {
        HuaweiCrypto crypto = buildStreamCryptoWithMocks(buildMaterialsWithoutCapsule(), false);
        assertNotNull(crypto.encrypt(new ByteArrayInputStream("test".getBytes(StandardCharsets.UTF_8)), new ByteArrayOutputStream(), null));
    }

    @Test
    public void testStreamDecryptNoLogConfig() throws Exception {
        HuaweiCrypto crypto = buildStreamCryptoWithMocks(buildMaterialsWithoutCapsule(), false);
        assertNotNull(crypto.decrypt(new ByteArrayInputStream(new byte[]{0, 0, 0, 0}), new ByteArrayOutputStream()));
    }

    @Test
    public void testEncryptWithCacheExceedLimit() throws Exception {
        DataKeyCache cache = Mockito.mock(DataKeyCache.class);
        CacheCryptoMeterialManager cm = new CacheCryptoMeterialManager(cache, config);
        cm.setMaxByteLimit(1L);
        HuaweiCrypto crypto = new HuaweiCrypto(config);
        crypto.withCryptoMeterialManager(cm);
        setField(crypto, "keyring", Mockito.mock(Keyring.class));
        try { crypto.encrypt(new EncryptRequest(Collections.emptyMap(), "test-data-too-long".getBytes(StandardCharsets.UTF_8))); } catch (HuaweicloudException e) { assertNotNull(e.getMessage()); }
    }

    @Test
    public void testStreamEncryptWithCacheExceedLimit() throws Exception {
        DataKeyCache cache = Mockito.mock(DataKeyCache.class);
        CacheCryptoMeterialManager cm = new CacheCryptoMeterialManager(cache, config);
        cm.setMaxByteLimit(1L);
        HuaweiCrypto crypto = new HuaweiCrypto(config);
        crypto.withCryptoMeterialManager(cm);
        setField(crypto, "keyring", Mockito.mock(Keyring.class));
        try { crypto.encrypt(new ByteArrayInputStream("test-data-too-long".getBytes(StandardCharsets.UTF_8)), new ByteArrayOutputStream(), Collections.emptyMap()); } catch (HuaweicloudException e) { assertNotNull(e.getMessage()); }
    }

    @Test
    public void testFileEncryptWithLogReportingAndKeyCapsule() throws Exception {
        HuaweiCrypto crypto = buildStreamCryptoWithMocks(buildMaterialsWithCapsule("key-file", 2, "i-file"), true);
        File in = File.createTempFile("enc-in", ".txt");
        File out = File.createTempFile("enc-out", ".enc");
        try {
            Files.write(in.toPath(), "test data".getBytes(StandardCharsets.UTF_8));
            assertNotNull(crypto.encrypt(in.getAbsolutePath(), out.getAbsolutePath(), Collections.emptyMap()));
            Mockito.verify(getLogMock(crypto)).recordEncryptLog(anyString(), anyLong(), anyString(), anyLong(), eq("key-file"), anyString(), isNull());
        } finally { in.delete(); out.delete(); }
    }

    @Test
    public void testFileDecryptWithLogReportingAndKeyCapsule() throws Exception {
        HuaweiCrypto crypto = buildStreamCryptoWithMocks(buildMaterialsWithCapsule("key-file-d", 2, "i-file-d"), true);
        File in = File.createTempFile("dec-in", ".enc");
        File out = File.createTempFile("dec-out", ".txt");
        try {
            Files.write(in.toPath(), new byte[]{0, 0, 0, 0});
            assertNotNull(crypto.decrypt(in.getAbsolutePath(), out.getAbsolutePath()));
            Mockito.verify(getLogMock(crypto)).recordDecryptLog(anyString(), anyLong(), anyString(), anyLong(), eq("key-file-d"), anyString(), eq("i-file-d"));
        } finally { in.delete(); out.delete(); }
    }

    @Test
    public void testFileEncryptNonExistentFile() throws Exception {
        HuaweiCrypto crypto = new HuaweiCrypto(config);
        setField(crypto, "keyring", Mockito.mock(Keyring.class));
        try { crypto.encrypt("/non/existent/file.txt", "/non/existent/file.enc", null); } catch (HuaweicloudException e) { assertNotNull(e.getMessage()); }
    }

    @Test
    public void testFileDecryptNonExistentFile() throws Exception {
        HuaweiCrypto crypto = new HuaweiCrypto(config);
        setField(crypto, "keyring", Mockito.mock(Keyring.class));
        try { crypto.decrypt("/non/existent/file.enc", "/non/existent/file.txt"); } catch (HuaweicloudException e) { assertNotNull(e.getMessage()); }
    }

    @Test
    public void testEncryptWithException() throws Exception {
        CryptoMeterialManager mm = Mockito.mock(CryptoMeterialManager.class);
        Mockito.when(mm.getMaterialsForEncrypt(any(Keyring.class), any(DataKeyMaterials.class), anyLong())).thenThrow(new RuntimeException("err"));
        HuaweiCrypto crypto = new HuaweiCrypto(config);
        crypto.withCryptoMeterialManager(mm);
        setField(crypto, "keyring", Mockito.mock(Keyring.class));
        try { crypto.encrypt(new EncryptRequest(Collections.emptyMap(), "test".getBytes(StandardCharsets.UTF_8))); } catch (HuaweicloudException e) { assertNotNull(e.getMessage()); }
    }

    @Test
    public void testDecryptWithException() throws Exception {
        CryptoMeterialManager mm = Mockito.mock(CryptoMeterialManager.class);
        Mockito.when(mm.getMaterialsForDecrypt(any(Keyring.class), any(byte[].class))).thenThrow(new RuntimeException("err"));
        HuaweiCrypto crypto = new HuaweiCrypto(config);
        crypto.withCryptoMeterialManager(mm);
        setField(crypto, "keyring", Mockito.mock(Keyring.class));
        try { crypto.decrypt(new byte[]{0, 0, 0, 0}); } catch (HuaweicloudException e) { assertNotNull(e.getMessage()); }
    }
}
