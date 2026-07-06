package com.huawei.encyptionsdk.test;

import com.huaweicloud.encryptionsdk.HuaweiConfig;
import com.huaweicloud.encryptionsdk.log.LogConfig;
import com.huaweicloud.encryptionsdk.log.LogReporterManager;
import com.huaweicloud.encryptionsdk.log.LTSSDKProducer;
import com.huaweicloud.encryptionsdk.model.KMSConfig;
import org.junit.Test;
import org.mockito.MockedConstruction;
import org.mockito.Mockito;

import java.util.Collections;

import static com.huaweicloud.encryptionsdk.model.enums.CryptoAlgorithm.AES_256_GCM_NOPADDING;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class LogReporterManagerTest {

    private static final KMSConfig KMS_CFG = new KMSConfig("cn-north-7", "key-123", "test-project", "https://kms.cn-north-7.myhuaweicloud.com");
    private static final LogConfig LOG_CFG = LogConfig.builder().region("cn-north-7").projectId("test-project").logGroupId("test-group-id").logStreamId("test-stream-id").build();

    private static HuaweiConfig buildConfig(boolean localLogOnly) {
        return HuaweiConfig.builder().ak("testAk").sk("testSk").localLogOnly(localLogOnly).cryptoAlgorithm(AES_256_GCM_NOPADDING).build();
    }

    private static HuaweiConfig buildConfigWithLog() {
        return HuaweiConfig.builder().ak("testAk").sk("testSk")
                .kmsConfigList(Collections.singletonList(KMS_CFG)).logConfig(LOG_CFG)
                .cryptoAlgorithm(AES_256_GCM_NOPADDING).build();
    }

    private static HuaweiConfig buildConfigWithLogNoProjectId() {
        LogConfig lc = LogConfig.builder().region("cn-north-7").logGroupId("test-group-id").logStreamId("test-stream-id").build();
        return HuaweiConfig.builder().ak("testAk").sk("testSk")
                .kmsConfigList(Collections.singletonList(KMS_CFG)).logConfig(lc)
                .cryptoAlgorithm(AES_256_GCM_NOPADDING).build();
    }

    private static HuaweiConfig buildConfigWithLogNoProjectIdNoKms() {
        LogConfig lc = LogConfig.builder().region("cn-north-7").logGroupId("test-group-id").logStreamId("test-stream-id").build();
        return HuaweiConfig.builder().ak("testAk").sk("testSk").logConfig(lc)
                .cryptoAlgorithm(AES_256_GCM_NOPADDING).build();
    }

    @Test
    public void testInitWithNullLogConfigAndNotLocalLogOnly() {
        LogReporterManager mgr = new LogReporterManager();
        mgr.init(buildConfig(false));
        assertFalse(mgr.isInitialized());
    }

    @Test
    public void testInitWithLocalLogOnly() {
        LogReporterManager mgr = new LogReporterManager();
        mgr.init(buildConfig(true));
        assertTrue(mgr.isInitialized());
    }

    @Test
    public void testInitWithLogConfig() {
        try (MockedConstruction<LTSSDKProducer> mocked = Mockito.mockConstruction(LTSSDKProducer.class)) {
            LogReporterManager mgr = new LogReporterManager();
            mgr.init(buildConfigWithLog());
            assertTrue(mgr.isInitialized());
        }
    }

    @Test
    public void testInitWithLogConfigNoProjectId() {
        try (MockedConstruction<LTSSDKProducer> mocked = Mockito.mockConstruction(LTSSDKProducer.class)) {
            LogReporterManager mgr = new LogReporterManager();
            mgr.init(buildConfigWithLogNoProjectId());
            assertTrue(mgr.isInitialized());
        }
    }

    @Test
    public void testInitWithLogConfigNoProjectIdNoKmsConfig() {
        try (MockedConstruction<LTSSDKProducer> mocked = Mockito.mockConstruction(LTSSDKProducer.class)) {
            LogReporterManager mgr = new LogReporterManager();
            mgr.init(buildConfigWithLogNoProjectIdNoKms());
            assertTrue(mgr.isInitialized());
        }
    }

    @Test
    public void testInitAlreadyInitialized() {
        LogReporterManager mgr = new LogReporterManager();
        mgr.init(buildConfig(true));
        assertTrue(mgr.isInitialized());
        mgr.init(buildConfig(true));
        assertTrue(mgr.isInitialized());
    }

    @Test
    public void testRecordEncryptLogNotInitialized() {
        LogReporterManager mgr = new LogReporterManager();
        assertFalse(mgr.isInitialized());
        mgr.recordEncryptLog("f.txt", 100L, "f.enc", 200L, "kid", "ECS", "i-123");
        assertFalse(mgr.isInitialized());
    }

    @Test
    public void testRecordDecryptLogNotInitialized() {
        LogReporterManager mgr = new LogReporterManager();
        assertFalse(mgr.isInitialized());
        mgr.recordDecryptLog("f.enc", 200L, "f.txt", 100L, "kid", "ECS", "i-123");
        assertFalse(mgr.isInitialized());
    }

    @Test
    public void testRecordEncryptLogLocalLogOnly() {
        LogReporterManager mgr = new LogReporterManager();
        mgr.init(buildConfig(true));
        assertTrue(mgr.isInitialized());
        mgr.recordEncryptLog("f.txt", 100L, "f.enc", 200L, "kid", "ECS", "i-123");
        assertTrue(mgr.isInitialized());
    }

    @Test
    public void testRecordDecryptLogLocalLogOnly() {
        LogReporterManager mgr = new LogReporterManager();
        mgr.init(buildConfig(true));
        assertTrue(mgr.isInitialized());
        mgr.recordDecryptLog("f.enc", 200L, "f.txt", 100L, "kid", "ECS", "i-123");
        assertTrue(mgr.isInitialized());
    }

    @Test
    public void testRecordEncryptLogWithLtsProducer() throws Exception {
        try (MockedConstruction<LTSSDKProducer> mocked = Mockito.mockConstruction(LTSSDKProducer.class)) {
            LogReporterManager mgr = new LogReporterManager();
            mgr.init(buildConfigWithLog());
            mgr.recordEncryptLog("f.txt", 100L, "f.enc", 200L, "kid", "ECS", "i-123");
            Mockito.verify(mocked.constructed().get(0)).sendLog(Mockito.argThat(arg ->
                    arg.contains("\"operation\":\"encrypt\"") && arg.contains("\"keyId\":\"kid\"")));
        }
    }

    @Test
    public void testRecordDecryptLogWithLtsProducer() throws Exception {
        try (MockedConstruction<LTSSDKProducer> mocked = Mockito.mockConstruction(LTSSDKProducer.class)) {
            LogReporterManager mgr = new LogReporterManager();
            mgr.init(buildConfigWithLog());
            mgr.recordDecryptLog("f.enc", 200L, "f.txt", 100L, "kid", "ECS", "i-123");
            Mockito.verify(mocked.constructed().get(0)).sendLog(Mockito.argThat(arg ->
                    arg.contains("\"operation\":\"decrypt\"") && arg.contains("\"keyId\":\"kid\"")));
        }
    }

    @Test
    public void testShutdownNotInitialized() {
        LogReporterManager mgr = new LogReporterManager();
        mgr.shutdown();
        assertFalse(mgr.isInitialized());
    }

    @Test
    public void testShutdownAfterInit() {
        LogReporterManager mgr = new LogReporterManager();
        mgr.init(buildConfig(true));
        assertTrue(mgr.isInitialized());
        mgr.shutdown();
        assertFalse(mgr.isInitialized());
    }

    @Test
    public void testShutdownWithLtsProducer() throws Exception {
        try (MockedConstruction<LTSSDKProducer> mocked = Mockito.mockConstruction(LTSSDKProducer.class)) {
            LogReporterManager mgr = new LogReporterManager();
            mgr.init(buildConfigWithLog());
            mgr.shutdown();
            Mockito.verify(mocked.constructed().get(0)).close();
        }
    }

    @Test
    public void testGetLtsProducerBeforeInit() {
        LogReporterManager mgr = new LogReporterManager();
        assertNull(mgr.getLtsProducer());
    }

    @Test
    public void testGetLtsProducerAfterInit() throws Exception {
        try (MockedConstruction<LTSSDKProducer> mocked = Mockito.mockConstruction(LTSSDKProducer.class)) {
            LogReporterManager mgr = new LogReporterManager();
            mgr.init(buildConfigWithLog());
            assertNotNull(mgr.getLtsProducer());
        }
    }

    @Test
    public void testRecordEncryptLogWithNullParams() throws Exception {
        try (MockedConstruction<LTSSDKProducer> mocked = Mockito.mockConstruction(LTSSDKProducer.class)) {
            LogReporterManager mgr = new LogReporterManager();
            mgr.init(buildConfigWithLog());
            mgr.recordEncryptLog(null, null, null, null, null, null, null);
            Mockito.verify(mocked.constructed().get(0)).sendLog(Mockito.argThat(arg ->
                    arg.contains("\"operation\":\"encrypt\"") && !arg.contains("\"keyId\"")));
        }
    }

    @Test
    public void testRecordDecryptLogWithNullParams() throws Exception {
        try (MockedConstruction<LTSSDKProducer> mocked = Mockito.mockConstruction(LTSSDKProducer.class)) {
            LogReporterManager mgr = new LogReporterManager();
            mgr.init(buildConfigWithLog());
            mgr.recordDecryptLog(null, null, null, null, null, null, null);
            Mockito.verify(mocked.constructed().get(0)).sendLog(Mockito.argThat(arg ->
                    arg.contains("\"operation\":\"decrypt\"") && !arg.contains("\"keyId\"")));
        }
    }

    @Test
    public void testDesensitizeNull() {
        assertEquals("****", LogReporterManager.desensitize(null));
    }

    @Test
    public void testDesensitizeShort() {
        assertEquals("****", LogReporterManager.desensitize("ab"));
    }

    @Test
    public void testDesensitizeLong() {
        assertEquals("ke****23", LogReporterManager.desensitize("key-123"));
    }

    @Test
    public void testInitRetryCountExceeded() {
        LogReporterManager mgr = new LogReporterManager();
        for (int i = 0; i < 5; i++) {
            mgr.init(buildConfig(false));
        }
        assertFalse(mgr.isInitialized());
    }

    @Test
    public void testInitRetryCountResetAfterShutdown() throws Exception {
        try (MockedConstruction<LTSSDKProducer> mocked = Mockito.mockConstruction(LTSSDKProducer.class)) {
            LogReporterManager mgr = new LogReporterManager();
            mgr.init(buildConfigWithLog());
            assertTrue(mgr.isInitialized());
            mgr.shutdown();
            assertFalse(mgr.isInitialized());
            mgr.init(buildConfigWithLog());
            assertTrue(mgr.isInitialized());
        }
    }
}
