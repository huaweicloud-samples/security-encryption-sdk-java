package com.huawei.encyptionsdk.test;

import com.huaweicloud.encryptionsdk.log.LogConfig;
import org.junit.Assert;
import org.junit.Test;

public class LogConfigTest {

    @Test
    public void testDefaultValues() {
        LogConfig config = LogConfig.builder().build();

        Assert.assertEquals("DSC", config.getLogGroupName());
        Assert.assertEquals("crypto_operation_log", config.getLogStreamName());
        Assert.assertEquals(1000, config.getBatchCountThreshold());
        Assert.assertEquals(524288, config.getBatchSizeThresholdInBytes());
        Assert.assertEquals(30000, config.getLingerMs());
        Assert.assertEquals(104857600, config.getTotalSizeInBytes());
        Assert.assertEquals(0L, config.getMaxBlockMs());
        Assert.assertEquals(5, config.getRetries());
        Assert.assertEquals(100L, config.getBaseRetryBackoffMs());
        Assert.assertEquals(500L, config.getMaxRetryBackoffMs());
        Assert.assertFalse(config.isEnableLocalTest());
        Assert.assertEquals(10 * 1024 * 1024, config.getMaxBackupFileSize());
        Assert.assertTrue(config.isEnableRecoveryOnStartup());
        Assert.assertEquals(1000, config.getRecoveryBatchSize());
        Assert.assertEquals(1000L, config.getRecoveryBatchInterval());
        Assert.assertFalse(config.isFailOnBackupDirMissing());
    }

    @Test
    public void testCustomValues() {
        LogConfig config = LogConfig.builder()
                .logGroupName("myGroup")
                .logStreamName("myStream")
                .region("cn-north-7")
                .projectId("pid-123")
                .batchCountThreshold(500)
                .batchSizeThresholdInBytes(1024)
                .lingerMs(10000)
                .totalSizeInBytes(20971520)
                .maxBlockMs(100L)
                .ioThreadCount(8)
                .retries(3)
                .baseRetryBackoffMs(200L)
                .maxRetryBackoffMs(1000L)
                .enableLocalTest(true)
                .backupDir("/tmp/backup")
                .maxBackupFileSize(2048L)
                .enableRecoveryOnStartup(false)
                .recoveryBatchSize(500)
                .recoveryBatchInterval(2000L)
                .failOnBackupDirMissing(true)
                .build();

        Assert.assertEquals("myGroup", config.getLogGroupName());
        Assert.assertEquals("myStream", config.getLogStreamName());
        Assert.assertEquals("cn-north-7", config.getRegion());
        Assert.assertEquals("pid-123", config.getProjectId());
        Assert.assertEquals(500, config.getBatchCountThreshold());
        Assert.assertEquals(1024, config.getBatchSizeThresholdInBytes());
        Assert.assertEquals(10000, config.getLingerMs());
        Assert.assertEquals(20971520, config.getTotalSizeInBytes());
        Assert.assertEquals(100L, config.getMaxBlockMs());
        Assert.assertEquals(8, config.getIoThreadCount());
        Assert.assertEquals(3, config.getRetries());
        Assert.assertEquals(200L, config.getBaseRetryBackoffMs());
        Assert.assertEquals(1000L, config.getMaxRetryBackoffMs());
        Assert.assertTrue(config.isEnableLocalTest());
        Assert.assertEquals("/tmp/backup", config.getBackupDir());
        Assert.assertEquals(2048L, config.getMaxBackupFileSize());
        Assert.assertFalse(config.isEnableRecoveryOnStartup());
        Assert.assertEquals(500, config.getRecoveryBatchSize());
        Assert.assertEquals(2000L, config.getRecoveryBatchInterval());
        Assert.assertTrue(config.isFailOnBackupDirMissing());
    }

    @Test
    public void testSetterGetter() {
        LogConfig config = new LogConfig();
        config.setRegion("us-east-1");
        Assert.assertEquals("us-east-1", config.getRegion());
    }

    @Test
    public void testNoArgsConstructor() {
        LogConfig config = new LogConfig();
        Assert.assertEquals("DSC", config.getLogGroupName());
        Assert.assertEquals("crypto_operation_log", config.getLogStreamName());
    }

    @Test
    public void testAllArgsConstructor() {
        LogConfig config = new LogConfig("groupId", "streamId", "g", "s", "r", "p", 1, 2, 3, 4, 5L, 6,
                7, 8L, 9L, true, "/tmp", 100L, false, 10, 11L, true);
        Assert.assertEquals("groupId", config.getLogGroupId());
        Assert.assertEquals("streamId", config.getLogStreamId());
        Assert.assertEquals("g", config.getLogGroupName());
        Assert.assertEquals("s", config.getLogStreamName());
        Assert.assertEquals("r", config.getRegion());
        Assert.assertEquals("p", config.getProjectId());
    }
}
