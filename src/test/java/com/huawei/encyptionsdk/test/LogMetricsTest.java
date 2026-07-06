package com.huawei.encyptionsdk.test;

import com.huaweicloud.encryptionsdk.log.LogMetrics;
import org.junit.Assert;
import org.junit.Test;

public class LogMetricsTest {

    @Test
    public void testDefaultValues() {
        LogMetrics metrics = LogMetrics.builder().build();

        Assert.assertEquals(0L, metrics.getLastReportTime());
        Assert.assertEquals(0L, metrics.getSuccessCount());
        Assert.assertEquals(0L, metrics.getFailureCount());
        Assert.assertEquals(0L, metrics.getSuccessLogCount());
        Assert.assertEquals(0L, metrics.getFailureLogCount());
        Assert.assertEquals(0L, metrics.getBufferLogCount());
        Assert.assertNull(metrics.getLastErrorMessage());
        Assert.assertEquals(0L, metrics.getLastErrorTime());
    }

    @Test
    public void testCustomValues() {
        LogMetrics metrics = LogMetrics.builder()
                .lastReportTime(1000L)
                .successCount(5L)
                .failureCount(2L)
                .successLogCount(100L)
                .failureLogCount(10L)
                .bufferLogCount(50L)
                .lastErrorMessage("timeout")
                .lastErrorTime(999L)
                .build();

        Assert.assertEquals(1000L, metrics.getLastReportTime());
        Assert.assertEquals(5L, metrics.getSuccessCount());
        Assert.assertEquals(2L, metrics.getFailureCount());
        Assert.assertEquals(100L, metrics.getSuccessLogCount());
        Assert.assertEquals(10L, metrics.getFailureLogCount());
        Assert.assertEquals(50L, metrics.getBufferLogCount());
        Assert.assertEquals("timeout", metrics.getLastErrorMessage());
        Assert.assertEquals(999L, metrics.getLastErrorTime());
    }

    @Test
    public void testSetterGetter() {
        LogMetrics metrics = new LogMetrics();
        metrics.setSuccessCount(10L);
        metrics.setFailureCount(3L);
        metrics.setBufferLogCount(7L);
        metrics.setLastErrorMessage("err");

        Assert.assertEquals(10L, metrics.getSuccessCount());
        Assert.assertEquals(3L, metrics.getFailureCount());
        Assert.assertEquals(7L, metrics.getBufferLogCount());
        Assert.assertEquals("err", metrics.getLastErrorMessage());
    }

    @Test
    public void testNoArgsConstructor() {
        LogMetrics metrics = new LogMetrics();
        Assert.assertEquals(0L, metrics.getSuccessCount());
        Assert.assertEquals(0L, metrics.getFailureCount());
    }

    @Test
    public void testAtomicIncrementAndAdd() {
        LogMetrics metrics = new LogMetrics();
        Assert.assertEquals(1L, metrics.incrementSuccessCount());
        Assert.assertEquals(2L, metrics.incrementSuccessCount());
        Assert.assertEquals(1L, metrics.incrementFailureCount());
        Assert.assertEquals(5L, metrics.addSuccessLogCount(5));
        Assert.assertEquals(2L, metrics.addFailureLogCount(2));
        Assert.assertEquals(10L, metrics.addBufferLogCount(10));
        Assert.assertEquals(7L, metrics.addBufferLogCount(-3));
    }

    @Test
    public void testReset() {
        LogMetrics metrics = LogMetrics.builder()
                .successCount(5L).failureCount(2L).bufferLogCount(10L)
                .lastErrorMessage("err").build();
        metrics.reset();
        Assert.assertEquals(0L, metrics.getSuccessCount());
        Assert.assertEquals(0L, metrics.getFailureCount());
        Assert.assertEquals(0L, metrics.getBufferLogCount());
        Assert.assertNull(metrics.getLastErrorMessage());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testBuilderRejectsNegativeSuccessCount() {
        LogMetrics.builder().successCount(-1L);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testBuilderRejectsNegativeFailureCount() {
        LogMetrics.builder().failureCount(-1L);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testBuilderRejectsNegativeBufferLogCount() {
        LogMetrics.builder().bufferLogCount(-1L);
    }
}
