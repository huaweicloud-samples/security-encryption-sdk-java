package com.huawei.encyptionsdk.test;

import com.huaweicloud.encryptionsdk.log.LogConfig;
import com.huaweicloud.encryptionsdk.log.LTSSDKProducer;
import com.huaweicloud.encryptionsdk.log.LogMetrics;
import com.huaweicloud.lts.appender.JavaSDKAppender;
import com.huaweicloud.lts.producer.Callback;
import com.huaweicloud.lts.producer.Producer;
import com.huaweicloud.lts.producer.Result;
import com.huaweicloud.lts.producer.exception.ProducerException;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;

public class LTSSDKProducerTest {

    private LogConfig logConfig;
    private Producer mockProducer;
    private JavaSDKAppender.Builder mockBuilder;

    @Before
    public void setUp() {
        logConfig = LogConfig.builder()
                .region("cn-north-7")
                .projectId("test-project")
                .logGroupId("test-group-id")
                .logStreamId("test-stream-id")
                .enableRecoveryOnStartup(false)
                .build();
        mockProducer = Mockito.mock(Producer.class);
        mockBuilder = Mockito.mock(JavaSDKAppender.Builder.class, Mockito.RETURNS_DEEP_STUBS);
    }

    private LTSSDKProducer createProducer() {
        return createProducerWithConfig(logConfig);
    }

    private LTSSDKProducer createProducerWithConfig(LogConfig config) {
        try (MockedStatic<JavaSDKAppender> mockedAppender = Mockito.mockStatic(JavaSDKAppender.class)) {
            Mockito.when(JavaSDKAppender.custom()).thenReturn(mockBuilder);
            Mockito.when(mockBuilder.setProjectId(anyString())).thenReturn(mockBuilder);
            Mockito.when(mockBuilder.setAccessKeyId(anyString())).thenReturn(mockBuilder);
            Mockito.when(mockBuilder.setAccessKeySecret(anyString())).thenReturn(mockBuilder);
            Mockito.when(mockBuilder.setRegionName(anyString())).thenReturn(mockBuilder);
            Mockito.when(mockBuilder.setTotalSizeInBytes(anyInt())).thenReturn(mockBuilder);
            Mockito.when(mockBuilder.setMaxBlockMs(anyLong())).thenReturn(mockBuilder);
            Mockito.when(mockBuilder.setBatchCountThreshold(anyInt())).thenReturn(mockBuilder);
            Mockito.when(mockBuilder.setBatchSizeThresholdInBytes(anyInt())).thenReturn(mockBuilder);
            Mockito.when(mockBuilder.setLingerMs(anyInt())).thenReturn(mockBuilder);
            Mockito.when(mockBuilder.setIoThreadCount(anyInt())).thenReturn(mockBuilder);
            Mockito.when(mockBuilder.setRetries(anyInt())).thenReturn(mockBuilder);
            Mockito.when(mockBuilder.setBaseRetryBackoffMs(anyLong())).thenReturn(mockBuilder);
            Mockito.when(mockBuilder.setMaxRetryBackoffMs(anyLong())).thenReturn(mockBuilder);
            Mockito.when(mockBuilder.setEnableLocalTest(anyBoolean())).thenReturn(mockBuilder);
            Mockito.when(mockBuilder.setLogGroupStreamByName(anyBoolean())).thenReturn(mockBuilder);
            JavaSDKAppender mockAppender = Mockito.mock(JavaSDKAppender.class);
            Mockito.when(mockBuilder.builder()).thenReturn(mockAppender);
            Mockito.when(mockAppender.getProducer()).thenReturn(mockProducer);
            return new LTSSDKProducer("testAk", "testSk", "test-project", "cn-north-7", config);
        }
    }

    @Test
    public void testConstructorWithGroupIdAndStreamId() {
        LTSSDKProducer producer = createProducer();
        assertNotNull(producer);
        assertEquals(mockProducer, producer.getProducer());
    }

    @Test
    public void testConstructorWithGroupNameAndStreamName() {
        LogConfig config = LogConfig.builder()
                .region("cn-north-7")
                .projectId("test-project")
                .logGroupName("myGroup")
                .logStreamName("myStream")
                .enableRecoveryOnStartup(false)
                .build();
        LTSSDKProducer producer = createProducerWithConfig(config);
        assertNotNull(producer);
        assertEquals(mockProducer, producer.getProducer());
    }

    @Test
    public void testSendLog() throws Exception {
        LTSSDKProducer producer = createProducer();
        producer.sendLog("test log content");
        verify(mockProducer).send(anyString(), anyString(), anyBoolean(), anyList(), any(Callback.class));
    }

    @Test
    public void testSendBatchLog() throws Exception {
        LTSSDKProducer producer = createProducer();
        List<String> logs = Arrays.asList("log1", "log2", "log3");
        producer.sendBatchLog(logs);
        verify(mockProducer).send(anyString(), anyString(), anyBoolean(), anyList(), any(Callback.class));
    }

    @Test
    public void testSendBatchLogNull() throws Exception {
        LTSSDKProducer producer = createProducer();
        producer.sendBatchLog(null);
        verify(mockProducer, Mockito.never()).send(anyString(), anyString(), anyBoolean(), anyList(), any(Callback.class));
    }

    @Test
    public void testSendBatchLogEmpty() throws Exception {
        LTSSDKProducer producer = createProducer();
        producer.sendBatchLog(Collections.emptyList());
        verify(mockProducer, Mockito.never()).send(anyString(), anyString(), anyBoolean(), anyList(), any(Callback.class));
    }

    @Test
    public void testSendLogException() throws Exception {
        LTSSDKProducer producer = createProducer();
        Mockito.doThrow(new ProducerException("send error")).when(mockProducer)
                .send(anyString(), anyString(), anyBoolean(), anyList(), any(Callback.class));
        producer.sendLog("test log");
        assertEquals(1, producer.getMetrics().getFailureCount());
        assertEquals(1, producer.getMetrics().getFailureLogCount());
    }

    @Test
    public void testGetMetrics() {
        LTSSDKProducer producer = createProducer();
        LogMetrics metrics = producer.getMetrics();
        assertNotNull(metrics);
        assertEquals(0L, metrics.getSuccessCount());
    }

    @Test
    public void testResetMetrics() {
        LTSSDKProducer producer = createProducer();
        producer.resetMetrics();
        LogMetrics metrics = producer.getMetrics();
        assertNotNull(metrics);
        assertEquals(0L, metrics.getSuccessCount());
        assertEquals(0L, metrics.getFailureCount());
    }

    @Test
    public void testClose() throws Exception {
        LTSSDKProducer producer = createProducer();
        producer.close();
        verify(mockProducer).close();
    }

    @Test
    public void testCloseWithProducerException() throws Exception {
        LTSSDKProducer producer = createProducer();
        Mockito.doThrow(new ProducerException("close error")).when(mockProducer).close();
        producer.close();
        assertEquals(false, producer.getMetrics() == null);
    }

    @Test
    public void testCloseWithInterruptedException() throws Exception {
        LTSSDKProducer producer = createProducer();
        Mockito.doThrow(new InterruptedException()).when(mockProducer).close();
        producer.close();
        assertNotNull(producer.getMetrics());
    }

    @Test
    public void testCloseNotInitialized() throws Exception {
        LTSSDKProducer producer = createProducer();
        setField(producer, "initialized", false);
        producer.close();
        verify(mockProducer, Mockito.never()).close();
    }

    @Test
    public void testSendLogNotInitialized() throws Exception {
        LTSSDKProducer producer = createProducer();
        setField(producer, "initialized", false);
        producer.sendLog("test");
        verify(mockProducer, Mockito.never()).send(anyString(), anyString(), anyBoolean(), anyList(), any(Callback.class));
    }

    @Test
    public void testHandleCallbackSuccess() throws Exception {
        LTSSDKProducer producer = createProducer();
        ArgumentCaptor<Callback> callbackCaptor = ArgumentCaptor.forClass(Callback.class);
        producer.sendLog("test log");
        verify(mockProducer).send(anyString(), anyString(), anyBoolean(), anyList(), callbackCaptor.capture());

        Result mockResult = Mockito.mock(Result.class);
        Mockito.when(mockResult.isSuccessful()).thenReturn(true);
        callbackCaptor.getValue().onCompletion(mockResult);

        LogMetrics metrics = producer.getMetrics();
        assertEquals(1, metrics.getSuccessCount());
    }

    @Test
    public void testHandleCallbackFailure() throws Exception {
        LTSSDKProducer producer = createProducer();
        ArgumentCaptor<Callback> callbackCaptor = ArgumentCaptor.forClass(Callback.class);
        producer.sendLog("test log");
        verify(mockProducer).send(anyString(), anyString(), anyBoolean(), anyList(), callbackCaptor.capture());

        Result mockResult = Mockito.mock(Result.class);
        Mockito.when(mockResult.isSuccessful()).thenReturn(false);
        Mockito.when(mockResult.getErrorCode()).thenReturn("ERR");
        Mockito.when(mockResult.getErrorMessage()).thenReturn("error msg");
        callbackCaptor.getValue().onCompletion(mockResult);

        LogMetrics metrics = producer.getMetrics();
        assertEquals(1, metrics.getFailureCount());
    }

    @Test
    public void testSanitizeStripsCRLF() {
        assertEquals("line1line2", LTSSDKProducer.sanitize("line1\r\nline2"));
    }

    @Test
    public void testSanitizeStripsTabAndControlChars() {
        assertEquals("abc", LTSSDKProducer.sanitize("a\tb\u0001c"));
    }

    @Test
    public void testSanitizeNullInput() {
        assertEquals("", LTSSDKProducer.sanitize(null));
    }

    @Test
    public void testSanitizeCleanInput() {
        assertEquals("clean log", LTSSDKProducer.sanitize("clean log"));
    }

    private void setField(Object obj, String fieldName, Object value) {
        try {
            Field field = obj.getClass().getDeclaredField(fieldName);
            field.setAccessible(true);
            field.set(obj, value);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            throw new AssertionError("Failed to set field: " + fieldName, e);
        }
    }
}
